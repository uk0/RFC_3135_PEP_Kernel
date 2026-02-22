/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/slab.h>

extern struct pep_context *pep_ctx;

#define PEP_BYTE_CACHE_MAX_RETRANS_BYTES (64 * 1024)
#define PEP_BYTE_CACHE_MAX_GAPS          4

struct pep_byte_cache_read_work {
    struct work_struct work;
    struct pep_byte_cache_entry *entry;
    struct pep_flow *flow;
};

static DEFINE_MUTEX(pep_byte_cache_disk_mutex);

/*
 * 功能/Main: 分配字节缓存（Allocate byte cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；字节缓存读写（byte cache access）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow, skb, seq, len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 中/Medium
 */
static struct pep_byte_cache_entry *pep_byte_cache_entry_alloc(struct pep_flow *flow,
                                                               struct sk_buff *skb,
                                                               u32 seq, u32 len)
{
    struct pep_byte_cache_entry *entry;

    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return NULL;

    INIT_LIST_HEAD(&entry->lru_node);
    INIT_LIST_HEAD(&entry->flow_node);
    entry->flow = flow;
    entry->skb = skb;
    entry->seq = seq;
    entry->end = seq + len;
    entry->len = skb ? skb->len : 0;
    entry->flags = 0;
    entry->disk_off = 0;
    entry->disk_len = 0;
    refcount_set(&entry->refcnt, 1);

    return entry;
}

/*
 * 功能/Main: 处理字节缓存（Handle byte cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）
 * 输入/Inputs: 参数/Inputs: entry
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static void pep_byte_cache_entry_put(struct pep_byte_cache_entry *entry)
{
    if (!entry)
        return;

    if (refcount_dec_and_test(&entry->refcnt)) {
        if (entry->skb)
            kfree_skb(entry->skb);
        kfree(entry);
    }
}

/*
 * 功能/Main: 查找字节缓存（Find byte cache）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；字节缓存读写（byte cache access）
 * 输入/Inputs: 参数/Inputs: flow, seq, end
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static struct pep_byte_cache_entry *pep_byte_cache_find_overlap_locked(struct pep_flow *flow,
                                                                       u32 seq, u32 end)
{
    struct rb_node *node = flow->byte_cache_root.rb_node;

    while (node) {
        struct pep_byte_cache_entry *entry =
            rb_entry(node, struct pep_byte_cache_entry, rb);

        if (PEP_SEQ_BEFORE(end, entry->seq) || end == entry->seq) {
            node = node->rb_left;
        } else if (PEP_SEQ_AFTER(seq, entry->end) || seq == entry->end) {
            node = node->rb_right;
        } else {
            return entry;
        }
    }

    return NULL;
}

/*
 * 功能/Main: 查找字节缓存（Find byte cache）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；字节缓存读写（byte cache access）
 * 输入/Inputs: 参数/Inputs: flow, seq
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static struct pep_byte_cache_entry *pep_byte_cache_find_covering_locked(struct pep_flow *flow,
                                                                        u32 seq)
{
    struct rb_node *node = flow->byte_cache_root.rb_node;

    while (node) {
        struct pep_byte_cache_entry *entry =
            rb_entry(node, struct pep_byte_cache_entry, rb);

        if (PEP_SEQ_BEFORE(seq, entry->seq)) {
            node = node->rb_left;
        } else if (PEP_SEQ_BEFORE(seq, entry->end)) {
            return entry;
        } else {
            node = node->rb_right;
        }
    }

    return NULL;
}

/*
 * 功能/Main: 查找字节缓存（Find byte cache）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；字节缓存读写（byte cache access）
 * 输入/Inputs: 参数/Inputs: flow, seq
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static struct pep_byte_cache_entry *pep_byte_cache_find_ge_locked(struct pep_flow *flow,
                                                                  u32 seq)
{
    struct rb_node *node = flow->byte_cache_root.rb_node;
    struct pep_byte_cache_entry *best = NULL;

    while (node) {
        struct pep_byte_cache_entry *entry =
            rb_entry(node, struct pep_byte_cache_entry, rb);

        if (PEP_SEQ_BEFORE(seq, entry->seq)) {
            best = entry;
            node = node->rb_left;
        } else if (seq == entry->seq) {
            return entry;
        } else {
            node = node->rb_right;
        }
    }

    return best;
}

/*
 * 功能/Main: 处理字节缓存（Handle byte cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；字节缓存读写（byte cache access）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: ctx, entry
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static int pep_byte_cache_write_disk(struct pep_context *ctx,
                                     struct pep_byte_cache_entry *entry)
{
    loff_t pos;
    ssize_t written;
    int ret = 0;

    if (!ctx || !entry || !entry->skb || !ctx->byte_cache_file)
        return -EINVAL;

    if (ctx->byte_cache_disk_max_bytes == 0)
        return -ENOSPC;

    if (ctx->byte_cache_disk_used + entry->len > ctx->byte_cache_disk_max_bytes)
        return -ENOSPC;

    if (skb_linearize(entry->skb))
        return -ENOMEM;

    mutex_lock(&pep_byte_cache_disk_mutex);
    if (ctx->byte_cache_disk_used + entry->len > ctx->byte_cache_disk_max_bytes) {
        ret = -ENOSPC;
        goto out_unlock;
    }

    pos = ctx->byte_cache_disk_used;
    written = kernel_write(ctx->byte_cache_file, entry->skb->data, entry->len, &pos);
    if (written != entry->len) {
        ret = written < 0 ? (int)written : -EIO;
        goto out_unlock;
    }

    entry->disk_off = pos - entry->len;
    entry->disk_len = entry->len;
    entry->flags |= PEP_BYTE_CACHE_F_ON_DISK;
    ctx->byte_cache_disk_used = pos;

    kfree_skb(entry->skb);
    entry->skb = NULL;

out_unlock:
    mutex_unlock(&pep_byte_cache_disk_mutex);
    return ret;
}

/*
 * 功能/Main: 处理字节缓存（Handle byte cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；重传/缓存处理（retransmission/cache）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: buf, len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static struct sk_buff *pep_byte_cache_build_skb(const u8 *buf, u32 len)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    unsigned int ip_hdr_len;

    skb = alloc_skb(LL_MAX_HEADER + len, GFP_KERNEL);
    if (!skb)
        return NULL;

    skb_reserve(skb, LL_MAX_HEADER);
    skb_reset_network_header(skb);
    memcpy(skb_put(skb, len), buf, len);

    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    skb_set_transport_header(skb, ip_hdr_len);

    pep_update_ip_checksum(iph);
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
        pep_update_tcp_checksum(skb, iph, tcph);
    }

    skb->protocol = htons(ETH_P_IP);
    skb->ip_summed = CHECKSUM_NONE;
    skb->mark = PEP_SKB_MARK_RETRANS;
    skb->priority = 0;

    return skb;
}

/*
 * 功能/Main: 处理字节缓存（Handle byte cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；字节缓存读写（byte cache access）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: ctx, entry
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static struct sk_buff *pep_byte_cache_read_disk(struct pep_context *ctx,
                                                struct pep_byte_cache_entry *entry)
{
    u8 *buf;
    loff_t pos;
    ssize_t read_len;
    struct sk_buff *skb;

    if (!ctx || !entry || !ctx->byte_cache_file || entry->disk_len == 0)
        return NULL;

    buf = kmalloc(entry->disk_len, GFP_KERNEL);
    if (!buf)
        return NULL;

    mutex_lock(&pep_byte_cache_disk_mutex);
    pos = entry->disk_off;
    read_len = kernel_read(ctx->byte_cache_file, buf, entry->disk_len, &pos);
    mutex_unlock(&pep_byte_cache_disk_mutex);

    if (read_len != entry->disk_len) {
        kfree(buf);
        return NULL;
    }

    skb = pep_byte_cache_build_skb(buf, entry->disk_len);
    kfree(buf);
    return skb;
}

/*
 * 功能/Main: 后台处理字节缓存（Work task byte cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；流表查找/创建/状态更新（flow lookup/create/update）；字节缓存读写（byte cache access）；并发同步（spinlock/atomic/rcu）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: work
 * 影响/Effects: 后台维护/调度，影响吞吐与时延（background maintenance/scheduling, affects throughput/latency）
 * 重要程度/Importance: 中/Medium
 */
static void pep_byte_cache_read_work_handler(struct work_struct *work)
{
    struct pep_byte_cache_read_work *rw =
        container_of(work, struct pep_byte_cache_read_work, work);
    struct pep_byte_cache_entry *entry = rw->entry;
    struct pep_flow *flow = rw->flow;
    struct pep_context *ctx = READ_ONCE(pep_ctx);
    struct sk_buff *skb = NULL;
    unsigned long flags;

    if (ctx && ctx->config.byte_cache_enabled)
        skb = pep_byte_cache_read_disk(ctx, entry);

    if (skb)
        pep_send_lan_skb(flow, skb);

    spin_lock_irqsave(&flow->byte_cache_lock, flags);
    entry->flags &= ~PEP_BYTE_CACHE_F_READ_PENDING;
    spin_unlock_irqrestore(&flow->byte_cache_lock, flags);

    pep_flow_put(flow);
    pep_byte_cache_entry_put(entry);
    kfree(rw);
}

/*
 * 功能/Main: 处理字节缓存（Handle byte cache）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；字节缓存读写（byte cache access）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow, entry
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static int pep_byte_cache_schedule_read(struct pep_flow *flow,
                                        struct pep_byte_cache_entry *entry)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);
    struct pep_byte_cache_read_work *rw;

    if (!ctx || !ctx->byte_cache_wq)
        return -EINVAL;

    rw = kzalloc(sizeof(*rw), GFP_ATOMIC);
    if (!rw)
        return -ENOMEM;

    refcount_inc(&entry->refcnt);
    pep_flow_get(flow);

    rw->entry = entry;
    rw->flow = flow;
    INIT_WORK(&rw->work, pep_byte_cache_read_work_handler);

    if (!queue_work(ctx->byte_cache_wq, &rw->work)) {
        entry->flags &= ~PEP_BYTE_CACHE_F_READ_PENDING;
        pep_flow_put(flow);
        pep_byte_cache_entry_put(entry);
        kfree(rw);
        return -EAGAIN;
    }

    return 0;
}

/*
 * 功能/Main: 处理重传/缓存（Handle retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；重传/缓存处理（retransmission/cache）；字节缓存读写（byte cache access）；并发同步（spinlock/atomic/rcu）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: flow, start, end, budget
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static u32 pep_byte_cache_retrans_gap(struct pep_flow *flow, u32 start, u32 end, u32 budget)
{
    struct pep_byte_cache_entry *entry;
    struct sk_buff *clone = NULL;
    unsigned long flags;
    u32 sent = 0;
    bool hold_ref = false;

    spin_lock_irqsave(&flow->byte_cache_lock, flags);
    entry = pep_byte_cache_find_covering_locked(flow, start);
    if (!entry)
        entry = pep_byte_cache_find_ge_locked(flow, start);

    if (entry && PEP_SEQ_BEFORE(entry->seq, end)) {
        if (entry->skb) {
            refcount_inc(&entry->refcnt);
            hold_ref = true;
            clone = skb_copy(entry->skb, GFP_ATOMIC);
        } else if (entry->flags & PEP_BYTE_CACHE_F_ON_DISK) {
            if (!(entry->flags & PEP_BYTE_CACHE_F_READ_PENDING)) {
                entry->flags |= PEP_BYTE_CACHE_F_READ_PENDING;
                pep_byte_cache_schedule_read(flow, entry);
            }
        }
    } else {
        entry = NULL;
    }
    spin_unlock_irqrestore(&flow->byte_cache_lock, flags);

    if (!entry)
        return 0;

    if (clone) {
        clone->mark = PEP_SKB_MARK_RETRANS;
        if (pep_send_lan_skb(flow, clone) == 0) {
            u32 payload_len = entry->end - entry->seq;
            if (payload_len > budget)
                payload_len = budget;
            sent = payload_len;
        } else {
            kfree_skb(clone);
        }
    }

    if (hold_ref)
        pep_byte_cache_entry_put(entry);
    return sent;
}

/*
 * 功能/Main: 处理字节缓存（Handle byte cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；字节缓存读写（byte cache access）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: ctx
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static void pep_byte_cache_evict(struct pep_context *ctx)
{
    unsigned long flags;

    if (!ctx || ctx->byte_cache_max_bytes == 0)
        return;

    while (true) {
        struct pep_byte_cache_entry *entry;
        struct pep_flow *flow;
        unsigned long flow_flags;

        spin_lock_irqsave(&ctx->byte_cache_lock, flags);
        if (ctx->byte_cache_bytes <= ctx->byte_cache_max_bytes ||
            list_empty(&ctx->byte_cache_lru)) {
            spin_unlock_irqrestore(&ctx->byte_cache_lock, flags);
            break;
        }

        entry = list_first_entry(&ctx->byte_cache_lru,
                                 struct pep_byte_cache_entry, lru_node);
        if (!entry->skb) {
            list_move_tail(&entry->lru_node, &ctx->byte_cache_lru);
            spin_unlock_irqrestore(&ctx->byte_cache_lock, flags);
            continue;
        }
        list_del_init(&entry->lru_node);
        if (entry->skb)
            ctx->byte_cache_bytes -= entry->len;
        spin_unlock_irqrestore(&ctx->byte_cache_lock, flags);

        flow = entry->flow;
        spin_lock_irqsave(&flow->byte_cache_lock, flow_flags);
        rb_erase(&entry->rb, &flow->byte_cache_root);
        list_del_init(&entry->flow_node);
        if (entry->skb)
            flow->byte_cache_bytes -= entry->len;
        if (flow->byte_cache_entries > 0)
            flow->byte_cache_entries--;
        spin_unlock_irqrestore(&flow->byte_cache_lock, flow_flags);

        pep_byte_cache_entry_put(entry);
    }
}

/*
 * 功能/Main: 处理字节缓存（Handle byte cache）
 * 细节/Details: 字节缓存读写（byte cache access）
 * 输入/Inputs: 参数/Inputs: ctx
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_byte_cache_trim(struct pep_context *ctx)
{
    if (!ctx)
        return;

    pep_byte_cache_evict(ctx);
}

/*
 * 功能/Main: 初始化字节缓存（Initialize byte cache）
 * 细节/Details: 队列/链表维护（queue/list maintenance）；字节缓存读写（byte cache access）；并发同步（spinlock/atomic/rcu）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: ctx
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
int pep_byte_cache_init(struct pep_context *ctx)
{
    if (!ctx)
        return -EINVAL;

    if (ctx->byte_cache_wq || ctx->byte_cache_file)
        pep_byte_cache_exit(ctx);

    spin_lock_init(&ctx->byte_cache_lock);
    INIT_LIST_HEAD(&ctx->byte_cache_lru);
    ctx->byte_cache_bytes = 0;
    ctx->byte_cache_max_bytes = (u64)ctx->config.byte_cache_mem_mb * 1024ULL * 1024ULL;
    ctx->byte_cache_disk_max_bytes = (u64)ctx->config.byte_cache_disk_mb * 1024ULL * 1024ULL;
    ctx->byte_cache_disk_used = 0;
    ctx->byte_cache_file = NULL;
    strscpy(ctx->byte_cache_disk_path, ctx->config.byte_cache_disk_path,
            sizeof(ctx->byte_cache_disk_path));

    if (!ctx->config.byte_cache_enabled)
        return 0;

    ctx->byte_cache_wq = alloc_workqueue("pep_byte_cache",
                                         WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
    if (!ctx->byte_cache_wq)
        return -ENOMEM;

    if (ctx->byte_cache_disk_max_bytes > 0) {
        ctx->byte_cache_file = filp_open(ctx->byte_cache_disk_path,
                                         O_CREAT | O_RDWR | O_TRUNC, 0600);
        if (IS_ERR(ctx->byte_cache_file)) {
            pep_warn("Byte cache: failed to open %s\n", ctx->byte_cache_disk_path);
            ctx->byte_cache_file = NULL;
        }
    }

    return 0;
}

/*
 * 功能/Main: 清理字节缓存（Cleanup byte cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；字节缓存读写（byte cache access）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: ctx
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_byte_cache_exit(struct pep_context *ctx)
{
    struct pep_byte_cache_entry *entry;
    struct pep_byte_cache_entry *tmp;
    LIST_HEAD(free_list);
    unsigned long flags;

    if (!ctx)
        return;

    if (ctx->byte_cache_wq) {
        flush_workqueue(ctx->byte_cache_wq);
        destroy_workqueue(ctx->byte_cache_wq);
        ctx->byte_cache_wq = NULL;
    }

    spin_lock_irqsave(&ctx->byte_cache_lock, flags);
    list_for_each_entry_safe(entry, tmp, &ctx->byte_cache_lru, lru_node) {
        list_del_init(&entry->lru_node);
        if (entry->skb && ctx->byte_cache_bytes >= entry->len)
            ctx->byte_cache_bytes -= entry->len;
        list_add(&entry->lru_node, &free_list);
    }
    spin_unlock_irqrestore(&ctx->byte_cache_lock, flags);

    list_for_each_entry_safe(entry, tmp, &free_list, lru_node) {
        struct pep_flow *flow = entry->flow;
        unsigned long flow_flags;

        spin_lock_irqsave(&flow->byte_cache_lock, flow_flags);
        rb_erase(&entry->rb, &flow->byte_cache_root);
        list_del_init(&entry->flow_node);
        if (entry->skb && flow->byte_cache_bytes >= entry->len)
            flow->byte_cache_bytes -= entry->len;
        if (flow->byte_cache_entries > 0)
            flow->byte_cache_entries--;
        spin_unlock_irqrestore(&flow->byte_cache_lock, flow_flags);

        list_del_init(&entry->lru_node);
        pep_byte_cache_entry_put(entry);
    }

    if (ctx->byte_cache_file) {
        filp_close(ctx->byte_cache_file, NULL);
        ctx->byte_cache_file = NULL;
    }
    ctx->byte_cache_disk_used = 0;
    ctx->byte_cache_disk_max_bytes = 0;
    ctx->byte_cache_max_bytes = 0;
}

/*
 * 功能/Main: 初始化流表/会话状态（Initialize flow/session state）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；字节缓存读写（byte cache access）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
void pep_byte_cache_flow_init(struct pep_flow *flow)
{
    if (!flow)
        return;

    flow->byte_cache_root = RB_ROOT;
    INIT_LIST_HEAD(&flow->byte_cache_list);
    spin_lock_init(&flow->byte_cache_lock);
    flow->byte_cache_bytes = 0;
    flow->byte_cache_entries = 0;
    flow->byte_cache_enabled = 1;
}

/*
 * 功能/Main: 清理流表/会话状态（Cleanup flow/session state）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；字节缓存读写（byte cache access）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_byte_cache_flow_cleanup(struct pep_flow *flow)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);
    struct pep_byte_cache_entry *entry;
    struct pep_byte_cache_entry *tmp;
    LIST_HEAD(free_list);
    unsigned long flags;
    unsigned long flow_flags;

    if (!flow || !ctx)
        return;

    spin_lock_irqsave(&ctx->byte_cache_lock, flags);
    spin_lock_irqsave(&flow->byte_cache_lock, flow_flags);
    list_for_each_entry_safe(entry, tmp, &flow->byte_cache_list, flow_node) {
        list_del_init(&entry->flow_node);
        rb_erase(&entry->rb, &flow->byte_cache_root);
        if (!list_empty(&entry->lru_node))
            list_del_init(&entry->lru_node);
        if (entry->skb) {
            if (flow->byte_cache_bytes >= entry->len)
                flow->byte_cache_bytes -= entry->len;
            if (ctx->byte_cache_bytes >= entry->len)
                ctx->byte_cache_bytes -= entry->len;
        }
        if (flow->byte_cache_entries > 0)
            flow->byte_cache_entries--;
        list_add(&entry->flow_node, &free_list);
    }
    spin_unlock_irqrestore(&flow->byte_cache_lock, flow_flags);
    spin_unlock_irqrestore(&ctx->byte_cache_lock, flags);

    list_for_each_entry_safe(entry, tmp, &free_list, flow_node) {
        list_del_init(&entry->flow_node);
        pep_byte_cache_entry_put(entry);
    }
}

/*
 * 功能/Main: 处理字节缓存（Handle byte cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；字节缓存读写（byte cache access）；并发同步（spinlock/atomic/rcu）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, skb, seq, len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
int pep_byte_cache_add(struct pep_flow *flow, struct sk_buff *skb,
                       u32 seq, u32 len)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);
    struct pep_byte_cache_entry *entry;
    unsigned long flags;
    unsigned long flow_flags;
    bool spill = false;

    if (!flow || !skb || len == 0 || !ctx || !ctx->config.byte_cache_enabled) {
        if (skb)
            kfree_skb(skb);
        return -EINVAL;
    }

    entry = pep_byte_cache_entry_alloc(flow, skb, seq, len);
    if (!entry) {
        kfree_skb(skb);
        return -ENOMEM;
    }

    if (ctx->byte_cache_disk_max_bytes > 0 &&
        (ctx->byte_cache_max_bytes == 0 ||
         ctx->byte_cache_bytes + entry->len > ctx->byte_cache_max_bytes)) {
        spill = true;
    }

    if (spill)
        pep_byte_cache_write_disk(ctx, entry);
    if (ctx->byte_cache_max_bytes == 0 && entry->skb) {
        pep_byte_cache_entry_put(entry);
        return -ENOSPC;
    }

    spin_lock_irqsave(&ctx->byte_cache_lock, flags);
    spin_lock_irqsave(&flow->byte_cache_lock, flow_flags);
    if (pep_byte_cache_find_overlap_locked(flow, entry->seq, entry->end)) {
        spin_unlock_irqrestore(&flow->byte_cache_lock, flow_flags);
        spin_unlock_irqrestore(&ctx->byte_cache_lock, flags);
        pep_byte_cache_entry_put(entry);
        return -EEXIST;
    }

    {
        struct rb_node **link = &flow->byte_cache_root.rb_node;
        struct rb_node *parent = NULL;

        while (*link) {
            struct pep_byte_cache_entry *cur =
                rb_entry(*link, struct pep_byte_cache_entry, rb);
            parent = *link;
            if (PEP_SEQ_BEFORE(entry->seq, cur->seq))
                link = &(*link)->rb_left;
            else
                link = &(*link)->rb_right;
        }

        rb_link_node(&entry->rb, parent, link);
        rb_insert_color(&entry->rb, &flow->byte_cache_root);
    }

    list_add_tail(&entry->flow_node, &flow->byte_cache_list);
    list_add_tail(&entry->lru_node, &ctx->byte_cache_lru);
    flow->byte_cache_entries++;
    if (entry->skb) {
        flow->byte_cache_bytes += entry->len;
        ctx->byte_cache_bytes += entry->len;
    }

    spin_unlock_irqrestore(&flow->byte_cache_lock, flow_flags);
    spin_unlock_irqrestore(&ctx->byte_cache_lock, flags);

    pep_byte_cache_evict(ctx);
    return 0;
}

/*
 * 功能/Main: 处理字节缓存（Handle byte cache）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；重传/缓存处理（retransmission/cache）；字节缓存读写（byte cache access）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, opts, ack_seq
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_byte_cache_on_ack(struct pep_flow *flow,
                           const struct pep_tcp_options *opts,
                           u32 ack_seq)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);
    struct {
        u32 start;
        u32 end;
    } ranges[4];
    int n = 0;
    int i;
    u32 cursor;
    u32 budget = PEP_BYTE_CACHE_MAX_RETRANS_BYTES;

    if (!ctx || !ctx->config.byte_cache_enabled || !flow || !opts)
        return;

    if (opts->sack_blocks_count == 0)
        return;

    for (i = 0; i < opts->sack_blocks_count && n < 4; i++) {
        u32 start = opts->sack_blocks[i].start;
        u32 end = opts->sack_blocks[i].end;

        if (!start || !end)
            continue;
        if (!PEP_SEQ_BEFORE(start, end))
            continue;
        ranges[n].start = start;
        ranges[n].end = end;
        n++;
    }

    for (i = 0; i < n - 1; i++) {
        int j;
        for (j = i + 1; j < n; j++) {
            if (PEP_SEQ_AFTER(ranges[i].start, ranges[j].start)) {
                u32 ts = ranges[i].start;
                u32 te = ranges[i].end;
                ranges[i].start = ranges[j].start;
                ranges[i].end = ranges[j].end;
                ranges[j].start = ts;
                ranges[j].end = te;
            }
        }
    }

    cursor = ack_seq;
    for (i = 0; i < n; i++) {
        if (PEP_SEQ_AFTER(ranges[i].start, cursor)) {
            u32 gap_start = cursor;
            u32 gap_end = ranges[i].start;
            u32 sent;

            sent = pep_byte_cache_retrans_gap(flow, gap_start, gap_end, budget);
            if (sent > budget)
                sent = budget;
            budget -= sent;
            if (budget == 0)
                break;
        }

        if (PEP_SEQ_AFTER(ranges[i].end, cursor))
            cursor = ranges[i].end;
    }
}
