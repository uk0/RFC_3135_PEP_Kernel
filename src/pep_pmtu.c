/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"
#include <linux/icmp.h>
#include <net/icmp.h>
#include <net/dst.h>
#include <net/route.h>

extern struct pep_context *pep_ctx;

#define PEP_PMTU_MIN            576
#define PEP_PMTU_MAX            65535
#define PEP_PMTU_CACHE_SIZE     256

struct pep_pmtu_entry {
    struct hlist_node       hnode;
    __be32                  dst_addr;
    u32                     pmtu;
    ktime_t                 last_update;
    atomic_t                refcnt;
};

struct pep_pmtu_cache {
    struct hlist_head       entries[PEP_PMTU_CACHE_SIZE];
    raw_spinlock_t          lock;
    atomic_t                count;
    u32                     default_pmtu;
    u32                     timeout_ms;

    u64                     lookups;
    u64                     hits;
    u64                     updates;
    u64                     icmp_sent;
    u64                     icmp_received;
};

static struct pep_pmtu_cache *pmtu_cache = NULL;

/*
 * 功能/Main: PMTU/MSS 处理（Handle PMTU/MSS handling）
 * 细节/Details: PMTU/MSS 更新（PMTU/MSS update）
 * 输入/Inputs: 参数/Inputs: dst_addr
 * 影响/Effects: 更新 PMTU 策略，影响分片与 MSS（update PMTU policy, affects fragmentation/MSS）
 * 重要程度/Importance: 中/Medium
 */
static inline u32 pep_pmtu_hash(__be32 dst_addr)
{
    return jhash_1word(dst_addr, 0) & (PEP_PMTU_CACHE_SIZE - 1);
}

/*
 * 功能/Main: 初始化PMTU/MSS 处理（Initialize PMTU/MSS handling）
 * 细节/Details: 队列/链表维护（queue/list maintenance）；PMTU/MSS 更新（PMTU/MSS update）；并发同步（spinlock/atomic/rcu）；配置/参数应用（config/params）
 * 输入/Inputs: 无（void）/none
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
int pep_pmtu_init(void)
{
    int i;
    u32 default_pmtu = PEP_PMTU_DEFAULT;
    u32 timeout_ms = PEP_PMTU_TIMEOUT_MS;

    pmtu_cache = kzalloc(sizeof(*pmtu_cache), GFP_KERNEL);
    if (!pmtu_cache)
        return -ENOMEM;

    for (i = 0; i < PEP_PMTU_CACHE_SIZE; i++)
        INIT_HLIST_HEAD(&pmtu_cache->entries[i]);

    raw_spin_lock_init(&pmtu_cache->lock);
    atomic_set(&pmtu_cache->count, 0);
    if (pep_ctx) {
        if (pep_ctx->config.pmtu_default)
            default_pmtu = pep_ctx->config.pmtu_default;
        if (pep_ctx->config.pmtu_timeout_ms)
            timeout_ms = pep_ctx->config.pmtu_timeout_ms;
    }
    if (default_pmtu < PEP_PMTU_MIN)
        default_pmtu = PEP_PMTU_MIN;
    if (default_pmtu > PEP_PMTU_MAX)
        default_pmtu = PEP_PMTU_MAX;
    pmtu_cache->default_pmtu = default_pmtu;
    pmtu_cache->timeout_ms = timeout_ms;

    pep_info("PMTU: Cache initialized (size=%u, default=%u, timeout=%u ms)\n",
             PEP_PMTU_CACHE_SIZE, pmtu_cache->default_pmtu,
             pmtu_cache->timeout_ms);

    return 0;
}

/*
 * 功能/Main: 清理PMTU/MSS 处理（Cleanup PMTU/MSS handling）
 * 细节/Details: PMTU/MSS 更新（PMTU/MSS update）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 无（void）/none
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_pmtu_exit(void)
{
    struct pep_pmtu_entry *entry;
    struct hlist_node *tmp;
    int i;
    unsigned long flags;

    if (!pmtu_cache)
        return;

    raw_spin_lock_irqsave(&pmtu_cache->lock, flags);

    for (i = 0; i < PEP_PMTU_CACHE_SIZE; i++) {
        hlist_for_each_entry_safe(entry, tmp, &pmtu_cache->entries[i], hnode) {
            hlist_del(&entry->hnode);
            kfree(entry);
        }
    }

    raw_spin_unlock_irqrestore(&pmtu_cache->lock, flags);

    pep_info("PMTU: Cache cleaned (lookups=%llu, hits=%llu, hit_rate=%llu/%llu)\n",
             pmtu_cache->lookups, pmtu_cache->hits,
             pmtu_cache->hits, pmtu_cache->lookups);

    kfree(pmtu_cache);
    pmtu_cache = NULL;
}

/*
 * 功能/Main: 获取PMTU/MSS 处理（Get PMTU/MSS handling）
 * 细节/Details: PMTU/MSS 更新（PMTU/MSS update）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: dst_addr
 * 影响/Effects: 更新 PMTU 策略，影响分片与 MSS（update PMTU policy, affects fragmentation/MSS）
 * 重要程度/Importance: 中/Medium
 */
u32 pep_pmtu_get(__be32 dst_addr)
{
    struct pep_pmtu_entry *entry;
    u32 hash;
    u32 pmtu;
    unsigned long flags;
    ktime_t now;
    s64 age_ms;

    if (!pmtu_cache)
        return PEP_PMTU_DEFAULT;

    hash = pep_pmtu_hash(dst_addr);

    raw_spin_lock_irqsave(&pmtu_cache->lock, flags);
    pmtu_cache->lookups++;

    hlist_for_each_entry(entry, &pmtu_cache->entries[hash], hnode) {
        if (entry->dst_addr == dst_addr) {

            now = ktime_get();
            age_ms = ktime_ms_delta(now, entry->last_update);

            if (pmtu_cache->timeout_ms > 0 &&
                age_ms > pmtu_cache->timeout_ms) {

                hlist_del(&entry->hnode);
                atomic_dec(&pmtu_cache->count);
                kfree(entry);
                break;
            }

            pmtu_cache->hits++;
            pmtu = entry->pmtu;
            raw_spin_unlock_irqrestore(&pmtu_cache->lock, flags);
            return pmtu;
        }
    }

    raw_spin_unlock_irqrestore(&pmtu_cache->lock, flags);

    return pmtu_cache->default_pmtu;
}

/*
 * 功能/Main: 更新PMTU/MSS 处理（Update PMTU/MSS handling）
 * 细节/Details: PMTU/MSS 更新（PMTU/MSS update）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: dst_addr, pmtu
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 中/Medium
 */
void pep_pmtu_update(__be32 dst_addr, u32 pmtu)
{
    struct pep_pmtu_entry *entry, *new_entry;
    u32 hash;
    unsigned long flags;
    bool found = false;

    if (!pmtu_cache)
        return;

    if (pmtu < PEP_PMTU_MIN)
        pmtu = PEP_PMTU_MIN;
    if (pmtu > PEP_PMTU_MAX)
        pmtu = PEP_PMTU_MAX;

    hash = pep_pmtu_hash(dst_addr);

    raw_spin_lock_irqsave(&pmtu_cache->lock, flags);

    hlist_for_each_entry(entry, &pmtu_cache->entries[hash], hnode) {
        if (entry->dst_addr == dst_addr) {
            entry->pmtu = pmtu;
            entry->last_update = ktime_get();
            pmtu_cache->updates++;
            found = true;
            break;
        }
    }

    if (!found && atomic_read(&pmtu_cache->count) < PEP_PMTU_CACHE_SIZE * 2) {

        new_entry = kzalloc(sizeof(*new_entry), GFP_ATOMIC);
        if (new_entry) {
            new_entry->dst_addr = dst_addr;
            new_entry->pmtu = pmtu;
            new_entry->last_update = ktime_get();
            atomic_set(&new_entry->refcnt, 1);

            hlist_add_head(&new_entry->hnode, &pmtu_cache->entries[hash]);
            atomic_inc(&pmtu_cache->count);
            pmtu_cache->updates++;

            pep_dbg("PMTU: Updated %pI4 to %u bytes\n", &dst_addr, pmtu);
        }
    }

    raw_spin_unlock_irqrestore(&pmtu_cache->lock, flags);
}

/*
 * 功能/Main: 设置PMTU/MSS 处理（Set PMTU/MSS handling）
 * 细节/Details: PMTU/MSS 更新（PMTU/MSS update）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: default_pmtu, timeout_ms
 * 影响/Effects: 更新 PMTU 策略，影响分片与 MSS（update PMTU policy, affects fragmentation/MSS）
 * 重要程度/Importance: 中/Medium
 */
void pep_pmtu_set_defaults(u32 default_pmtu, u32 timeout_ms)
{
    unsigned long flags;

    if (!pmtu_cache)
        return;

    raw_spin_lock_irqsave(&pmtu_cache->lock, flags);
    if (default_pmtu >= PEP_PMTU_MIN && default_pmtu <= PEP_PMTU_MAX)
        pmtu_cache->default_pmtu = default_pmtu;
    if (timeout_ms > 0)
        pmtu_cache->timeout_ms = timeout_ms;
    raw_spin_unlock_irqrestore(&pmtu_cache->lock, flags);
}

/*
 * 功能/Main: PMTU/MSS 处理（Handle PMTU/MSS handling）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；frag/分片结构处理（frag list handling）；流表查找/创建/状态更新（flow lookup/create/update）；PMTU/MSS 更新（PMTU/MSS update）
 * 输入/Inputs: 参数/Inputs: skb
 * 影响/Effects: 更新 PMTU 策略，影响分片与 MSS（update PMTU policy, affects fragmentation/MSS）
 * 重要程度/Importance: 高/High
 */
void pep_pmtu_handle_icmp_frag_needed(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct icmphdr *icmph;
    struct iphdr *inner_iph;
    struct tcphdr *inner_tcph;
    __be32 dst_addr;
    u32 mtu;

    if (!skb || !pmtu_cache)
        return;

    iph = ip_hdr(skb);
    icmph = icmp_hdr(skb);

    mtu = ntohs(icmph->un.frag.mtu);
    if (mtu == 0) {

        mtu = 1492;
    }

    inner_iph = (struct iphdr *)((u8 *)icmph + sizeof(*icmph));

    if (inner_iph->protocol != IPPROTO_TCP)
        return;

    inner_tcph = (struct tcphdr *)((u8 *)inner_iph + (inner_iph->ihl * 4));
    dst_addr = inner_iph->daddr;

    pep_pmtu_update(dst_addr, mtu);

    pmtu_cache->icmp_received++;

    pep_info("PMTU: ICMP Frag Needed from %pI4, MTU=%u for dst=%pI4\n",
             &iph->saddr, mtu, &dst_addr);

    struct pep_context *ctx;
    struct iphdr *orig_iph;
    struct tcphdr *orig_tcph;
    struct pep_tuple tuple;
    struct pep_flow *flow;
    u32 new_mss;

    ctx = READ_ONCE(pep_ctx);
    if (!ctx || !icmph)
        return;

    orig_iph = (struct iphdr *)(icmph + 1);

    if (orig_iph->protocol != IPPROTO_TCP)
        return;

    orig_tcph = (struct tcphdr *)((unsigned char *)orig_iph + (orig_iph->ihl * 4));

    tuple.src_addr = orig_iph->saddr;
    tuple.dst_addr = orig_iph->daddr;
    tuple.src_port = orig_tcph->source;
    tuple.dst_port = orig_tcph->dest;
    tuple.protocol = IPPROTO_TCP;

    flow = pep_flow_find(&ctx->flow_table, &tuple);
    if (!flow) {
        pep_dbg("PMTU: No flow found for ICMP frag needed from %pI4\n",
                &orig_iph->daddr);
        return;
    }

    new_mss = mtu - 40;

    if (flow->mss > new_mss) {
        u32 old_mss = flow->mss;
        flow->mss = new_mss;
        pr_info("pep: PMTU adjusted MSS for flow %pI4:%u -> %pI4:%u from %u to %u\n",
                &tuple.src_addr, ntohs(tuple.src_port),
                &tuple.dst_addr, ntohs(tuple.dst_port),
                old_mss, new_mss);
    }

    pep_fec_adjust_mss(flow);
    pep_flow_put(flow);
}

/*
 * 功能/Main: 发送PMTU/MSS 处理（Send PMTU/MSS handling）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；frag/分片结构处理（frag list handling）；PMTU/MSS 更新（PMTU/MSS update）；并发同步（spinlock/atomic/rcu）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: skb, mtu
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
int pep_pmtu_send_icmp_frag_needed(struct sk_buff *skb, u32 mtu)
{
    struct iphdr *iph;
    struct sk_buff *nskb;
    struct iphdr *niph;
    struct icmphdr *icmph;
    int hlen, payload_len;
    __be32 saddr;

    if (!skb || !pmtu_cache)
        return -EINVAL;

    iph = ip_hdr(skb);

    if (iph->protocol == IPPROTO_ICMP)
        return 0;

    hlen = sizeof(struct iphdr) + sizeof(struct icmphdr);
    payload_len = min_t(int, 8 + (iph->ihl * 4) + 8, skb->len);

    nskb = alloc_skb(LL_MAX_HEADER + hlen + payload_len, GFP_ATOMIC);
    if (!nskb)
        return -ENOMEM;

    skb_reserve(nskb, LL_MAX_HEADER);
    skb_reset_network_header(nskb);

    niph = skb_put(nskb, sizeof(struct iphdr));
    niph->version = 4;
    niph->ihl = 5;
    niph->tos = 0;
    niph->tot_len = htons(hlen + payload_len);
    niph->id = 0;
    niph->frag_off = htons(IP_DF);
    niph->ttl = 64;
    niph->protocol = IPPROTO_ICMP;
    niph->check = 0;

    saddr = 0;
    niph->saddr = saddr;
    niph->daddr = iph->saddr;

    skb_set_transport_header(nskb, sizeof(struct iphdr));
    icmph = skb_put(nskb, sizeof(struct icmphdr));
    icmph->type = ICMP_DEST_UNREACH;
    icmph->code = ICMP_FRAG_NEEDED;
    icmph->checksum = 0;
    icmph->un.frag.mtu = htons(mtu);
    icmph->un.frag.__unused = 0;

    skb_put_data(nskb, iph, payload_len);

    niph->check = 0;

    icmph->checksum = ip_compute_csum((unsigned char *)icmph,
                                       sizeof(*icmph) + payload_len);

    nskb->protocol = htons(ETH_P_IP);
    nskb->mark = PEP_SKB_MARK;
    nskb->priority = 0;

    if (pep_send_wan_skb(nskb) == 0) {
        if (pmtu_cache)
            pmtu_cache->icmp_sent++;
        pep_dbg("PMTU: Sent ICMP Frag Needed to %pI4, MTU=%u\n",
                &niph->daddr, mtu);
        return 0;
    }

    pep_warn("PMTU: Failed to send ICMP Frag Needed\n");
    return -EIO;
}

/*
 * 功能/Main: PMTU/MSS 处理（Handle PMTU/MSS handling）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；frag/分片结构处理（frag list handling）；PMTU/MSS 更新（PMTU/MSS update）
 * 输入/Inputs: 参数/Inputs: skb, dst_addr
 * 影响/Effects: 更新 PMTU 策略，影响分片与 MSS（update PMTU policy, affects fragmentation/MSS）
 * 重要程度/Importance: 中/Medium
 */
u32 pep_pmtu_check_fragmentation(struct sk_buff *skb, __be32 dst_addr)
{
    struct iphdr *iph;
    u32 pmtu;
    u32 pkt_len;

    if (!skb)
        return 0;

    iph = ip_hdr(skb);

    if (iph->protocol == IPPROTO_ICMP)
        return 0;

    pkt_len = ntohs(iph->tot_len);

    pmtu = pep_pmtu_get(dst_addr);

    if (pkt_len > pmtu) {

        if (iph->frag_off & htons(IP_DF)) {

            return pmtu;
        }

        pep_dbg("PMTU: Packet len=%u exceeds PMTU=%u for %pI4 (fragmenting)\n",
                pkt_len, pmtu, &dst_addr);
    }

    return 0;
}

/*
 * 功能/Main: 获取PMTU/MSS 处理（Get PMTU/MSS handling）
 * 细节/Details: PMTU/MSS 更新（PMTU/MSS update）
 * 输入/Inputs: 参数/Inputs: lookups, hits, updates, icmp_sent, icmp_received
 * 影响/Effects: 更新 PMTU 策略，影响分片与 MSS（update PMTU policy, affects fragmentation/MSS）
 * 重要程度/Importance: 中/Medium
 */
void pep_pmtu_get_stats(u64 *lookups, u64 *hits, u64 *updates,
                        u64 *icmp_sent, u64 *icmp_received)
{
    if (!pmtu_cache) {
        *lookups = 0;
        *hits = 0;
        *updates = 0;
        *icmp_sent = 0;
        *icmp_received = 0;
        return;
    }

    *lookups = pmtu_cache->lookups;
    *hits = pmtu_cache->hits;
    *updates = pmtu_cache->updates;
    *icmp_sent = pmtu_cache->icmp_sent;
    *icmp_received = pmtu_cache->icmp_received;
}

/*
 * 功能/Main: PMTU/MSS 处理（Handle PMTU/MSS handling）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；PMTU/MSS 更新（PMTU/MSS update）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新 PMTU 策略，影响分片与 MSS（update PMTU policy, affects fragmentation/MSS）
 * 重要程度/Importance: 中/Medium
 */
void pep_pmtu_adjust_mss(struct pep_flow *flow)
{
    u32 pmtu;
    u32 new_mss;

    if (!flow || !pmtu_cache)
        return;

    pmtu = pep_pmtu_get(flow->tuple.dst_addr);

    new_mss = pmtu - 40;

    if (test_bit(PEP_FLOW_F_TIMESTAMP_BIT, &flow->flags))
        new_mss -= 12;
    if (test_bit(PEP_FLOW_F_SACK_ENABLED_BIT, &flow->flags))
        new_mss -= 2;

    if (new_mss < flow->mss) {
        u32 old_mss = flow->mss;
        flow->mss = new_mss;

        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
            pep_info("PMTU: Adjusted MSS for flow %pI4:%u -> %pI4:%u from %u to %u (PMTU=%u)\n",
                     &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
                     &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port),
                     old_mss, new_mss, pmtu);
        }
    }

    pep_fec_adjust_mss(flow);
}

EXPORT_SYMBOL(pep_pmtu_init);
EXPORT_SYMBOL(pep_pmtu_exit);
EXPORT_SYMBOL(pep_pmtu_get);
EXPORT_SYMBOL(pep_pmtu_update);
EXPORT_SYMBOL(pep_pmtu_set_defaults);
EXPORT_SYMBOL(pep_pmtu_handle_icmp_frag_needed);
EXPORT_SYMBOL(pep_pmtu_send_icmp_frag_needed);
EXPORT_SYMBOL(pep_pmtu_check_fragmentation);
EXPORT_SYMBOL(pep_pmtu_get_stats);
EXPORT_SYMBOL(pep_pmtu_adjust_mss);
