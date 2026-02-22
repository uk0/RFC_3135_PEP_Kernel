/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"

extern struct pep_context *pep_ctx;

/*
 * 功能/Main: 初始化pep_queue_init相关逻辑（Initialize pep_queue_init logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；队列/链表维护（queue/list maintenance）；FEC 编码/映射/恢复（FEC encode/map/recover）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: q, min_bytes, max_bytes
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
void pep_queue_init(struct pep_queue *q, u32 min_bytes, u32 max_bytes)
{
    skb_queue_head_init(&q->queue);
    spin_lock_init(&q->lock);
    q->bytes = 0;
    q->packets = 0;
    q->min_bytes = min_bytes;
    q->max_bytes = max_bytes;
    q->effective_max = max_bytes;
    q->absolute_max = max_bytes;
    q->bdp_estimate = 0;
    q->bdp_multiplier = 1;
    q->backpressure_level = 0;
    q->total_enqueued = 0;
    q->total_dropped = 0;
    q->peak_bytes = 0;
    q->peak_packets = 0;
    q->backpressure_events = 0;
}

/*
 * 功能/Main: 初始化pep_queue_init_bdp相关逻辑（Initialize pep_queue_init_bdp logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；队列/链表维护（queue/list maintenance）；FEC 编码/映射/恢复（FEC encode/map/recover）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: q, min_bytes, max_bytes, bdp_multiplier, absolute_max
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
void pep_queue_init_bdp(struct pep_queue *q, u32 min_bytes, u32 max_bytes,
                        u32 bdp_multiplier, u32 absolute_max)
{
    skb_queue_head_init(&q->queue);
    spin_lock_init(&q->lock);
    q->bytes = 0;
    q->packets = 0;
    q->min_bytes = min_bytes;
    q->max_bytes = max_bytes;
    q->effective_max = max_bytes;
    q->absolute_max = absolute_max;
    q->bdp_estimate = 0;
    q->bdp_multiplier = bdp_multiplier;
    q->backpressure_level = 0;
    q->total_enqueued = 0;
    q->total_dropped = 0;
    q->peak_bytes = 0;
    q->peak_packets = 0;
    q->backpressure_events = 0;
}

/*
 * 功能/Main: 销毁pep_queue_destroy相关逻辑（Destroy pep_queue_destroy logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；队列/链表维护（queue/list maintenance）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: q
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_queue_destroy(struct pep_queue *q)
{
    struct sk_buff *skb;
    unsigned long flags;

    spin_lock_irqsave(&q->lock, flags);
    while ((skb = __skb_dequeue(&q->queue)) != NULL) {
        spin_unlock_irqrestore(&q->lock, flags);
        kfree_skb(skb);
        spin_lock_irqsave(&q->lock, flags);
    }
    q->bytes = 0;
    q->packets = 0;
    spin_unlock_irqrestore(&q->lock, flags);
}

/*
 * 功能/Main: 处理pep_queue_enqueue相关逻辑（Handle pep_queue_enqueue logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；队列/链表维护（queue/list maintenance）；FEC 编码/映射/恢复（FEC encode/map/recover）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: q, skb
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
int pep_queue_enqueue(struct pep_queue *q, struct sk_buff *skb)
{
    unsigned long flags;
    u32 new_bytes;
    u32 usage_pct;
    u8 old_bp_level;

    spin_lock_irqsave(&q->lock, flags);

    if (q->bytes + skb->len > q->effective_max) {
        q->total_dropped++;
        spin_unlock_irqrestore(&q->lock, flags);
        return -ENOSPC;
    }

    __skb_queue_tail(&q->queue, skb);
    new_bytes = q->bytes + skb->len;
    q->bytes = new_bytes;
    q->packets++;
    q->total_enqueued++;

    if (new_bytes > q->peak_bytes)
        q->peak_bytes = new_bytes;
    if (q->packets > q->peak_packets)
        q->peak_packets = q->packets;

    old_bp_level = q->backpressure_level;
    if (q->effective_max > 0) {
        usage_pct = (u64)new_bytes * 100 / q->effective_max;

        if (usage_pct >= PEP_QUEUE_BACKPRESSURE_LEVEL2) {
            q->backpressure_level = 2;
        } else if (usage_pct >= PEP_QUEUE_BACKPRESSURE_LEVEL1) {
            q->backpressure_level = 1;
        } else {
            q->backpressure_level = 0;
        }

        if (old_bp_level == 0 && q->backpressure_level > 0)
            q->backpressure_events++;
    }

    spin_unlock_irqrestore(&q->lock, flags);
    return 0;
}

/*
 * 功能/Main: 处理pep_queue_dequeue相关逻辑（Handle pep_queue_dequeue logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；队列/链表维护（queue/list maintenance）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: q
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
struct sk_buff *pep_queue_dequeue(struct pep_queue *q)
{
    struct sk_buff *skb;
    unsigned long flags;

    spin_lock_irqsave(&q->lock, flags);

    skb = __skb_dequeue(&q->queue);
    if (skb) {

        if (unlikely(skb->len > q->bytes)) {
            pr_warn_ratelimited("pep: queue bytes underflow! bytes=%u skb_len=%u, resetting\n",
                                q->bytes, skb->len);
            q->bytes = 0;
        } else {
            q->bytes -= skb->len;
        }
        q->packets--;
    }

    spin_unlock_irqrestore(&q->lock, flags);
    return skb;
}

/*
 * 功能/Main: 处理pep_queue_len相关逻辑（Handle pep_queue_len logic）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: q
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
u32 pep_queue_len(struct pep_queue *q)
{
    return READ_ONCE(q->packets);
}

/*
 * 功能/Main: 更新pep_queue_update_bdp相关逻辑（Update pep_queue_update_bdp logic）
 * 细节/Details: 队列/链表维护（queue/list maintenance）；FEC 编码/映射/恢复（FEC encode/map/recover）；RTT/RTO 估计（RTT/RTO estimation）；并发同步（spinlock/atomic/rcu）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: q, bandwidth_bps, rtt_us
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 中/Medium
 */
void pep_queue_update_bdp(struct pep_queue *q, u32 bandwidth_bps, u32 rtt_us)
{
    unsigned long flags;
    u64 bdp_bytes;
    u32 new_effective_max;

    if (!q || bandwidth_bps == 0 || rtt_us == 0)
        return;

    bdp_bytes = ((u64)bandwidth_bps * (u64)rtt_us) / 8000000ULL;

    bdp_bytes *= q->bdp_multiplier;

    new_effective_max = max_t(u32, q->max_bytes, (u32)bdp_bytes);
    new_effective_max = min_t(u32, new_effective_max, q->absolute_max);

    spin_lock_irqsave(&q->lock, flags);
    q->bdp_estimate = (u32)bdp_bytes;
    q->effective_max = new_effective_max;
    spin_unlock_irqrestore(&q->lock, flags);

    if (pep_ctx && pep_ctx->config.debug_level >= 2) {
        pr_info("pep: BDP queue update: bw=%u bps, rtt=%u us, bdp=%llu bytes, "
                "effective_max=%u (was %u)\n",
                bandwidth_bps, rtt_us, bdp_bytes,
                new_effective_max, q->max_bytes);
    }
}

/*
 * 功能/Main: 处理pep_reseq_consume_locked相关逻辑（Handle pep_reseq_consume_locked logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static void pep_reseq_consume_locked(struct pep_flow *flow)
{
    struct pep_reseq_node *node, *tmp;

    list_for_each_entry_safe(node, tmp, &flow->reseq_list, list) {
        if (PEP_SEQ_AFTER(node->start, flow->reseq_next))
            break;

        if (PEP_SEQ_AFTER(node->end, flow->reseq_next))
            flow->reseq_next = node->end;

        list_del(&node->list);
        kfree(node);
        flow->reseq_queued--;
    }
}

/*
 * 功能/Main: 处理pep_reseq_insert_node相关逻辑（Handle pep_reseq_insert_node logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow, start, end, before
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static bool pep_reseq_insert_node(struct pep_flow *flow, u32 start, u32 end,
                                  struct list_head *before)
{
    struct pep_reseq_node *node;

    if (!flow->reseq_max || flow->reseq_queued >= flow->reseq_max) {
        flow->reseq_dropped++;
        return false;
    }

    node = kmalloc(sizeof(*node), GFP_ATOMIC);
    if (!node) {
        flow->reseq_dropped++;
        return false;
    }

    node->start = start;
    node->end = end;
    list_add_tail(&node->list, before);
    flow->reseq_queued++;

    return true;
}

/*
 * 功能/Main: 处理pep_reseq_insert_locked相关逻辑（Handle pep_reseq_insert_locked logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）
 * 输入/Inputs: 参数/Inputs: flow, start, end
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static bool pep_reseq_insert_locked(struct pep_flow *flow, u32 start, u32 end)
{
    struct pep_reseq_node *node;

    list_for_each_entry(node, &flow->reseq_list, list) {
        if (PEP_SEQ_BEFORE(end, node->start)) {

            return pep_reseq_insert_node(flow, start, end, &node->list);
        }

        if (PEP_SEQ_BEFORE(node->end, start)) {

            continue;
        }

        if (PEP_SEQ_BEFORE(start, node->start))
            node->start = start;
        if (PEP_SEQ_AFTER(end, node->end))
            node->end = end;

        while (node->list.next != &flow->reseq_list) {
            struct pep_reseq_node *next;

            next = list_entry(node->list.next, struct pep_reseq_node, list);
            if (PEP_SEQ_BEFORE(node->end, next->start))
                break;

            if (PEP_SEQ_AFTER(next->end, node->end))
                node->end = next->end;

            list_del(&next->list);
            kfree(next);
            flow->reseq_queued--;
        }

        return true;
    }

    return pep_reseq_insert_node(flow, start, end, &flow->reseq_list);
}

/*
 * 功能/Main: 初始化pep_reseq_init相关逻辑（Initialize pep_reseq_init logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow, max_packets, enabled
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
void pep_reseq_init(struct pep_flow *flow, u32 max_packets, bool enabled)
{
    if (!flow)
        return;

    INIT_LIST_HEAD(&flow->reseq_list);
    spin_lock_init(&flow->reseq_lock);
    flow->reseq_next = 0;
    flow->reseq_max = max_packets;
    flow->reseq_queued = 0;
    flow->reseq_dropped = 0;
    if (!enabled || max_packets == 0)
        flow->reseq_enabled = 0;
    else
        flow->reseq_enabled = 1;
    flow->reseq_initialized = 0;
}

/*
 * 功能/Main: 清理pep_reseq_cleanup相关逻辑（Cleanup pep_reseq_cleanup logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_reseq_cleanup(struct pep_flow *flow)
{
    struct pep_reseq_node *node, *tmp;
    unsigned long flags;

    if (!flow)
        return;

    spin_lock_irqsave(&flow->reseq_lock, flags);
    list_for_each_entry_safe(node, tmp, &flow->reseq_list, list) {
        list_del(&node->list);
        kfree(node);
    }
    flow->reseq_queued = 0;
    spin_unlock_irqrestore(&flow->reseq_lock, flags);
}

/*
 * 功能/Main: 更新pep_reseq_update相关逻辑（Update pep_reseq_update logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow, seg_start, seg_len, new_ack
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 中/Medium
 */
bool pep_reseq_update(struct pep_flow *flow, u32 seg_start, u32 seg_len, u32 *new_ack)
{
    unsigned long flags;
    u32 seg_end;
    bool advanced = false;

    if (!flow || seg_len == 0 || !flow->reseq_enabled)
        return false;

    seg_end = seg_start + seg_len;

    spin_lock_irqsave(&flow->reseq_lock, flags);

    if (!flow->reseq_initialized) {
        if (flow->wan.seq_next != 0)
            flow->reseq_next = flow->wan.seq_next;
        else
            flow->reseq_next = seg_start;
        flow->reseq_initialized = 1;
    }

    if (PEP_SEQ_LEQ(seg_end, flow->reseq_next))
        goto out;

    if (PEP_SEQ_LEQ(seg_start, flow->reseq_next)) {
        if (PEP_SEQ_AFTER(seg_end, flow->reseq_next)) {
            flow->reseq_next = seg_end;
            advanced = true;
            pep_reseq_consume_locked(flow);
        }
        goto out;
    }

    pep_reseq_insert_locked(flow, seg_start, seg_end);

out:
    if (advanced && new_ack)
        *new_ack = flow->reseq_next;
    spin_unlock_irqrestore(&flow->reseq_lock, flags);
    return advanced;
}

/*
 * 功能/Main: 初始化pep_reorder_init相关逻辑（Initialize pep_reorder_init logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow, max_packets, enabled
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
void pep_reorder_init(struct pep_flow *flow, u32 max_packets, bool enabled)
{
    if (!flow)
        return;

    INIT_LIST_HEAD(&flow->reorder_list);
    spin_lock_init(&flow->reorder_lock);
    flow->reorder_next = 0;
    flow->reorder_max = max_packets;
    flow->reorder_queued = 0;
    flow->reorder_dropped = 0;
    flow->reorder_enabled = (enabled && max_packets > 0) ? 1 : 0;
    flow->reorder_initialized = 0;
    flow->reorder_last_activity = ktime_get();
}

/*
 * 功能/Main: 清理pep_reorder_cleanup相关逻辑（Cleanup pep_reorder_cleanup logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_reorder_cleanup(struct pep_flow *flow)
{
    struct pep_reorder_node *node, *tmp;
    unsigned long flags;

    if (!flow)
        return;

    spin_lock_irqsave(&flow->reorder_lock, flags);
    list_for_each_entry_safe(node, tmp, &flow->reorder_list, list) {
        list_del(&node->list);
        if (node->skb)
            kfree_skb(node->skb);
        kfree(node);
    }
    flow->reorder_queued = 0;
    spin_unlock_irqrestore(&flow->reorder_lock, flags);
}

/*
 * 功能/Main: 处理pep_reorder_flush_locked相关逻辑（Handle pep_reorder_flush_locked logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）
 * 输入/Inputs: 参数/Inputs: flow, ready_q, flush_all
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static void pep_reorder_flush_locked(struct pep_flow *flow,
                                     struct sk_buff_head *ready_q,
                                     bool flush_all)
{
    struct pep_reorder_node *node, *tmp;

    list_for_each_entry_safe(node, tmp, &flow->reorder_list, list) {
        if (!flush_all && PEP_SEQ_AFTER(node->seq, flow->reorder_next))
            break;

        list_del(&node->list);
        flow->reorder_queued--;

        if (node->skb) {
            __skb_queue_tail(ready_q, node->skb);
            if (PEP_SEQ_AFTER(node->end, flow->reorder_next))
                flow->reorder_next = node->end;
        }
        kfree(node);
    }
}

/*
 * 功能/Main: 处理pep_reorder_queue相关逻辑（Handle pep_reorder_queue logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；并发同步（spinlock/atomic/rcu）；配置/参数应用（config/params）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: flow, skb, seq, seg_len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
int pep_reorder_queue(struct pep_flow *flow, struct sk_buff *skb,
                      u32 seq, u32 seg_len)
{
    unsigned long flags;
    struct pep_reorder_node *node;
    struct pep_reorder_node *iter;
    struct sk_buff_head ready_q;
    ktime_t now;
    u32 end;
    bool queued_any = false;

    if (!flow || !skb || seg_len == 0 || !flow->reorder_enabled)
        return -EINVAL;

    __skb_queue_head_init(&ready_q);
    now = ktime_get();
    end = seq + seg_len;

    spin_lock_irqsave(&flow->reorder_lock, flags);

    if (!flow->reorder_initialized) {
        flow->reorder_next = seq;
        flow->reorder_initialized = 1;
    }

    if (flow->reorder_queued > 0 &&
        pep_ctx && pep_ctx->config.downlink_reorder_timeout_ms > 0) {
        s64 elapsed_ms = ktime_to_ms(ktime_sub(now, flow->reorder_last_activity));
        if (elapsed_ms >= (s64)pep_ctx->config.downlink_reorder_timeout_ms) {
            pep_reorder_flush_locked(flow, &ready_q, true);
        }
    }

    if (PEP_SEQ_LEQ(end, flow->reorder_next)) {

        spin_unlock_irqrestore(&flow->reorder_lock, flags);
        kfree_skb(skb);
        return 0;
    }

    if (PEP_SEQ_LEQ(seq, flow->reorder_next)) {

        if (PEP_SEQ_AFTER(end, flow->reorder_next))
            flow->reorder_next = end;
        __skb_queue_tail(&ready_q, skb);
        pep_reorder_flush_locked(flow, &ready_q, false);
        flow->reorder_last_activity = now;
        spin_unlock_irqrestore(&flow->reorder_lock, flags);
        goto out_send;
    }

    if (flow->reorder_max > 0 && flow->reorder_queued >= flow->reorder_max) {
        flow->reorder_dropped++;
        spin_unlock_irqrestore(&flow->reorder_lock, flags);
        skb->mark = PEP_SKB_MARK;
        netif_receive_skb(skb);
        return 0;
    }

    node = kmalloc(sizeof(*node), GFP_ATOMIC);
    if (!node) {
        flow->reorder_dropped++;
        spin_unlock_irqrestore(&flow->reorder_lock, flags);
        skb->mark = PEP_SKB_MARK;
        netif_receive_skb(skb);
        return 0;
    }

    node->seq = seq;
    node->end = end;
    node->skb = skb;

    list_for_each_entry(iter, &flow->reorder_list, list) {
        if (PEP_SEQ_BEFORE(seq, iter->seq)) {
            list_add_tail(&node->list, &iter->list);
            node = NULL;
            break;
        }
    }
    if (node)
        list_add_tail(&node->list, &flow->reorder_list);
    flow->reorder_queued++;
    flow->reorder_last_activity = now;
    spin_unlock_irqrestore(&flow->reorder_lock, flags);

    return 0;

out_send:
    while (!skb_queue_empty(&ready_q)) {
        struct sk_buff *out_skb;

        out_skb = __skb_dequeue(&ready_q);
        if (!out_skb)
            break;

        out_skb->mark = PEP_SKB_MARK;
        if (pep_queue_enqueue(&flow->wan_to_lan, out_skb) == 0) {
            queued_any = true;
        } else {

            netif_receive_skb(out_skb);
        }
    }

    if (queued_any)
        pep_schedule_lan_tx(flow);

    return 0;
}

/*
 * 功能/Main: 获取pep_queue_get_backpressure_level相关逻辑（Get pep_queue_get_backpressure_level logic）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: q
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
u8 pep_queue_get_backpressure_level(struct pep_queue *q)
{
    return READ_ONCE(q->backpressure_level);
}

/*
 * 功能/Main: 定时处理GSO/GRO 分段/合并（Timer task GSO/GRO segmentation/aggregation）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；定时器/工作队列上下文（timer/workqueue context）；并发同步（spinlock/atomic/rcu）；GSO/GRO 分段/合并（GSO/GRO seg/agg）
 * 输入/Inputs: 参数/Inputs: timer
 * 影响/Effects: 周期维护状态，影响稳定性（periodic maintenance, affects stability）
 * 重要程度/Importance: 中/Medium
 */
static void pep_gro_flush_work_handler(struct work_struct *work)
{
    struct pep_flow *flow = container_of(work, struct pep_flow, gro_flush_work);
    struct sk_buff *flush_skb = NULL;
    unsigned long flags;
    bool queue_empty;

    if (!flow)
        return;

    /*
     * v87 关键修复: 死亡流也需要刷新 GRO 队列
     *
     * 问题: 之前死亡流直接 return，但 GRO 队列中可能有已聚合的数据包
     *       这些数据包会被丢弃，导致客户端数据不完整
     *
     * 解决: 移除早期返回，让死亡流也能刷新 GRO 队列
     *       只是在最后跳过 timer 重启（因为流已死亡）
     */
    bool is_dead = test_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags);

    spin_lock_irqsave(&flow->gro_lock, flags);
    flush_skb = pep_gro_timeout_flush(&flow->gro_queue, PEP_ADV_ACK_TIMEOUT_US);
    if (flush_skb)
        flow->gro_last_flush = ktime_get();
    queue_empty = skb_queue_empty(&flow->gro_queue);
    spin_unlock_irqrestore(&flow->gro_lock, flags);

    if (flush_skb) {
        /*
         * v69 关键修复: 移除 seq_offset != 0 检查
         *
         * 问题: seq_offset 可能在极端情况下为 0 (ISN_pep == ISN_server)
         *       但 flow 仍然是 spoofed 的，需要完整的 GRO flush 处理
         *
         * 解决: 只检查 SPOOFED_BIT，translate 函数会正确处理 seq_offset == 0
         */
        if (test_bit(PEP_FLOW_F_SPOOFED_BIT, &flow->flags)) {
            /*
             * v67 关键修复: GRO timer flush 需要完整处理
             *
             * 1. 先提取服务器空间的 SEQ 和 payload 长度（翻译前）
             * 2. 更新 flow->wan.seq_next（服务器空间跟踪）
             * 3. 调度 Advance ACK 给服务器
             * 4. 翻译 SEQ 和 ACK 到客户端空间
             * 5. 投递给客户端
             */
            struct iphdr *iph = ip_hdr(flush_skb);
            struct tcphdr *tcph = (struct tcphdr *)((unsigned char *)iph + iph->ihl * 4);
            unsigned int ip_hdr_len = iph->ihl * 4;
            unsigned int tcp_hdr_len = tcph->doff * 4;
            unsigned int payload_len = ntohs(iph->tot_len) - ip_hdr_len - tcp_hdr_len;
            u32 server_seq = ntohl(tcph->seq);
            u32 server_seq_end = server_seq + payload_len;

            /* Step 1: 更新 WAN 接收序列跟踪（服务器空间） */
            if (payload_len > 0 && PEP_SEQ_AFTER(server_seq_end, flow->wan.seq_next)) {
                flow->wan.seq_next = server_seq_end;
            }

            /* Step 2: 调度 Advance ACK（如果启用） */
            if (payload_len > 0 && pep_ctx && pep_ctx->config.aggressive_ack &&
                READ_ONCE(flow->wan_state) == PEP_WAN_ESTABLISHED) {
                pep_schedule_advance_ack(flow, flow->wan.seq_next, payload_len);
            }

            /* Step 3: 翻译 SEQ（服务器空间 → 客户端空间） */
            if (pep_translate_seq_wan_to_lan(flow, flush_skb) < 0) {
                pep_warn("GRO timeout flush: SEQ translation failed\n");
                kfree_skb(flush_skb);
            } else {
                /*
                 * Step 4: 翻译 ACK（服务器 ACK 空间 → 客户端空间）
                 *
                 * 服务器发送的数据包中的 ACK 序列号需要翻译回客户端序列空间
                 * 否则客户端收到的 ACK 序列号不正确，导致 TCP 状态异常
                 */
                /* 重新获取头指针（可能被 skb_ensure_writable 改变） */
                iph = ip_hdr(flush_skb);
                tcph = (struct tcphdr *)((unsigned char *)iph + iph->ihl * 4);

                if (tcph->ack && READ_ONCE(flow->wan_state) != PEP_WAN_CLOSED) {
                    if (pep_translate_ack_wan_to_client(flow, flush_skb) < 0) {
                        pep_warn("GRO timeout flush: ACK translation failed\n");
                    }
                }

                /* Step 5: 投递给客户端 */
                flush_skb->mark = PEP_SKB_MARK;
                if (pep_queue_enqueue(&flow->wan_to_lan, flush_skb) == 0) {
                    pep_schedule_lan_tx(flow);
                } else {
                    netif_receive_skb(flush_skb);
                }
            }
        } else {
            flush_skb->mark = PEP_SKB_MARK;
            if (pep_queue_enqueue(&flow->wan_to_lan, flush_skb) == 0) {
                pep_schedule_lan_tx(flow);
            } else {
                netif_receive_skb(flush_skb);
            }
        }
    }

    atomic_set(&flow->gro_flush_pending, 0);

    /* v87: 死亡流不重启 timer，但数据已经被刷新 */
    if (!queue_empty && !is_dead)
        pep_gro_timer_start(flow);

    pep_flow_put(flow);
}

/*
 * 功能/Main: 定时处理GSO/GRO 分段/合并（Timer task GSO/GRO segmentation/aggregation）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；定时器/工作队列上下文（timer/workqueue context）；并发同步（spinlock/atomic/rcu）；GSO/GRO 分段/合并（GSO/GRO seg/agg）
 * 输入/Inputs: 参数/Inputs: timer
 * 影响/Effects: 周期维护状态，影响稳定性（periodic maintenance, affects stability）
 * 重要程度/Importance: 中/Medium
 */
static enum hrtimer_restart pep_gro_timer_callback(struct hrtimer *timer)
{
    struct pep_flow *flow = container_of(timer, struct pep_flow, gro_timer);
    struct pep_context *ctx;
    unsigned long flags;
    bool has_queue;

    spin_lock_irqsave(&flow->gro_lock, flags);
    flow->gro_timer_active = false;
    has_queue = !skb_queue_empty(&flow->gro_queue);
    spin_unlock_irqrestore(&flow->gro_lock, flags);

    ctx = READ_ONCE(pep_ctx);
    if (!has_queue || !ctx || !ctx->wq || !atomic_read(&ctx->running))
        return HRTIMER_NORESTART;

    if (atomic_cmpxchg(&flow->gro_flush_pending, 0, 1) == 0) {
        if (!refcount_inc_not_zero(&flow->refcnt)) {
            atomic_set(&flow->gro_flush_pending, 0);
            return HRTIMER_NORESTART;
        }
        if (!queue_work(ctx->wq, &flow->gro_flush_work)) {
            atomic_set(&flow->gro_flush_pending, 0);
            pep_flow_put(flow);
        }
    }

    return HRTIMER_NORESTART;
}

/*
 * 功能/Main: 初始化GSO/GRO 分段/合并（Initialize GSO/GRO segmentation/aggregation）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；定时器/工作队列上下文（timer/workqueue context）；GSO/GRO 分段/合并（GSO/GRO seg/agg）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
static void pep_gro_timer_init(struct pep_flow *flow)
{
    hrtimer_init(&flow->gro_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    flow->gro_timer.function = pep_gro_timer_callback;
    flow->gro_timer_active = false;
}

/*
 * 功能/Main: 清理GSO/GRO 分段/合并（Cleanup GSO/GRO segmentation/aggregation）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；定时器/工作队列上下文（timer/workqueue context）；GSO/GRO 分段/合并（GSO/GRO seg/agg）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
static void pep_gro_timer_cleanup(struct pep_flow *flow)
{
    if (flow->gro_timer_active) {
        hrtimer_cancel(&flow->gro_timer);
        flow->gro_timer_active = false;
    }
}

/*
 * 功能/Main: 定时处理GSO/GRO 分段/合并（Timer task GSO/GRO segmentation/aggregation）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 周期维护状态，影响稳定性（periodic maintenance, affects stability）
 * 重要程度/Importance: 中/Medium
 */
void pep_gro_timer_start(struct pep_flow *flow)
{
    unsigned long flags;

    if (!flow)
        return;

    /*
     * v63 修复: 实现 GRO 定时器启动
     *
     * 设计: 定时器作为备份机制，确保 GRO 队列中的包
     *       不会因为没有后续包而无限期等待。
     *       主要刷新仍由 netfilter 内联代码处理。
     *
     * 超时: 使用 PEP_ADV_ACK_TIMEOUT_US (40ms)
     */
    spin_lock_irqsave(&flow->gro_lock, flags);

    if (!flow->gro_timer_active && !skb_queue_empty(&flow->gro_queue)) {
        flow->gro_timer_active = true;
        hrtimer_start(&flow->gro_timer,
                      ktime_set(0, PEP_ADV_ACK_TIMEOUT_US * 1000),
                      HRTIMER_MODE_REL);
    }

    spin_unlock_irqrestore(&flow->gro_lock, flags);
}

/*
 * 功能/Main: 初始化流表/会话状态（Initialize flow/session state）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: table, max_flows, timeout_ms
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
int pep_flow_table_init(struct pep_flow_table *table, u32 max_flows, u32 timeout_ms)
{
    if (!table)
        return -EINVAL;

    hash_init(table->flows);
    raw_spin_lock_init(&table->lock);
    atomic_set(&table->count, 0);
    table->max_flows = max_flows;
    table->timeout_ms = timeout_ms;

    pep_info("Flow table initialized: max=%u, timeout=%ums\n",
             max_flows, timeout_ms);

    return 0;
}

/*
 * 功能/Main: 处理流表/会话状态（Handle flow/session state）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；ACK pacing 调度（ACK pacing scheduling）；定时器/工作队列上下文（timer/workqueue context）；并发同步（spinlock/atomic/rcu）；GSO/GRO 分段/合并（GSO/GRO seg/agg）
 * 输入/Inputs: 参数/Inputs: table
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
void pep_flow_table_cancel_all_timers(struct pep_flow_table *table)
{
    struct pep_flow *flow;
    int bkt;
    int count = 0;

    pr_info("pep: [TIMER_CANCEL] === Cancelling all flow timers START ===\n");

    if (!table) {
        pr_info("pep: [TIMER_CANCEL] table is NULL, returning\n");
        return;
    }

    rcu_read_lock();
    hash_for_each_rcu(table->flows, bkt, flow, hnode) {

        pep_flow_mark_dead(flow);
        count++;
    }
    rcu_read_unlock();

    pr_info("pep: [TIMER_CANCEL] Marked %d flows as DEAD\n", count);

    synchronize_rcu();

    rcu_read_lock();
    hash_for_each_rcu(table->flows, bkt, flow, hnode) {

        if (!refcount_inc_not_zero(&flow->refcnt))
            continue;

        rcu_read_unlock();

        pr_info("pep: [TIMER_CANCEL] Flow %pI4:%u - cancelling timers...\n",
                &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));

        pep_pacing_cleanup(flow);
        pep_tlp_cleanup(flow);
        pep_ack_pacer_cleanup(flow);
        pep_wan_syn_timer_cleanup(flow);
        pep_gro_timer_cleanup(flow);

        cancel_work_sync(&flow->wan_tx_work);
        cancel_work_sync(&flow->lan_tx_work);
        cancel_work_sync(&flow->gro_flush_work);

        pr_info("pep: [TIMER_CANCEL] Flow %pI4:%u - done\n",
                &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));

        pep_flow_put(flow);

        rcu_read_lock();
    }
    rcu_read_unlock();

    pr_info("pep: [TIMER_CANCEL] === Cancelling all flow timers COMPLETE ===\n");
}

/*
 * 功能/Main: 清理流表/会话状态（Cleanup flow/session state）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；ACK pacing 调度（ACK pacing scheduling）；FEC 编码/映射/恢复（FEC encode/map/recover）；学习控制/区域统计（learning/regional stats）；内存池管理（mempool management）
 * 输入/Inputs: 参数/Inputs: table
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_flow_table_exit(struct pep_flow_table *table)
{
    struct pep_flow *flow;
    struct hlist_node *tmp;
    int bkt;
    unsigned long flags;
    int count = 0;
    int wait_count;
    int max_wait = 100;
    LIST_HEAD(destroy_list);
    int pending;

    pr_info("pep: [FLOW_EXIT] === Flow table exit START ===\n");

    if (!table) {
        pr_info("pep: [FLOW_EXIT] table is NULL, returning\n");
        return;
    }

    pr_info("pep: [FLOW_EXIT] Step 1: Marking flows DEAD and removing from hash...\n");
    raw_spin_lock_irqsave(&table->lock, flags);

    hash_for_each_safe(table->flows, bkt, tmp, flow, hnode) {

        pep_flow_mark_dead(flow);
        hash_del_rcu(&flow->hnode);
        atomic_dec(&table->count);
        list_add(&flow->list, &destroy_list);
        count++;
    }

    raw_spin_unlock_irqrestore(&table->lock, flags);
    pr_info("pep: [FLOW_EXIT] Step 1: Done, marked %d flows\n", count);

    if (count == 0) {
        pep_info("Flow table destroyed, no flows\n");
        return;
    }

    pr_info("pep: [FLOW_EXIT] Step 2: synchronize_rcu...\n");
    synchronize_rcu();
    pr_info("pep: [FLOW_EXIT] Step 2: Done\n");

    pr_info("pep: [FLOW_EXIT] Step 3: Processing %d flows in destroy_list...\n", count);
    wait_count = 0;
    pending = count;

    while (!list_empty(&destroy_list) && wait_count < max_wait) {
        struct pep_flow *f, *f_tmp;
        int processed_this_round = 0;

        list_for_each_entry_safe(f, f_tmp, &destroy_list, list) {
            int ref = refcount_read(&f->refcnt);

            if (ref == 1) {

                pr_info("pep: [FLOW_EXIT] Flow %pI4:%u ref=1, cleaning up...\n",
                        &f->tuple.dst_addr, ntohs(f->tuple.dst_port));
                list_del(&f->list);

                pr_info("pep: [FLOW_EXIT]   - pep_pacing_cleanup...\n");
                pep_pacing_cleanup(f);
                pr_info("pep: [FLOW_EXIT]   - pep_tlp_cleanup...\n");
                pep_tlp_cleanup(f);
                pr_info("pep: [FLOW_EXIT]   - pep_ack_pacer_cleanup...\n");
                pep_ack_pacer_cleanup(f);
                pr_info("pep: [FLOW_EXIT]   - pep_wan_syn_timer_cleanup...\n");
                pep_wan_syn_timer_cleanup(f);

                pr_info("pep: [FLOW_EXIT]   - cancel_work_sync wan_tx_work...\n");
                cancel_work_sync(&f->wan_tx_work);
                pr_info("pep: [FLOW_EXIT]   - cancel_work_sync lan_tx_work...\n");
                cancel_work_sync(&f->lan_tx_work);

                pr_info("pep: [FLOW_EXIT]   - pep_flow_put...\n");
                pep_flow_put(f);
                pending--;
                processed_this_round++;
            } else if (ref == 0) {

                pr_info("pep: [FLOW_EXIT] Flow ref=0, removing from list\n");
                list_del(&f->list);
                pending--;
                processed_this_round++;
            } else {

                pr_info("pep: [FLOW_EXIT] Flow %pI4:%u ref=%d, waiting...\n",
                        &f->tuple.dst_addr, ntohs(f->tuple.dst_port), ref);
            }
        }

        if (list_empty(&destroy_list))
            break;

        pr_info("pep: [FLOW_EXIT] Step 3: Round %d done, processed=%d, pending=%d, sleeping 10ms...\n",
                wait_count, processed_this_round, pending);
        msleep(10);
        wait_count++;
    }
    pr_info("pep: [FLOW_EXIT] Step 3: Done, wait_count=%d, pending=%d\n", wait_count, pending);

    if (!list_empty(&destroy_list)) {
        struct pep_flow *f, *f_tmp;
        struct sk_buff *skb;
        int forced = 0;

        pr_info("pep: [FLOW_EXIT] Step 4: Force releasing remaining flows...\n");
        pep_warn("Force releasing flows with pending references\n");

        pr_info("pep: [FLOW_EXIT] Step 4a: Cancelling all timers and work for remaining flows...\n");
        list_for_each_entry_safe(f, f_tmp, &destroy_list, list) {
            int ref = refcount_read(&f->refcnt);
            pep_warn("  Flow %pI4:%u -> %pI4:%u refcnt=%d - cancelling timers/work\n",
                     &f->tuple.src_addr, ntohs(f->tuple.src_port),
                     &f->tuple.dst_addr, ntohs(f->tuple.dst_port),
                     ref);

            pr_info("pep: [FLOW_EXIT]     - pep_pacing_cleanup...\n");
            pep_pacing_cleanup(f);
            pr_info("pep: [FLOW_EXIT]     - pep_tlp_cleanup...\n");
            pep_tlp_cleanup(f);
            pr_info("pep: [FLOW_EXIT]     - pep_ack_pacer_cleanup...\n");
            pep_ack_pacer_cleanup(f);
            pr_info("pep: [FLOW_EXIT]     - pep_wan_syn_timer_cleanup...\n");
            pep_wan_syn_timer_cleanup(f);
            pr_info("pep: [FLOW_EXIT]     - pep_gro_timer_cleanup...\n");
            pep_gro_timer_cleanup(f);

            pr_info("pep: [FLOW_EXIT]     - cancel_work_sync wan_tx_work...\n");
            cancel_work_sync(&f->wan_tx_work);
            pr_info("pep: [FLOW_EXIT]     - cancel_work_sync lan_tx_work...\n");
            cancel_work_sync(&f->lan_tx_work);
            pr_info("pep: [FLOW_EXIT]     - Done\n");
        }

        pr_info("pep: [FLOW_EXIT] Step 4b: synchronize_rcu + rcu_barrier...\n");
        synchronize_rcu();
        rcu_barrier();
        pr_info("pep: [FLOW_EXIT] Step 4b: Done\n");

        pr_info("pep: [FLOW_EXIT] Step 4c: Directly freeing flows...\n");
        list_for_each_entry_safe(f, f_tmp, &destroy_list, list) {
            pr_info("pep: [FLOW_EXIT]   Freeing flow %pI4:%u...\n",
                    &f->tuple.dst_addr, ntohs(f->tuple.dst_port));
            list_del(&f->list);

            if (pep_ctx && pep_ctx->learning.state_cache) {
                pep_learning_remove_state(&pep_ctx->learning, f->hash);
            }

            pep_fec_cleanup(f);

            pep_queue_destroy(&f->lan_to_wan);
            pep_queue_destroy(&f->wan_to_lan);

            while ((skb = skb_dequeue(&f->rtx_queue)) != NULL)
                kfree_skb(skb);

            if (pep_ctx && pep_ctx->mempool.flow_cache) {
                pep_mempool_free_flow(&pep_ctx->mempool, f);
            }

            forced++;
        }

        pep_warn("Forced release of %d flows\n", forced);
        pr_info("pep: [FLOW_EXIT] Step 4: Done, forced=%d\n", forced);
    }

    pr_info("pep: [FLOW_EXIT] Step 5: Final synchronize_rcu + rcu_barrier...\n");
    synchronize_rcu();
    rcu_barrier();
    pr_info("pep: [FLOW_EXIT] Step 5: Done\n");

    pr_info("pep: [FLOW_EXIT] === Flow table exit COMPLETE ===\n");
    pep_info("Flow table destroyed, %d flows released\n", count);
}

/*
 * 功能/Main: 处理流表/会话状态（Handle flow/session state）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: tuple
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
static inline u32 pep_flow_hash(const struct pep_tuple *tuple)
{
    return PEP_TUPLE_HASH(tuple);
}

/*
 * 功能/Main: 处理pep_tuple_equal相关逻辑（Handle pep_tuple_equal logic）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: a, b
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static inline bool pep_tuple_equal(const struct pep_tuple *a,
                                    const struct pep_tuple *b)
{
    return a->src_addr == b->src_addr &&
           a->dst_addr == b->dst_addr &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           a->protocol == b->protocol;
}

/*
 * 功能/Main: 查找流表/会话状态（Find flow/session state）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: table, tuple
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
struct pep_flow *pep_flow_find(struct pep_flow_table *table,
                                const struct pep_tuple *tuple)
{
    struct pep_flow *flow;
    u32 hash;

    if (!table || !tuple)
        return NULL;

    hash = pep_flow_hash(tuple);

    rcu_read_lock();
    hash_for_each_possible_rcu(table->flows, flow, hnode, hash) {
        if (pep_tuple_equal(&flow->tuple, tuple)) {

            if (pep_flow_is_dead(flow)) {
                rcu_read_unlock();
                return NULL;
            }

            if (!refcount_inc_not_zero(&flow->refcnt)) {
                rcu_read_unlock();
                return NULL;
            }

            if (pep_flow_is_dead(flow)) {
                rcu_read_unlock();
                pep_flow_put(flow);
                return NULL;
            }

            rcu_read_unlock();
            return flow;
        }
    }
    rcu_read_unlock();

    return NULL;
}

/*
 * 功能/Main: 查找流表/会话状态（Find flow/session state）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）
 * 输入/Inputs: 参数/Inputs: table, tuple
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
struct pep_flow *pep_flow_find_reverse(struct pep_flow_table *table,
                                        const struct pep_tuple *tuple)
{
    struct pep_tuple reverse;

    reverse.src_addr = tuple->dst_addr;
    reverse.dst_addr = tuple->src_addr;
    reverse.src_port = tuple->dst_port;
    reverse.dst_port = tuple->src_port;
    reverse.protocol = tuple->protocol;

    return pep_flow_find(table, &reverse);
}

/*
 * v94 关键修复: 为序列号翻译查找流（包括 DEAD 流）
 *
 * 功能/Main: 查找流用于序列号翻译（Find flow for SEQ translation）
 * 细节/Details: 允许返回 DEAD 流，因为它们仍有有效的 seq_offset 数据
 *               （Allow returning DEAD flows as they still have valid seq_offset）
 *
 * 问题: 当连接关闭时，DEAD_BIT 被设置，但服务器的在途数据包仍然需要
 *       序列号翻译。如果 pep_flow_find() 返回 NULL，这些包会直接通过
 *       而没有翻译，导致客户端收到错误序列号的包并丢弃它们。
 *
 * 解决: 这个函数在 refcnt > 0 时仍返回 DEAD 流，允许完成序列号翻译
 *       调用者必须在使用后调用 pep_flow_put()
 *
 * 输入/Inputs: table, tuple
 * 影响/Effects: 允许 DEAD 流的序列号翻译，避免并发请求超时
 * 重要程度/Importance: 高/High（修复 ~50% 并发请求超时问题）
 */
struct pep_flow *pep_flow_find_for_translation(struct pep_flow_table *table,
                                                const struct pep_tuple *tuple)
{
    struct pep_flow *flow;
    u32 hash;

    if (!table || !tuple)
        return NULL;

    hash = pep_flow_hash(tuple);

    rcu_read_lock();
    hash_for_each_possible_rcu(table->flows, flow, hnode, hash) {
        if (pep_tuple_equal(&flow->tuple, tuple)) {
            /*
             * v94: 即使是 DEAD 流也尝试获取引用
             * 只要 refcnt > 0，流的 seq_offset 仍然有效
             */
            if (!refcount_inc_not_zero(&flow->refcnt)) {
                rcu_read_unlock();
                return NULL;
            }

            rcu_read_unlock();
            return flow;
        }
    }
    rcu_read_unlock();

    return NULL;
}

/*
 * v94: 反向查找用于序列号翻译（包括 DEAD 流）
 *
 * 功能/Main: 反向查找流用于 WAN→LAN 序列号翻译
 * 细节/Details: 用于服务器→客户端方向的包，即使流已标记为 DEAD
 * 输入/Inputs: table, tuple
 * 影响/Effects: 修复并发请求超时问题
 * 重要程度/Importance: 高/High
 */
struct pep_flow *pep_flow_find_reverse_for_translation(struct pep_flow_table *table,
                                                        const struct pep_tuple *tuple)
{
    struct pep_tuple reverse;

    reverse.src_addr = tuple->dst_addr;
    reverse.dst_addr = tuple->src_addr;
    reverse.src_port = tuple->dst_port;
    reverse.dst_port = tuple->src_port;
    reverse.protocol = tuple->protocol;

    return pep_flow_find_for_translation(table, &reverse);
}

/*
 * 功能/Main: 处理流表/会话状态（Handle flow/session state）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；ACK pacing 调度（ACK pacing scheduling）；FEC 编码/映射/恢复（FEC encode/map/recover）；RTT/RTO 估计（RTT/RTO estimation）
 * 输入/Inputs: 参数/Inputs: table, tuple
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
struct pep_flow *pep_flow_create(struct pep_flow_table *table,
                                  const struct pep_tuple *tuple)
{
    struct pep_flow *flow;
    unsigned long flags;
    struct pep_context *ctx;

    ctx = READ_ONCE(pep_ctx);
    if (!table || !tuple || !ctx)
        return NULL;

    if (atomic_read(&table->count) >= table->max_flows) {
        pep_warn("Flow table full: max=%u\n", table->max_flows);
        return NULL;
    }

    flow = pep_mempool_alloc_flow(&ctx->mempool);
    if (!flow)
        return NULL;

    memcpy(&flow->tuple, tuple, sizeof(struct pep_tuple));
    flow->hash = pep_flow_hash(tuple);
    flow->state = PEP_TCP_CLOSED;
    flow->flags = PEP_FLOW_F_ACTIVE;
    flow->ecn_requested = 0;
    flow->ecn_ece_pending = 0;

    INIT_LIST_HEAD(&flow->list);
    INIT_HLIST_NODE(&flow->hnode);

    memset(&flow->lan, 0, sizeof(flow->lan));
    memset(&flow->wan, 0, sizeof(flow->wan));

    pep_cc_init(&flow->cc, &ctx->config);

    flow->rtt.srtt = 0;
    flow->rtt.rttvar = 0;
    flow->rtt.rto = ctx->config.rto_init_ms;
    flow->rtt.min_rtt = UINT_MAX;
    flow->rtt.max_rtt = 0;
    flow->rtt.last_sample = ktime_get();
    flow->rtt.samples = 0;

    if (ctx->config.queue_bdp_enabled) {
        pep_queue_init_bdp(&flow->lan_to_wan,
                           ctx->config.lan_wan_queue_min * 1500,
                           ctx->config.lan_wan_queue_max * 1500,
                           ctx->config.queue_bdp_multiplier,
                           ctx->config.queue_max_absolute);
        pep_queue_init_bdp(&flow->wan_to_lan,
                           ctx->config.wan_lan_queue_min * 1500,
                           ctx->config.wan_lan_queue_max * 1500,
                           ctx->config.queue_bdp_multiplier,
                           ctx->config.queue_max_absolute);
    } else {
        pep_queue_init(&flow->lan_to_wan,
                       ctx->config.lan_wan_queue_min * 1500,
                       ctx->config.lan_wan_queue_max * 1500);
        pep_queue_init(&flow->wan_to_lan,
                       ctx->config.wan_lan_queue_min * 1500,
                       ctx->config.wan_lan_queue_max * 1500);
    }

    skb_queue_head_init(&flow->rtx_queue);
    spin_lock_init(&flow->rtx_lock);
    flow->rtx_bytes = 0;

    pep_lan_retrans_init(flow, ctx->config.local_retrans_max_pkts,
                         ctx->config.local_retrans_max_bytes,
                         ctx->config.local_retrans);
    pep_byte_cache_flow_init(flow);

    pep_rack_init(flow);
    pep_tlp_init(flow);

    pep_pacing_init(flow);

    pep_fec_init(flow);

    flow->wan_snd_nxt = 0;
    flow->wan_snd_una = 0;
    INIT_WORK(&flow->wan_tx_work, pep_wan_tx_work_handler);
    atomic_set(&flow->wan_tx_pending, 0);

    flow->lan_snd_nxt = 0;
    flow->lan_snd_una = 0;
    INIT_WORK(&flow->lan_tx_work, pep_lan_tx_work_handler);
    atomic_set(&flow->lan_tx_pending, 0);

    pep_ack_pacer_init(flow);
    pep_adv_ack_init(flow);

    pep_reseq_init(flow, ctx->config.reseq_max_packets,
                   ctx->config.reseq_enabled);

    pep_reorder_init(flow, ctx->config.downlink_reorder_max,
                     ctx->config.downlink_reorder_enabled);

    __skb_queue_head_init(&flow->gro_queue);
    spin_lock_init(&flow->gro_lock);
    flow->gro_max_size = PEP_GRO_MAX_SIZE;
    flow->gro_last_flush = ktime_get();
    flow->gro_pkts_aggregated = 0;
    flow->gro_bytes_aggregated = 0;
    pep_gro_timer_init(flow);
    INIT_WORK(&flow->gro_flush_work, pep_gro_flush_work_handler);
    atomic_set(&flow->gro_flush_pending, 0);

    __skb_queue_head_init(&flow->rsc_queue);
    spin_lock_init(&flow->rsc_lock);
    flow->rsc_max_size = ctx->config.rsc_max_size ? ctx->config.rsc_max_size :
                         PEP_DEFAULT_RSC_MAX_SIZE;
    flow->rsc_timeout_us = ctx->config.rsc_timeout_us ? ctx->config.rsc_timeout_us :
                           PEP_DEFAULT_RSC_TIMEOUT_US;
    flow->rsc_last_flush = ktime_get();
    flow->rsc_pkts_aggregated = 0;
    flow->rsc_bytes_aggregated = 0;
    flow->rsc_enabled = ctx->config.rsc_enabled ? 1 : 0;

    flow->isn_client = 0;
    flow->isn_pep_wan = 0;
    flow->c2w_seq_offset = 0;
    pep_wan_syn_timer_init(flow);

    pep_flow_init_from_region(flow);

    flow->rx_packets = 0;
    flow->rx_bytes = 0;
    flow->tx_packets = 0;
    flow->tx_bytes = 0;
    flow->retrans_packets = 0;
    flow->fake_acks_sent = 0;

    flow->create_time = ktime_get();
    flow->last_activity = flow->create_time;
    flow->last_rtx_time = flow->create_time;

    flow->rtt_probe_enabled = ctx->config.rtt_probe_enabled ? 1 : 0;
    flow->rtt_probe_pending = 0;
    flow->rtt_probe_ack_seq = 0;
    flow->rtt_probe_sent_time = ktime_set(0, 0);
    flow->rtt_probe_last_time = ktime_set(0, 0);

    INIT_LIST_HEAD(&flow->sched_node_wan);
    INIT_LIST_HEAD(&flow->sched_node_lan);
    flow->sched_prio = PEP_SCHED_PRIO_NORMAL;
    flow->sched_queued_wan = 0;
    flow->sched_queued_lan = 0;
    flow->engine_id = (ctx->engine_num > 0) ? (flow->hash % ctx->engine_num) : 0;

    refcount_set(&flow->refcnt, 2);
    spin_lock_init(&flow->lock);

    flow->cpu = raw_smp_processor_id();

    raw_spin_lock_irqsave(&table->lock, flags);
    hash_add_rcu(table->flows, &flow->hnode, flow->hash);
    atomic_inc(&table->count);
    raw_spin_unlock_irqrestore(&table->lock, flags);

    atomic64_inc(&ctx->stats.flow_creates);
    atomic64_inc(&ctx->stats.active_flows);

    pep_region_flow_start(flow);

    pep_dbg("Flow created: %pI4:%u -> %pI4:%u\n",
            &tuple->src_addr, ntohs(tuple->src_port),
            &tuple->dst_addr, ntohs(tuple->dst_port));

    return flow;
}

/*
 * 功能/Main: 释放流表/会话状态（Free flow/session state）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；FEC 编码/映射/恢复（FEC encode/map/recover）；学习控制/区域统计（learning/regional stats）；字节缓存读写（byte cache access）
 * 输入/Inputs: 参数/Inputs: rcu
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
static void pep_flow_free_rcu(struct rcu_head *rcu)
{
    struct pep_flow *flow = container_of(rcu, struct pep_flow, rcu);
    struct pep_context *ctx;
    struct sk_buff *skb;

    ctx = READ_ONCE(pep_ctx);

    pep_region_flow_end(flow);

    if (ctx && ctx->learning.state_cache) {
        pep_learning_remove_state(&ctx->learning, flow->hash);
    }

    pep_fec_cleanup(flow);

    pep_queue_destroy(&flow->lan_to_wan);
    pep_queue_destroy(&flow->wan_to_lan);
    pep_reseq_cleanup(flow);
    pep_reorder_cleanup(flow);
    /* v109: removed duplicate cleanup calls */
    pep_lan_retrans_cleanup(flow);
    pep_byte_cache_flow_cleanup(flow);

    while ((skb = skb_dequeue(&flow->rtx_queue)) != NULL)
        kfree_skb(skb);

    pep_gro_timer_cleanup(flow);

    spin_lock(&flow->gro_lock);
    while ((skb = __skb_dequeue(&flow->gro_queue)) != NULL) {
        spin_unlock(&flow->gro_lock);
        kfree_skb(skb);
        spin_lock(&flow->gro_lock);
    }
    spin_unlock(&flow->gro_lock);

    spin_lock(&flow->rsc_lock);
    while ((skb = __skb_dequeue(&flow->rsc_queue)) != NULL) {
        spin_unlock(&flow->rsc_lock);
        kfree_skb(skb);
        spin_lock(&flow->rsc_lock);
    }
    spin_unlock(&flow->rsc_lock);

    ctx = READ_ONCE(pep_ctx);
    if (ctx && ctx->mempool.flow_cache) {
        pep_mempool_free_flow(&ctx->mempool, flow);
    }
}

/*
 * 功能/Main: 销毁流表/会话状态（Destroy flow/session state）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；ACK pacing 调度（ACK pacing scheduling）；FEC 编码/映射/恢复（FEC encode/map/recover）；学习控制/区域统计（learning/regional stats）；内存池管理（mempool management）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
void pep_flow_destroy(struct pep_flow *flow)
{
    struct pep_context *ctx;
    struct sk_buff *skb;

    if (!flow)
        return;

    ctx = READ_ONCE(pep_ctx);

    pep_pacing_cleanup(flow);
    pep_tlp_cleanup(flow);
    pep_ack_pacer_cleanup(flow);
    pep_adv_ack_cleanup(flow);
    pep_wan_syn_timer_cleanup(flow);

    cancel_work_sync(&flow->wan_tx_work);
    cancel_work_sync(&flow->lan_tx_work);
    cancel_work_sync(&flow->gro_flush_work);

    if (ctx && ctx->learning.state_cache) {
        pep_learning_remove_state(&ctx->learning, flow->hash);
    }

    pep_fec_cleanup(flow);

    pep_queue_destroy(&flow->lan_to_wan);
    pep_queue_destroy(&flow->wan_to_lan);
    pep_reseq_cleanup(flow);
    pep_reorder_cleanup(flow);

    while ((skb = skb_dequeue(&flow->rtx_queue)) != NULL)
        kfree_skb(skb);

    pep_gro_timer_cleanup(flow);

    spin_lock(&flow->gro_lock);
    while ((skb = __skb_dequeue(&flow->gro_queue)) != NULL) {
        spin_unlock(&flow->gro_lock);
        kfree_skb(skb);
        spin_lock(&flow->gro_lock);
    }
    spin_unlock(&flow->gro_lock);

    spin_lock(&flow->rsc_lock);
    while ((skb = __skb_dequeue(&flow->rsc_queue)) != NULL) {
        spin_unlock(&flow->rsc_lock);
        kfree_skb(skb);
        spin_lock(&flow->rsc_lock);
    }
    spin_unlock(&flow->rsc_lock);

    if (ctx && ctx->mempool.flow_cache) {
        pep_mempool_free_flow(&ctx->mempool, flow);
    }
}

/*
 * 功能/Main: 获取流表/会话状态（Get flow/session state）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
void pep_flow_get(struct pep_flow *flow)
{
    if (flow)
        refcount_inc(&flow->refcnt);
}

/*
 * 功能/Main: 处理流表/会话状态（Handle flow/session state）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
void pep_flow_put(struct pep_flow *flow)
{
    struct pep_context *ctx;

    if (!flow)
        return;

    if (refcount_dec_and_test(&flow->refcnt)) {
        ctx = READ_ONCE(pep_ctx);
        if (ctx) {
            atomic64_inc(&ctx->stats.flow_destroys);
            atomic64_dec(&ctx->stats.active_flows);
        }

        pep_dbg("Flow released: %pI4:%u -> %pI4:%u\n",
                &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
                &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));

        call_rcu(&flow->rcu, pep_flow_free_rcu);
    }
}

/*
 * 功能/Main: 更新流表/会话状态（Update flow/session state）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 高/High
 */
void pep_flow_update_activity(struct pep_flow *flow)
{
    if (!flow)
        return;

    /*
     * v74: 不更新 closing 状态流的 last_activity
     *
     * 问题: FIN_WAIT_2 状态的流仍然接收 WAN 数据包,
     *       每个包都更新 last_activity，导致 10 秒超时永远不触发
     *
     * 解决: 对 closing 状态的流不更新 activity，让超时机制正常工作
     */
    if (flow->state >= PEP_TCP_FIN_WAIT_1 &&
        flow->state <= PEP_TCP_TIME_WAIT)
        return;

    WRITE_ONCE(flow->last_activity, ktime_get());
}

/*
 * 功能/Main: 处理流表/会话状态（Handle flow/session state）
 * 细节/Details: 统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: state
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
const char *pep_flow_state_str(enum pep_tcp_state state)
{
    static const char *state_names[] = {
        [PEP_TCP_CLOSED]     = "CLOSED",
        [PEP_TCP_LISTEN]     = "LISTEN",
        [PEP_TCP_SYN_SENT]   = "SYN_SENT",
        [PEP_TCP_SYN_RECV]   = "SYN_RECV",
        [PEP_TCP_ESTABLISHED] = "ESTABLISHED",
        [PEP_TCP_FIN_WAIT_1] = "FIN_WAIT_1",
        [PEP_TCP_FIN_WAIT_2] = "FIN_WAIT_2",
        [PEP_TCP_CLOSE_WAIT] = "CLOSE_WAIT",
        [PEP_TCP_CLOSING]    = "CLOSING",
        [PEP_TCP_LAST_ACK]   = "LAST_ACK",
        [PEP_TCP_TIME_WAIT]  = "TIME_WAIT",
    };

    if (state >= PEP_TCP_STATE_MAX)
        return "UNKNOWN";

    return state_names[state];
}
