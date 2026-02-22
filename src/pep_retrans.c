/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"

extern struct pep_context *pep_ctx;

/*
 * 功能/Main: 处理pep_skb_cb相关逻辑（Handle pep_skb_cb logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）
 * 输入/Inputs: 参数/Inputs: skb
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static inline struct pep_skb_cb *pep_skb_cb(struct sk_buff *skb)
{
    BUILD_BUG_ON(sizeof(struct pep_skb_cb) > sizeof(skb->cb));
    return (struct pep_skb_cb *)skb->cb;
}

/*
 * 功能/Main: 处理重传/缓存（Handle retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: skb, acked_portion, new_seq
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static bool pep_retrans_trim_partial_skb(struct sk_buff *skb,
                                          u32 acked_portion,
                                          u32 new_seq)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len, tcp_hdr_len;
    unsigned int old_payload_len, new_payload_len;
    u32 old_seq;

    if (!skb || acked_portion == 0)
        return false;

    if (skb_ensure_writable(skb, skb->len)) {
        pep_warn("Partial ACK trim: skb_ensure_writable failed\n");
        return false;
    }

    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
    tcp_hdr_len = tcph->doff * 4;

    old_payload_len = ntohs(iph->tot_len) - ip_hdr_len - tcp_hdr_len;

    if (acked_portion > old_payload_len) {
        pep_warn("Partial ACK trim: acked_portion(%u) > payload(%u)\n",
                 acked_portion, old_payload_len);
        return false;
    }

    new_payload_len = old_payload_len - acked_portion;

    old_seq = ntohl(tcph->seq);

    {
        unsigned char *payload_start = (unsigned char *)tcph + tcp_hdr_len;
        unsigned char *new_payload_start = payload_start + acked_portion;

        if (new_payload_len > 0) {
            memmove(payload_start, new_payload_start, new_payload_len);
        }

        skb_trim(skb, ip_hdr_len + tcp_hdr_len + new_payload_len);
    }

    tcph->seq = htonl(new_seq);

    iph->tot_len = htons(ip_hdr_len + tcp_hdr_len + new_payload_len);

    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

    {
        unsigned int tcp_len = tcp_hdr_len + new_payload_len;
        tcph->check = 0;
        tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                        tcp_len, IPPROTO_TCP,
                                        csum_partial(tcph, tcp_len, 0));
    }

    pep_dbg("Partial ACK trim: seq %u->%u, payload %u->%u bytes\n",
            old_seq, new_seq, old_payload_len, new_payload_len);

    return true;
}

/*
 * 功能/Main: 初始化重传/缓存（Initialize retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
void pep_retrans_init(struct pep_flow *flow)
{
    if (!flow)
        return;

    skb_queue_head_init(&flow->rtx_queue);
    spin_lock_init(&flow->rtx_lock);
    flow->rtx_bytes = 0;
    flow->last_rtx_time = ktime_get();

    pep_dbg("Retrans: initialized for flow %pI4:%u -> %pI4:%u\n",
            &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
            &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));
}

/*
 * 功能/Main: 处理重传/缓存（Handle retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；并发同步（spinlock/atomic/rcu）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, skb, seq, len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
int pep_retrans_queue_skb(struct pep_flow *flow, struct sk_buff *skb,
                           u32 seq, u32 len)
{
    struct sk_buff *clone;
    struct pep_skb_cb *cb;
    unsigned long flags;

    if (!flow || !skb || len == 0)
        return -EINVAL;

    clone = skb_copy(skb, GFP_ATOMIC);
    if (!clone) {
        pep_warn("Retrans: failed to clone skb seq=%u len=%u\n", seq, len);
        return -ENOMEM;
    }

    cb = pep_skb_cb(clone);
    cb->tx_time = ktime_get();
    cb->seq = seq;
    cb->len = len;
    cb->retrans_count = 0;

    spin_lock_irqsave(&flow->rtx_lock, flags);
    __skb_queue_tail(&flow->rtx_queue, clone);
    flow->rtx_bytes += len;
    flow->cc.bytes_in_flight += len;
    spin_unlock_irqrestore(&flow->rtx_lock, flags);

    if (pep_ctx && pep_ctx->config.debug_level >= 3) {
        pr_info_ratelimited("pep: RTX ENQUEUE port=%u: seq=[%u,%u) len=%u, rtx_bytes=%u, in_flight=%u, queue_len=%u\n",
                ntohs(flow->tuple.src_port),
                seq, seq + len, len, flow->rtx_bytes, flow->cc.bytes_in_flight,
                skb_queue_len(&flow->rtx_queue));
    }

    return 0;
}

/*
 * 功能/Main: 处理重传/缓存（Handle retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；RTT/RTO 估计（RTT/RTO estimation）；并发同步（spinlock/atomic/rcu）；proc 接口读写（/proc IO）
 * 输入/Inputs: 参数/Inputs: flow, ack_seq
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
u32 pep_retrans_ack_received(struct pep_flow *flow, u32 ack_seq)
{
    struct sk_buff *skb, *tmp;
    struct pep_skb_cb *cb;
    unsigned long flags;
    u32 acked_bytes = 0;
    u32 rtt_sample = 0;
    ktime_t now = ktime_get();
    u32 rtx_queue_len;
    u32 first_seq = 0, first_end = 0;
    bool found_first = false;

    ktime_t rack_xmit_time = ns_to_ktime(0);
    u32 rack_end_seq = 0;
    bool rack_updated = false;

    if (!flow)
        return 0;

    spin_lock_irqsave(&flow->rtx_lock, flags);

    rtx_queue_len = skb_queue_len(&flow->rtx_queue);

    skb = skb_peek(&flow->rtx_queue);
    if (skb) {
        cb = pep_skb_cb(skb);
        first_seq = cb->seq;
        first_end = cb->seq + cb->len;
        found_first = true;

        if (PEP_SEQ_AFTER(first_seq, ack_seq)) {

            u32 gap = first_seq - ack_seq;
            if (pep_ctx && pep_ctx->config.debug_level >= 3) {
                pr_info_ratelimited("pep: RTX ACK GAP port=%u state=%d: ack=%u < first=%u, gap=%u, isn_wan=%u\n",
                        ntohs(flow->tuple.src_port), flow->state,
                        ack_seq, first_seq, gap, flow->isn_pep_wan);
            }
        }
    }

    skb_queue_walk_safe(&flow->rtx_queue, skb, tmp) {
        cb = pep_skb_cb(skb);

        if (PEP_SEQ_LEQ(cb->seq + cb->len, ack_seq)) {

            __skb_unlink(skb, &flow->rtx_queue);

            if (cb->retrans_count == 0 && rtt_sample == 0) {
                rtt_sample = ktime_to_us(ktime_sub(now, cb->tx_time));
            }

            if (ktime_after(cb->tx_time, rack_xmit_time)) {
                rack_xmit_time = cb->tx_time;
                rack_end_seq = cb->seq + cb->len;
                rack_updated = true;
            }

            acked_bytes += cb->len;

            if (flow->rtx_bytes >= cb->len)
                flow->rtx_bytes -= cb->len;
            else
                flow->rtx_bytes = 0;
            if (flow->cc.bytes_in_flight >= cb->len)
                flow->cc.bytes_in_flight -= cb->len;
            else
                flow->cc.bytes_in_flight = 0;

            kfree_skb(skb);
        } else if (PEP_SEQ_AFTER(cb->seq, ack_seq)) {

            break;
        } else if (PEP_SEQ_AFTER(ack_seq, cb->seq) && PEP_SEQ_BEFORE(ack_seq, cb->seq + cb->len)) {

            u32 acked_portion = ack_seq - cb->seq;

            pep_dbg("RTX Partial ACK: seg=[%u,%u) ack=%u, acked_portion=%u, remaining=%u\n",
                    cb->seq, cb->seq + cb->len, ack_seq, acked_portion, cb->len - acked_portion);

            acked_bytes += acked_portion;

            if (flow->rtx_bytes >= acked_portion)
                flow->rtx_bytes -= acked_portion;
            else
                flow->rtx_bytes = 0;
            if (flow->cc.bytes_in_flight >= acked_portion)
                flow->cc.bytes_in_flight -= acked_portion;
            else
                flow->cc.bytes_in_flight = 0;

            cb->seq = ack_seq;
            cb->len -= acked_portion;

            if (!pep_retrans_trim_partial_skb(skb, acked_portion, ack_seq)) {
                pep_warn("Partial ACK: failed to trim skb seq=%u acked=%u\n",
                         ack_seq, acked_portion);

                __skb_unlink(skb, &flow->rtx_queue);
                kfree_skb(skb);
                continue;
            }

            if (cb->retrans_count == 0 && rtt_sample == 0) {
                rtt_sample = ktime_to_us(ktime_sub(now, cb->tx_time));
            }

            if (ktime_after(cb->tx_time, rack_xmit_time)) {
                rack_xmit_time = cb->tx_time;
                rack_end_seq = ack_seq;
                rack_updated = true;
            }

        }

    }

    spin_unlock_irqrestore(&flow->rtx_lock, flags);

    if (rtt_sample > 0) {
        pep_rtt_update(&flow->rtt, rtt_sample);
    }

    if (rack_updated && rtt_sample > 0) {
        pep_rack_update(flow, rack_end_seq, rack_xmit_time, rtt_sample);
    }

    if (acked_bytes > 0) {
        pep_cc_flow_update(flow, acked_bytes, rtt_sample, false);

        pep_dbg("Retrans ACK processed: ack_seq=%u acked=%u bytes, "
                "rtt=%u us, in_flight=%u, rtx_queue_len=%u\n",
                ack_seq, acked_bytes, rtt_sample,
                flow->cc.bytes_in_flight, skb_queue_len(&flow->rtx_queue));
    } else if (found_first && rtx_queue_len > 0) {

        if (ack_seq > first_seq) {
            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                pr_info_ratelimited("pep: RTX ACK NO MATCH port=%u: ack_seq=%u > first_pkt=[%u,%u), "
                        "queue_len=%u, in_flight=%u\n",
                        ntohs(flow->tuple.src_port),
                        ack_seq, first_seq, first_end,
                        rtx_queue_len, flow->cc.bytes_in_flight);
            }
        } else if (ack_seq == first_seq && pep_ctx && pep_ctx->config.debug_level >= 3) {

            pep_dbg("RTX handshake ACK port=%u: ack_seq=%u == first_seq=%u (normal)\n",
                    ntohs(flow->tuple.src_port), ack_seq, first_seq);
        }
    }

    return acked_bytes;
}

/*
 * 功能/Main: 处理重传/缓存（Handle retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；RTT/RTO 估计（RTT/RTO estimation）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
int pep_retrans_timeout(struct pep_flow *flow)
{
    struct sk_buff *skb, *clone;
    struct pep_skb_cb *cb;
    unsigned long flags;
    ktime_t now = ktime_get();
    u32 rto_us;

    if (!flow)
        return -1;

    spin_lock_irqsave(&flow->rtx_lock, flags);

    skb = skb_peek(&flow->rtx_queue);
    if (!skb) {
        spin_unlock_irqrestore(&flow->rtx_lock, flags);
        return -1;
    }

    cb = pep_skb_cb(skb);
    rto_us = flow->rtt.rto * 1000;

    if (ktime_to_us(ktime_sub(now, cb->tx_time)) < rto_us) {
        spin_unlock_irqrestore(&flow->rtx_lock, flags);
        return -1;
    }

    if (cb->retrans_count >= pep_ctx->config.max_retrans) {
        pep_warn("Retrans: max retries (%d) reached for seq=%u\n",
                 cb->retrans_count, cb->seq);

        pep_flow_mark_dead(flow);
        spin_unlock_irqrestore(&flow->rtx_lock, flags);
        return -1;
    }

    clone = skb_copy(skb, GFP_ATOMIC);
    if (!clone) {
        spin_unlock_irqrestore(&flow->rtx_lock, flags);
        return -1;
    }

    cb->retrans_count++;
    cb->tx_time = now;

    spin_unlock_irqrestore(&flow->rtx_lock, flags);

    pep_cc_on_loss(flow);

    flow->retrans_packets++;

    pep_dbg("Retrans: retransmitting seq=%u len=%u, attempt=%d\n",
            cb->seq, cb->len, cb->retrans_count);

    if (pep_send_wan_skb(clone) == 0) {
        pep_stats_inc_retrans();
        pep_dbg("Retrans: sent seq=%u len=%u attempt=%d\n",
                cb->seq, cb->len, cb->retrans_count);
    } else {
        pep_warn("Retrans: failed to send seq=%u\n", cb->seq);
    }

    return 0;
}

/*
 * 功能/Main: 获取重传/缓存（Get retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；RTT/RTO 估计（RTT/RTO estimation）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
u32 pep_retrans_get_next_timeout(struct pep_flow *flow)
{
    struct sk_buff *skb;
    struct pep_skb_cb *cb;
    unsigned long flags;
    ktime_t now;
    s64 elapsed_us, rto_us, remaining_us;

    if (!flow)
        return 0;

    spin_lock_irqsave(&flow->rtx_lock, flags);

    skb = skb_peek(&flow->rtx_queue);
    if (!skb) {
        spin_unlock_irqrestore(&flow->rtx_lock, flags);
        return 0;
    }

    cb = pep_skb_cb(skb);
    now = ktime_get();
    elapsed_us = ktime_to_us(ktime_sub(now, cb->tx_time));
    rto_us = flow->rtt.rto * 1000;

    spin_unlock_irqrestore(&flow->rtx_lock, flags);

    remaining_us = rto_us - elapsed_us;
    if (remaining_us <= 0)
        return 1;

    return max(1U, (u32)(remaining_us / 1000));
}

/*
 * 功能/Main: 处理重传/缓存（Handle retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；FEC 编码/映射/恢复（FEC encode/map/recover）；RTT/RTO 估计（RTT/RTO estimation）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
int pep_retrans_check_timeouts(struct pep_flow *flow)
{
    struct sk_buff *skb;
    struct sk_buff *clone;
    struct pep_skb_cb *cb;
    unsigned long flags;
    ktime_t now = ktime_get();
    u32 base_rto_us;
    u32 effective_rto_us;
    int retrans_count = 0;
    struct sk_buff_head send_list;
    s64 elapsed_us;

    if (!flow || pep_flow_is_dead(flow))
        return 0;

    base_rto_us = flow->rtt.rto * 1000;

    __skb_queue_head_init(&send_list);

    spin_lock_irqsave(&flow->rtx_lock, flags);

    skb_queue_walk(&flow->rtx_queue, skb) {
        cb = pep_skb_cb(skb);
        elapsed_us = ktime_to_us(ktime_sub(now, cb->tx_time));

        effective_rto_us = base_rto_us << cb->retrans_count;

        if (effective_rto_us > pep_ctx->config.rto_max_ms * 1000)
            effective_rto_us = pep_ctx->config.rto_max_ms * 1000;

        if (elapsed_us >= effective_rto_us) {

            if (cb->retrans_count < pep_ctx->config.max_retrans) {

                clone = skb_copy(skb, GFP_ATOMIC);
                if (clone) {

                    __skb_queue_tail(&send_list, clone);

                    cb->retrans_count++;
                    cb->tx_time = now;
                    retrans_count++;

                    pep_dbg("Retrans timeout: seq=%u len=%u attempt=%d/%d "
                            "elapsed=%lld us, rto=%u us (next_rto=%u us)\n",
                            cb->seq, cb->len, cb->retrans_count,
                            pep_ctx->config.max_retrans,
                            elapsed_us, effective_rto_us,
                            min(effective_rto_us * 2, pep_ctx->config.rto_max_ms * 1000));
                }
            } else {
                pr_warn("pep: CRITICAL: max retries (%d) reached for seq=%u, "
                        "marking flow DEAD! port=%u, in_flight=%u\n",
                        cb->retrans_count, cb->seq,
                        ntohs(flow->tuple.src_port),
                        flow->cc.bytes_in_flight);

                pep_flow_mark_dead(flow);
                break;
            }
        }
    }

    spin_unlock_irqrestore(&flow->rtx_lock, flags);

    while ((skb = __skb_dequeue(&send_list)) != NULL) {

        if (pep_flow_is_dead(flow)) {
            kfree_skb(skb);

            while ((skb = __skb_dequeue(&send_list)) != NULL)
                kfree_skb(skb);
            break;
        }
        if (pep_send_wan_skb(skb) == 0) {
            pep_stats_inc_retrans();
        }
    }

    if (retrans_count > 0) {

        pep_cc_on_loss(flow);
        flow->retrans_packets += retrans_count;

        pep_dbg("Retrans check: sent %d retransmissions for flow %pI4:%u, "
                "in_flight=%u, cwnd=%u\n",
                retrans_count, &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port),
                flow->cc.bytes_in_flight, flow->cc.cwnd);
    }

    return retrans_count;
}

/*
 * 功能/Main: 清理重传/缓存（Cleanup retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_retrans_cleanup(struct pep_flow *flow)
{
    struct sk_buff *skb;
    struct sk_buff_head tmp_list;
    unsigned long flags;
    u32 count = 0;

    if (!flow)
        return;

    /* v109: collect skbs under lock, free outside to avoid
     * kfree_skb in spinlock context (potential deadlock) */
    __skb_queue_head_init(&tmp_list);

    spin_lock_irqsave(&flow->rtx_lock, flags);

    while ((skb = __skb_dequeue(&flow->rtx_queue)) != NULL) {
        __skb_queue_tail(&tmp_list, skb);
        count++;
    }

    flow->rtx_bytes = 0;
    flow->cc.bytes_in_flight = 0;

    spin_unlock_irqrestore(&flow->rtx_lock, flags);

    while ((skb = __skb_dequeue(&tmp_list)) != NULL)
        kfree_skb(skb);

    if (count > 0) {
        pep_dbg("Retrans: cleanup, freed %u packets\n", count);
    }
}

/*
 * 功能/Main: 获取重传/缓存（Get retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow, queued_bytes, queued_packets
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_retrans_get_stats(struct pep_flow *flow, u32 *queued_bytes,
                            u32 *queued_packets)
{
    unsigned long flags;

    if (!flow) {
        if (queued_bytes) *queued_bytes = 0;
        if (queued_packets) *queued_packets = 0;
        return;
    }

    spin_lock_irqsave(&flow->rtx_lock, flags);

    if (queued_bytes)
        *queued_bytes = flow->rtx_bytes;
    if (queued_packets)
        *queued_packets = skb_queue_len(&flow->rtx_queue);

    spin_unlock_irqrestore(&flow->rtx_lock, flags);
}

/*
 * 功能/Main: 初始化pep_rack_init相关逻辑（Initialize pep_rack_init logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；RTT/RTO 估计（RTT/RTO estimation）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
void pep_rack_init(struct pep_flow *flow)
{
    struct pep_rack_state *rack;

    if (!flow)
        return;

    rack = &flow->rack;
    memset(rack, 0, sizeof(*rack));

    rack->xmit_time = ns_to_ktime(0);
    rack->end_seq = 0;
    rack->rtt_us = 0;
    rack->min_rtt_us = UINT_MAX;
    rack->reord_wnd_us = 0;
    rack->advanced = 0;
    rack->fack_enabled = 1;
}

/*
 * 功能/Main: 更新pep_rack_update相关逻辑（Update pep_rack_update logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；FEC 编码/映射/恢复（FEC encode/map/recover）；RTT/RTO 估计（RTT/RTO estimation）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, acked_seq, xmit_time, rtt_us
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 中/Medium
 */
void pep_rack_update(struct pep_flow *flow, u32 acked_seq, ktime_t xmit_time, u32 rtt_us)
{
    struct pep_rack_state *rack;

    if (!flow)
        return;

    rack = &flow->rack;

    if (ktime_after(xmit_time, rack->xmit_time)) {
        rack->xmit_time = xmit_time;
        rack->end_seq = acked_seq;
        rack->advanced = 1;

        pep_dbg("RACK: updated xmit_time, acked_seq=%u, rtt=%u us\n",
                acked_seq, rtt_us);
    }

    if (rtt_us > 0) {
        u32 effective_rtt_us = rtt_us;

        if (pep_ctx && rtt_us < PEP_WAN_RTT_MIN_THRESHOLD_US &&
            pep_ctx->config.wan_rtt_ms > 0) {
            effective_rtt_us = pep_ctx->config.wan_rtt_ms * 1000;
            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                pr_info_ratelimited("pep: RACK using fallback WAN RTT: "
                                    "measured=%u us, using=%u us\n",
                                    rtt_us, effective_rtt_us);
            }
        }

        rack->rtt_us = effective_rtt_us;

        if (effective_rtt_us < rack->min_rtt_us)
            rack->min_rtt_us = effective_rtt_us;

        rack->reord_wnd_us = rack->min_rtt_us / 4;
        if (rack->reord_wnd_us < 1000)
            rack->reord_wnd_us = 1000;
    }
}

/*
 * 功能/Main: 处理pep_rack_detect_loss相关逻辑（Handle pep_rack_detect_loss logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
int pep_rack_detect_loss(struct pep_flow *flow)
{
    struct pep_rack_state *rack;
    struct sk_buff *skb, *clone;
    struct pep_skb_cb *cb;
    unsigned long flags;
    ktime_t loss_threshold;
    int lost_count = 0;
    struct sk_buff_head send_list;

    if (!flow)
        return 0;

    rack = &flow->rack;

    if (!rack->advanced || ktime_to_ns(rack->xmit_time) == 0)
        return 0;

    loss_threshold = ktime_sub_us(rack->xmit_time, rack->reord_wnd_us);

    __skb_queue_head_init(&send_list);

    spin_lock_irqsave(&flow->rtx_lock, flags);

    skb_queue_walk(&flow->rtx_queue, skb) {
        cb = pep_skb_cb(skb);

        if (ktime_before(cb->tx_time, loss_threshold)) {

            if (cb->retrans_count >= pep_ctx->config.max_retrans) {
                pep_warn("RACK: max retries reached for seq=%u\n", cb->seq);

                pep_flow_mark_dead(flow);
                break;
            }

            clone = skb_copy(skb, GFP_ATOMIC);
            if (clone) {
                __skb_queue_tail(&send_list, clone);
                cb->retrans_count++;
                cb->tx_time = ktime_get();
                lost_count++;
                rack->lost += cb->len;

                pep_dbg("RACK: detected loss seq=%u len=%u, delta=%lld us\n",
                        cb->seq, cb->len,
                        ktime_to_us(ktime_sub(rack->xmit_time, cb->tx_time)));
            }
        } else {

            break;
        }
    }

    spin_unlock_irqrestore(&flow->rtx_lock, flags);

    while ((skb = __skb_dequeue(&send_list)) != NULL) {

        if (pep_flow_is_dead(flow)) {
            kfree_skb(skb);

            while ((skb = __skb_dequeue(&send_list)) != NULL)
                kfree_skb(skb);
            break;
        }
        if (pep_send_wan_skb(skb) == 0) {
            pep_stats_inc_retrans();
        }
    }

    if (lost_count > 0) {
        pep_cc_on_loss(flow);
        flow->retrans_packets += lost_count;

        pep_dbg("RACK detected %d lost packets, retransmitting\n", lost_count);
    }

    rack->advanced = 0;

    return lost_count;
}

/*
 * 功能/Main: 处理pep_rack_mark_lost相关逻辑（Handle pep_rack_mark_lost logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）
 * 输入/Inputs: 参数/Inputs: flow, seq, len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_rack_mark_lost(struct pep_flow *flow, u32 seq, u32 len)
{
    if (!flow)
        return;

    flow->rack.lost += len;
}

/*
 * 功能/Main: 定时处理定时任务（timer task）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；定时器/工作队列上下文（timer/workqueue context）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: timer
 * 影响/Effects: 周期维护状态，影响稳定性（periodic maintenance, affects stability）
 * 重要程度/Importance: 中/Medium
 */
static enum hrtimer_restart pep_tlp_timer_callback(struct hrtimer *timer)
{
    struct pep_tlp_state *tlp = container_of(timer, struct pep_tlp_state, timer);
    struct pep_flow *flow = container_of(tlp, struct pep_flow, tlp);
    struct pep_context *ctx;

    ctx = READ_ONCE(pep_ctx);
    if (!ctx || !atomic_read(&ctx->running)) {
        WRITE_ONCE(tlp->timer_active, false);
        return HRTIMER_NORESTART;
    }

    if (pep_flow_is_dead(flow)) {
        WRITE_ONCE(tlp->timer_active, false);
        return HRTIMER_NORESTART;
    }

    tlp->is_pending = 1;
    WRITE_ONCE(tlp->timer_active, false);

    /* v109: verify flow is still alive before scheduling work */
    if (refcount_inc_not_zero(&flow->refcnt)) {
        pep_schedule_wan_tx(flow);
        pep_flow_put(flow);
    }

    return HRTIMER_NORESTART;
}

/*
 * 功能/Main: 初始化pep_tlp_init相关逻辑（Initialize pep_tlp_init logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；定时器/工作队列上下文（timer/workqueue context）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
void pep_tlp_init(struct pep_flow *flow)
{
    struct pep_tlp_state *tlp;

    if (!flow)
        return;

    tlp = &flow->tlp;
    memset(tlp, 0, sizeof(*tlp));

    hrtimer_init(&tlp->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    tlp->timer.function = pep_tlp_timer_callback;
    tlp->timer_active = false;
    tlp->pto_us = PEP_TLP_MIN_PTO_US;
    tlp->probes_sent = 0;
}

/*
 * 功能/Main: 清理pep_tlp_cleanup相关逻辑（Cleanup pep_tlp_cleanup logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；定时器/工作队列上下文（timer/workqueue context）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
bool pep_tlp_cleanup(struct pep_flow *flow)
{
    struct pep_tlp_state *tlp;

    if (!flow)
        return true;

    tlp = &flow->tlp;

    hrtimer_cancel(&tlp->timer);

    tlp->timer_active = false;
    return true;
}

/*
 * 功能/Main: 计算pep_tlp_calc_pto相关逻辑（Compute pep_tlp_calc_pto logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；RTT/RTO 估计（RTT/RTO estimation）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 计算派生值，影响策略决策（compute derived values, affects policy decisions）
 * 重要程度/Importance: 低/Low
 */
static u32 pep_tlp_calc_pto(struct pep_flow *flow)
{
    u32 srtt_us, rttvar_us, pto_us;
    struct pep_rtt_estimator *rtt = &flow->rtt;

    srtt_us = rtt->srtt >> 3;
    rttvar_us = rtt->rttvar >> 2;

    if (pep_ctx && srtt_us < PEP_WAN_RTT_MIN_THRESHOLD_US &&
        pep_ctx->config.wan_rtt_ms > 0) {
        u32 fallback_rtt_us = pep_ctx->config.wan_rtt_ms * 1000;

        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
            pr_info_ratelimited("pep: TLP PTO using fallback WAN RTT: "
                                "measured=%u us, using=%u us (%u ms)\n",
                                srtt_us, fallback_rtt_us,
                                pep_ctx->config.wan_rtt_ms);
        }

        srtt_us = fallback_rtt_us;

        rttvar_us = fallback_rtt_us / 4;
    }

    pto_us = 2 * srtt_us + max_t(u32, PEP_TLP_MIN_PTO_US, 2 * rttvar_us);

    if (pto_us < PEP_TLP_MIN_PTO_US)
        pto_us = PEP_TLP_MIN_PTO_US;

    if (pto_us > flow->rtt.rto * 1000)
        pto_us = flow->rtt.rto * 1000;

    return pto_us;
}

/*
 * 功能/Main: 处理pep_tlp_schedule相关逻辑（Handle pep_tlp_schedule logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；RTT/RTO 估计（RTT/RTO estimation）；定时器/工作队列上下文（timer/workqueue context）；统计计数更新（stats counters）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_tlp_schedule(struct pep_flow *flow)
{
    struct pep_tlp_state *tlp;
    u32 pto_us;
    ktime_t delay;

    if (!flow)
        return;

    if (pep_flow_is_dead(flow))
        return;

    tlp = &flow->tlp;

    if (tlp->probes_sent >= PEP_TLP_MAX_PROBES)
        return;

    if (READ_ONCE(tlp->timer_active))
        return;

    if (skb_queue_empty(&flow->rtx_queue))
        return;

    if (flow->rtt.samples == 0)
        return;

    pto_us = pep_tlp_calc_pto(flow);
    tlp->pto_us = pto_us;
    tlp->high_seq = flow->cc.snd_nxt;
    tlp->last_sent = ktime_get();

    delay = ktime_set(0, pto_us * NSEC_PER_USEC);
    hrtimer_start(&tlp->timer, delay, HRTIMER_MODE_REL);
    WRITE_ONCE(tlp->timer_active, true);

    pep_dbg("TLP: scheduled, pto=%u us, high_seq=%u\n", pto_us, tlp->high_seq);
}

/*
 * 功能/Main: 处理pep_tlp_cancel相关逻辑（Handle pep_tlp_cancel logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；定时器/工作队列上下文（timer/workqueue context）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_tlp_cancel(struct pep_flow *flow)
{
    struct pep_tlp_state *tlp;
    int ret;

    if (!flow)
        return;

    tlp = &flow->tlp;
    if (READ_ONCE(tlp->timer_active)) {
        ret = hrtimer_try_to_cancel(&tlp->timer);
        if (ret >= 0) {
            WRITE_ONCE(tlp->timer_active, false);
        }

        tlp->probes_sent = 0;
        tlp->is_pending = 0;
    }
}

/*
 * 功能/Main: 发送pep_tlp_send_probe相关逻辑（Send pep_tlp_send_probe logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
int pep_tlp_send_probe(struct pep_flow *flow)
{
    struct pep_tlp_state *tlp;
    struct sk_buff *skb, *clone;
    struct pep_skb_cb *cb;
    unsigned long flags;

    if (!flow)
        return -1;

    tlp = &flow->tlp;

    tlp->is_pending = 0;

    if (tlp->probes_sent >= PEP_TLP_MAX_PROBES) {
        pep_dbg("TLP: max probes (%d) reached\n", PEP_TLP_MAX_PROBES);
        return -1;
    }

    spin_lock_irqsave(&flow->rtx_lock, flags);

    skb = skb_peek_tail(&flow->rtx_queue);
    if (!skb) {
        spin_unlock_irqrestore(&flow->rtx_lock, flags);
        return -1;
    }

    cb = pep_skb_cb(skb);

    clone = skb_copy(skb, GFP_ATOMIC);
    if (!clone) {
        spin_unlock_irqrestore(&flow->rtx_lock, flags);
        return -1;
    }

    cb->tx_time = ktime_get();

    spin_unlock_irqrestore(&flow->rtx_lock, flags);

    if (pep_send_wan_skb(clone) == 0) {
        tlp->probes_sent++;
        tlp->total_tlp_sent++;
        pep_stats_inc_retrans();

        pep_dbg("TLP sent probe #%d, seq=%u len=%u, pto=%u us\n",
                tlp->probes_sent, cb->seq, cb->len, tlp->pto_us);

        pep_tlp_schedule(flow);

        return 0;
    }

    return -1;
}

/*
 * 功能/Main: 处理pep_tlp_on_ack相关逻辑（Handle pep_tlp_on_ack logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow, ack_seq
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_tlp_on_ack(struct pep_flow *flow, u32 ack_seq)
{
    struct pep_tlp_state *tlp;

    if (!flow)
        return;

    tlp = &flow->tlp;

    pep_tlp_cancel(flow);

    if (tlp->probes_sent > 0 && PEP_SEQ_AFTER(ack_seq, tlp->high_seq)) {
        tlp->total_tlp_recoveries++;
        pep_dbg("TLP: recovery successful, ack_seq=%u > high_seq=%u\n",
                ack_seq, tlp->high_seq);
    }

    tlp->probes_sent = 0;
}

/*
 * 功能/Main: 处理重传/缓存（Process retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；RTT/RTO 估计（RTT/RTO estimation）；并发同步（spinlock/atomic/rcu）；proc 接口读写（/proc IO）
 * 输入/Inputs: 参数/Inputs: flow, opts
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
int pep_retrans_process_sack(struct pep_flow *flow,
                             struct pep_tcp_options *opts,
                             u32 ack_seq)
{
    struct sk_buff *skb, *clone;
    struct pep_skb_cb *cb;
    unsigned long flags;
    int retrans_count = 0;
    int i;
    u32 sack_start, sack_end;
    bool in_sack;
    bool dsack_seen = false;
    ktime_t now = ktime_get();

    if (!flow || !opts || opts->sack_blocks_count == 0)
        return 0;

    if (!test_bit(PEP_FLOW_F_SPOOFED_BIT, &flow->flags))
        return 0;

    if (!test_bit(PEP_FLOW_F_SACK_ENABLED_BIT, &flow->flags))
        return 0;

    if (pep_ctx && pep_ctx->config.debug_level >= 3) {
        pr_info_ratelimited("pep: SACK processing %u blocks for flow %pI4:%u->%pI4:%u\n",
                            opts->sack_blocks_count,
                            &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
                            &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));
    }

    for (i = 0; i < opts->sack_blocks_count; i++) {
        sack_start = opts->sack_blocks[i].start;
        sack_end = opts->sack_blocks[i].end;
        if (PEP_SEQ_BEFORE(sack_start, ack_seq) &&
            PEP_SEQ_LEQ(sack_end, ack_seq)) {
            dsack_seen = true;
            break;
        }
    }

    if (dsack_seen) {
        u32 mss = flow->mss ? flow->mss : 1460;

        flow->rack.dsack_seen++;
        if (flow->cc.undo_pending &&
            PEP_SEQ_AFTER(ack_seq, flow->cc.undo_marker)) {
            flow->cc.cwnd = max_t(u32, flow->cc.prior_cwnd, 2 * mss);
            flow->cc.ssthresh = max_t(u32, flow->cc.prior_ssthresh, 2 * mss);
            flow->cc.ca_state = PEP_CA_OPEN;
            flow->cc.loss_recovery = 0;
            flow->cc.undo_pending = 0;

            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                pr_info_ratelimited("pep: DSACK undo cwnd=%u ssthresh=%u ack=%u\n",
                                    flow->cc.cwnd, flow->cc.ssthresh, ack_seq);
            }
        }
    }

    spin_lock_irqsave(&flow->rtx_lock, flags);

    skb_queue_walk(&flow->rtx_queue, skb) {
        cb = pep_skb_cb(skb);
        in_sack = false;

        for (i = 0; i < opts->sack_blocks_count; i++) {
            sack_start = opts->sack_blocks[i].start;
            sack_end = opts->sack_blocks[i].end;

            if (!PEP_SEQ_BEFORE(cb->seq, sack_start) &&
                !PEP_SEQ_AFTER(cb->seq + cb->len, sack_end)) {
                in_sack = true;
                break;
            }
        }

        if (!in_sack) {

            u32 highest_sack = 0;
            for (i = 0; i < opts->sack_blocks_count; i++) {
                if (PEP_SEQ_AFTER(opts->sack_blocks[i].end, highest_sack))
                    highest_sack = opts->sack_blocks[i].end;
            }

            if (highest_sack > 0 && PEP_SEQ_BEFORE(cb->seq, highest_sack)) {

                if (cb->retrans_count >= pep_ctx->config.max_retrans) {
                    pr_warn_ratelimited("pep: SACK retrans limit reached for seq=%u\n",
                                        cb->seq);
                    continue;
                }

                u32 elapsed_ms = ktime_ms_delta(now, cb->tx_time);
                if (elapsed_ms < (flow->rtt.rto / 2)) {

                    continue;
                }

                clone = skb_copy(skb, GFP_ATOMIC);
                if (!clone) {
                    pr_warn_ratelimited("pep: SACK retrans clone failed for seq=%u\n",
                                        cb->seq);
                    continue;
                }

                cb->retrans_count++;
                cb->tx_time = now;

                if (pep_ctx && pep_ctx->config.debug_level >= 3) {
                    pr_info_ratelimited("pep: SACK retrans seq=%u len=%u (attempt %u)\n",
                                        cb->seq, cb->len, cb->retrans_count);
                }

                spin_unlock_irqrestore(&flow->rtx_lock, flags);

                if (pep_send_wan_skb(clone) == 0) {
                    flow->retrans_packets++;
                    pep_stats_inc_retrans();
                    retrans_count++;
                } else {
                    kfree_skb(clone);
                }

                spin_lock_irqsave(&flow->rtx_lock, flags);
            }
        }
    }

    spin_unlock_irqrestore(&flow->rtx_lock, flags);

    if (retrans_count > 0) {
        if (pep_ctx && pep_ctx->config.debug_level >= 3) {
            pr_info_ratelimited("pep: SACK triggered %d retransmissions\n", retrans_count);
        }

        pep_cc_on_loss(flow);
    }

    return retrans_count;
}

/*
 * 功能/Main: 处理pep_sack_mark_lost相关逻辑（Handle pep_sack_mark_lost logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, seq, len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_sack_mark_lost(struct pep_flow *flow, u32 seq, u32 len)
{
    if (!flow)
        return;

    flow->rack.lost += len;

    if (pep_ctx && pep_ctx->config.debug_level >= 3) {
        pr_info_ratelimited("pep: SACK marked lost: seq=%u len=%u, total_lost=%u\n",
                            seq, len, flow->rack.lost);
    }
}

/*
 * 功能/Main: 初始化重传/缓存（Initialize retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow, max_pkts, max_bytes, enabled
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
void pep_lan_retrans_init(struct pep_flow *flow, u32 max_pkts, u32 max_bytes, bool enabled)
{
    if (!flow)
        return;

    skb_queue_head_init(&flow->lan_rtx_queue);
    spin_lock_init(&flow->lan_rtx_lock);
    flow->lan_rtx_bytes = 0;
    flow->lan_rtx_max_pkts = enabled ? max_pkts : 0;
    flow->lan_rtx_max_bytes = enabled ? max_bytes : 0;
    flow->lan_rtx_dropped = 0;
    flow->lan_retrans_packets = 0;
    flow->lan_last_ack = 0;
    flow->lan_dup_acks = 0;
}

/*
 * 功能/Main: 清理重传/缓存（Cleanup retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_lan_retrans_cleanup(struct pep_flow *flow)
{
    struct sk_buff *skb;
    unsigned long flags;

    if (!flow)
        return;

    spin_lock_irqsave(&flow->lan_rtx_lock, flags);
    while ((skb = __skb_dequeue(&flow->lan_rtx_queue)) != NULL) {
        flow->lan_rtx_bytes -= skb->len;
        spin_unlock_irqrestore(&flow->lan_rtx_lock, flags);
        kfree_skb(skb);
        spin_lock_irqsave(&flow->lan_rtx_lock, flags);
    }
    spin_unlock_irqrestore(&flow->lan_rtx_lock, flags);
}

/*
 * 功能/Main: 处理重传/缓存（Handle retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）
 * 输入/Inputs: 参数/Inputs: flow, payload_len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
bool pep_lan_retrans_can_cache(const struct pep_flow *flow, u32 payload_len)
{
    u32 bytes;

    if (!flow || payload_len == 0)
        return false;

    if (flow->lan_rtx_max_pkts == 0 || flow->lan_rtx_max_bytes == 0)
        return false;

    bytes = READ_ONCE(flow->lan_rtx_bytes);
    if (bytes + payload_len > flow->lan_rtx_max_bytes)
        return false;

    if (skb_queue_len(&flow->lan_rtx_queue) >= flow->lan_rtx_max_pkts)
        return false;

    return true;
}

/*
 * 功能/Main: 处理重传/缓存（Handle retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow, skb, seq, len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
int pep_lan_retrans_cache_add(struct pep_flow *flow, struct sk_buff *skb,
                              u32 seq, u32 len)
{
    struct pep_skb_cb *cb;
    unsigned long flags;

    if (!flow || !skb || len == 0)
        return -EINVAL;

    if (flow->lan_rtx_max_pkts == 0 || flow->lan_rtx_max_bytes == 0) {
        kfree_skb(skb);
        return -ENOSPC;
    }

    cb = pep_skb_cb(skb);
    cb->tx_time = ktime_get();
    cb->seq = seq;
    cb->len = len;
    cb->retrans_count = 0;

    spin_lock_irqsave(&flow->lan_rtx_lock, flags);
    /* v108.1: Single eviction + deferred free outside lock.
     * Eliminates the unlock/relock loop that caused lock contention
     * storm under high throughput (100+ Mbps, 37 concurrent flows). */
    {
        struct sk_buff *evict = NULL;

        if (skb_queue_len(&flow->lan_rtx_queue) >= flow->lan_rtx_max_pkts ||
            flow->lan_rtx_bytes + skb->len > flow->lan_rtx_max_bytes) {
            evict = __skb_dequeue(&flow->lan_rtx_queue);
            if (evict) {
                flow->lan_rtx_bytes -= evict->len;
                flow->lan_rtx_dropped++;
            }
        }

        __skb_queue_tail(&flow->lan_rtx_queue, skb);
        flow->lan_rtx_bytes += skb->len;
        spin_unlock_irqrestore(&flow->lan_rtx_lock, flags);

        if (evict)
            kfree_skb(evict);
    }

    return 0;
}

/*
 * 功能/Main: 发送重传/缓存（Send retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
static void pep_lan_retrans_send_head(struct pep_flow *flow)
{
    struct sk_buff *skb;
    struct sk_buff *clone = NULL;
    unsigned long flags;

    if (!flow)
        return;

    spin_lock_irqsave(&flow->lan_rtx_lock, flags);
    skb = skb_peek(&flow->lan_rtx_queue);
    if (skb)
        clone = skb_copy(skb, GFP_ATOMIC);
    spin_unlock_irqrestore(&flow->lan_rtx_lock, flags);

    if (!clone)
        return;

    clone->mark = PEP_SKB_MARK_RETRANS;
    if (pep_send_lan_skb(flow, clone) == 0)
        flow->lan_retrans_packets++;
}

/*
 * 功能/Main: 处理重传/缓存（Handle retransmission/cache）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow, ack_seq
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_lan_retrans_on_ack(struct pep_flow *flow, u32 ack_seq)
{
    struct sk_buff *skb;
    struct pep_skb_cb *cb;
    unsigned long flags;
    bool advanced = false;
    bool do_retrans = false;

    if (!flow || flow->lan_rtx_max_bytes == 0 || flow->lan_rtx_max_pkts == 0)
        return;

    spin_lock_irqsave(&flow->lan_rtx_lock, flags);

    if (flow->lan_last_ack == 0)
        flow->lan_last_ack = ack_seq;

    if (PEP_SEQ_AFTER(ack_seq, flow->lan_last_ack)) {
        flow->lan_last_ack = ack_seq;
        flow->lan_dup_acks = 0;
        advanced = true;
        flow->lan_snd_una = ack_seq;
    } else if (ack_seq == flow->lan_last_ack) {
        if (flow->lan_dup_acks < UINT_MAX)
            flow->lan_dup_acks++;
    }

    while ((skb = skb_peek(&flow->lan_rtx_queue)) != NULL) {
        cb = pep_skb_cb(skb);
        if (PEP_SEQ_LEQ(cb->seq + cb->len, ack_seq)) {
            skb = __skb_dequeue(&flow->lan_rtx_queue);
            flow->lan_rtx_bytes -= skb->len;
            spin_unlock_irqrestore(&flow->lan_rtx_lock, flags);
            kfree_skb(skb);
            spin_lock_irqsave(&flow->lan_rtx_lock, flags);
            continue;
        }
        break;
    }

    if (!advanced && flow->lan_dup_acks >= 3) {
        flow->lan_dup_acks = 0;
        do_retrans = true;
    }

    spin_unlock_irqrestore(&flow->lan_rtx_lock, flags);

    if (do_retrans)
        pep_lan_retrans_send_head(flow);
}
