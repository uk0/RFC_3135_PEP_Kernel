/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"
#include <net/netfilter/nf_conntrack.h>
#include <linux/fib_rules.h>

extern struct pep_context *pep_ctx;

#define PEP_ACK_DYNAMIC_MIN_US 200
#define PEP_ACK_DYNAMIC_MAX_US 10000

/*
 * 功能/Main: 发送校验和处理（Send checksum handling）
 * 细节/Details: 校验和处理（checksum adjust）；配置/参数应用（config/params）
 * 输入/Inputs: 无（void）/none
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
static inline bool pep_tx_csum_offload_enabled(void)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);

    return ctx && ctx->config.tx_csum_enabled;
}

static int pep_send_skb(struct sk_buff *skb);
static int pep_send_skb_with_dev(struct sk_buff *skb, struct net_device *in_dev);
int pep_send_lan_skb(struct pep_flow *flow, struct sk_buff *skb);
static struct sk_buff *pep_create_wan_data_ack(struct pep_flow *flow, u32 ack_seq);
int pep_spoofing_handle_data(struct pep_context *ctx, struct pep_flow *flow,
                              struct sk_buff *skb, enum pep_direction dir);

/*
 * 功能/Main: 处理pep_generate_isn相关逻辑（Handle pep_generate_isn logic）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 无（void）/none
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static inline u32 pep_generate_isn(void)
{
    return get_random_u32();
}

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

static inline bool pep_flow_ecn_active(struct pep_flow *flow)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);

    return flow && ctx && ctx->config.ecn_enabled &&
           test_bit(PEP_FLOW_F_ECN_BIT, &flow->flags) &&
           flow->cc.ecn_enabled;
}

static inline void pep_ecn_apply_wan_tx(struct pep_flow *flow,
                                        struct iphdr *iph,
                                        struct tcphdr *tcph)
{
    if (!pep_flow_ecn_active(flow) || !iph || !tcph)
        return;

    iph->tos = (iph->tos & ~PEP_ECN_MASK) | PEP_ECN_ECT0;
    if (flow->cc.ecn_state == PEP_ECN_STATE_CWR)
        tcph->cwr = 1;
}

static inline void pep_ecn_apply_wan_ack(struct pep_flow *flow,
                                         struct tcphdr *tcph)
{
    if (!pep_flow_ecn_active(flow) || !tcph)
        return;

    if (flow->ecn_ece_pending)
        tcph->ece = 1;
}

static void pep_ack_pacer_recalc(struct pep_flow *flow, u32 bandwidth_kbps)
{
    struct pep_ack_pacer *pacer;
    struct pep_context *ctx;
    u32 mss;
    u32 srtt_us = 0;
    u32 bytes_per_ack = PEP_DEFAULT_ACK_BYTES_THRESHOLD;
    u32 ack_interval_us = PEP_DEFAULT_ACK_DELAY_US;

    if (!flow)
        return;

    pacer = &flow->ack_pacer;
    ctx = READ_ONCE(pep_ctx);
    mss = flow->mss ? flow->mss : 1460;

    if (flow->rtt.srtt > 0)
        srtt_us = flow->rtt.srtt >> 3;

    if (ctx && ctx->config.ack_bytes_threshold > 0) {
        bytes_per_ack = ctx->config.ack_bytes_threshold;
    } else {
        u32 cwnd = flow->cc.cwnd;

        if (test_bit(PEP_FLOW_F_ECN_CE_SEEN_BIT, &flow->flags) ||
            cwnd < 4 * mss) {
            bytes_per_ack = mss;
        } else if (cwnd < 16 * mss) {
            bytes_per_ack = 2 * mss;
        } else if (cwnd < 64 * mss) {
            bytes_per_ack = 4 * mss;
        } else {
            bytes_per_ack = 8 * mss;
        }
    }

    if (bytes_per_ack < mss)
        bytes_per_ack = mss;

    pacer->bytes_per_ack = bytes_per_ack;

    if (ctx && ctx->config.ack_delay_us > 0) {
        ack_interval_us = ctx->config.ack_delay_us;
    } else if (bandwidth_kbps > 0) {
        ack_interval_us = (bytes_per_ack * 8 * 1000) / bandwidth_kbps;
        if (ack_interval_us == 0)
            ack_interval_us = 1;
    } else if (srtt_us > 0) {
        ack_interval_us = srtt_us / 8;
    }

    if (srtt_us > 0) {
        u32 min_us = max_t(u32, PEP_ACK_DYNAMIC_MIN_US, srtt_us / 16);
        u32 max_us = min_t(u32, PEP_ACK_DYNAMIC_MAX_US, srtt_us / 4);
        ack_interval_us = clamp(ack_interval_us, min_us, max_us);
    } else {
        ack_interval_us = clamp(ack_interval_us,
                                PEP_ACK_DYNAMIC_MIN_US,
                                PEP_ACK_DYNAMIC_MAX_US);
    }

    pacer->ack_interval_us = ack_interval_us;
}

/*
 * 功能/Main: 定时处理定时任务（timer task）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；定时器/工作队列上下文（timer/workqueue context）；并发同步（spinlock/atomic/rcu）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: timer
 * 影响/Effects: 周期维护状态，影响稳定性（periodic maintenance, affects stability）
 * 重要程度/Importance: 中/Medium
 */
static enum hrtimer_restart pep_ack_timer_callback(struct hrtimer *timer)
{
    struct pep_ack_pacer *pacer = container_of(timer, struct pep_ack_pacer, timer);
    struct pep_flow *flow = container_of(pacer, struct pep_flow, ack_pacer);
    struct pep_context *ctx;

    ctx = READ_ONCE(pep_ctx);
    if (!ctx || !atomic_read(&ctx->running)) {
        WRITE_ONCE(pacer->timer_active, false);
        return HRTIMER_NORESTART;
    }

    if (!flow || test_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags)) {
        WRITE_ONCE(pacer->timer_active, false);
        return HRTIMER_NORESTART;
    }

    if (pacer->bytes_received == 0) {
        WRITE_ONCE(pacer->timer_active, false);
        return HRTIMER_NORESTART;
    }

    pacer->is_pending = 1;
    WRITE_ONCE(pacer->timer_active, false);

    pep_schedule_lan_tx(flow);

    return HRTIMER_NORESTART;
}

/*
 * 功能/Main: 初始化pep_ack_pacer_init相关逻辑（Initialize pep_ack_pacer_init logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；定时器/工作队列上下文（timer/workqueue context）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
void pep_ack_pacer_init(struct pep_flow *flow)
{
    struct pep_ack_pacer *pacer;

    if (!flow)
        return;

    pacer = &flow->ack_pacer;
    memset(pacer, 0, sizeof(*pacer));
    pep_ack_pacer_recalc(flow, 0);

    hrtimer_init(&pacer->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    pacer->timer.function = pep_ack_timer_callback;
    pacer->timer_active = false;
}

/*
 * 功能/Main: 清理pep_ack_pacer_cleanup相关逻辑（Cleanup pep_ack_pacer_cleanup logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；定时器/工作队列上下文（timer/workqueue context）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
bool pep_ack_pacer_cleanup(struct pep_flow *flow)
{
    struct pep_ack_pacer *pacer;

    if (!flow)
        return true;

    pacer = &flow->ack_pacer;

    hrtimer_cancel(&pacer->timer);

    pacer->timer_active = false;
    return true;
}

/*
 * 功能/Main: 获取pep_get_backpressure_ack_delay相关逻辑（Get pep_get_backpressure_ack_delay logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static u32 pep_get_backpressure_ack_delay(struct pep_flow *flow)
{
    u32 base_delay_us;
    u8 bp_level;

    if (!flow || !pep_ctx)
        return PEP_DEFAULT_ACK_DELAY_US;

    base_delay_us = flow->ack_pacer.ack_interval_us;
    if (base_delay_us == 0)
        base_delay_us = pep_ctx->config.ack_delay_us;
    if (base_delay_us == 0)
        base_delay_us = PEP_DEFAULT_ACK_DELAY_US;

    bp_level = pep_queue_get_backpressure_level(&flow->lan_to_wan);

    switch (bp_level) {
    case 2:

        return base_delay_us * 4;

    case 1:

        return base_delay_us * 2;

    case 0:
    default:

        return base_delay_us;
    }
}

/*
 * 功能/Main: 处理pep_should_pause_ack_for_backpressure相关逻辑（Handle pep_should_pause_ack_for_backpressure logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；FEC 编码/映射/恢复（FEC encode/map/recover）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static bool pep_should_pause_ack_for_backpressure(struct pep_flow *flow)
{
    u32 bytes, max_bytes;
    u32 usage_pct;

    if (!flow || !pep_ctx)
        return false;

    if (!pep_ctx->config.queue_bdp_enabled)
        return false;

    bytes = READ_ONCE(flow->lan_to_wan.bytes);
    max_bytes = READ_ONCE(flow->lan_to_wan.effective_max);

    if (max_bytes == 0)
        return false;

    usage_pct = (u64)bytes * 100 / max_bytes;

    return usage_pct >= 95;
}

/*
 * 功能/Main: 处理pep_ack_pacer_queue相关逻辑（Handle pep_ack_pacer_queue logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；ACK pacing 调度（ACK pacing scheduling）；定时器/工作队列上下文（timer/workqueue context）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, ack_seq, bytes
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_ack_pacer_queue(struct pep_flow *flow, u32 ack_seq, u32 bytes)
{
    struct pep_ack_pacer *pacer;
    struct sk_buff *ack_skb;
    u32 pep_seq;
    bool send_now = false;
    u32 adjusted_delay_us;
    ktime_t delay;

    if (!flow || !pep_ctx)
        return;

    if (test_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags))
        return;

    if (pep_should_pause_ack_for_backpressure(flow)) {
        /*
         * v85 关键修复: 背压时也必须设置 timer 或 is_pending
         *
         * 问题: 之前背压时只更新 bytes_received 和 pending_ack_seq，
         *       然后直接 return，没有设置 timer 或 is_pending
         *       导致客户端永远收不到 ACK → NS_BINDING_ABORTED
         *
         * 解决: 设置 is_pending=1 并启动延迟 timer（10ms）
         *       让 pep_lan_tx_work_handler 在队列下降后发送 ACK
         */
        pacer = &flow->ack_pacer;
        pacer->bytes_received += bytes;
        pacer->pending_ack_seq = ack_seq;
        pacer->is_pending = 1;  /* v85: 标记有 pending ACK */

        /* v85: 启动延迟 timer，等队列下降后发送 ACK */
        if (!READ_ONCE(pacer->timer_active)) {
            ktime_t bp_delay = ktime_set(0, 10000000);  /* 10ms 延迟 */
            WRITE_ONCE(pacer->timer_active, true);
            hrtimer_start(&pacer->timer, bp_delay, HRTIMER_MODE_REL);
        }

        if (pep_ctx->config.debug_level >= 2) {
            pr_info_ratelimited("pep: ACK Pacing: backpressure (queue >95%%), "
                                "scheduled delayed ACK, bytes=%u\n", bytes);
        }
        return;
    }

    pacer = &flow->ack_pacer;

    pacer->bytes_received += bytes;
    pacer->pending_ack_seq = ack_seq;

    if (!pep_ctx->config.ack_pacing_enabled) {
        send_now = true;
    } else if (pacer->bytes_received >= pacer->bytes_per_ack) {

        send_now = true;
        pacer->acks_batched++;
    }

    if (send_now) {

        if (pacer->timer_active) {
            int ret = hrtimer_try_to_cancel(&pacer->timer);
            if (ret >= 0) {
                pacer->timer_active = false;
            }

        }

        pep_seq = flow->isn_pep + 1;
        ack_skb = pep_create_fake_ack(flow, pep_seq, ack_seq);
        if (ack_skb) {

            if (pep_send_lan_skb(flow, ack_skb) == 0) {
                pep_stats_inc_fake_ack();
                flow->fake_acks_sent++;
                pacer->acks_sent++;

                pacer->last_ack_seq = ack_seq;
                pacer->last_ack_time_ns = ktime_get_ns();
                pacer->bytes_received = 0;

                if (pep_ctx && pep_ctx->config.debug_level >= 3) {
                    pr_info("pep: ACK Pacing: sent immediate ACK ack=%u bytes=%u\n",
                            ack_seq, bytes);
                }
            }
        }
    } else {

        if (!READ_ONCE(pacer->timer_active)) {

            adjusted_delay_us = pep_get_backpressure_ack_delay(flow);
            delay = ktime_set(0, adjusted_delay_us * 1000);
            hrtimer_start(&pacer->timer, delay, HRTIMER_MODE_REL);
            WRITE_ONCE(pacer->timer_active, true);

            if (pep_ctx && pep_ctx->config.debug_level >= 4) {
                pr_info("pep: ACK Pacing: scheduled ACK in %u us (bp adjusted)\n",
                        adjusted_delay_us);
            }
        }
    }
}

/*
 * 功能/Main: 处理pep_ack_pacer_flush相关逻辑（Handle pep_ack_pacer_flush logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；定时器/工作队列上下文（timer/workqueue context）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_ack_pacer_flush(struct pep_flow *flow)
{
    struct pep_ack_pacer *pacer;
    struct sk_buff *ack_skb;
    u32 pep_seq;

    if (!flow)
        return;

    pacer = &flow->ack_pacer;

    if (pacer->timer_active) {
        hrtimer_cancel(&pacer->timer);
        pacer->timer_active = false;
    }

    if (pacer->bytes_received > 0) {
        pep_seq = flow->isn_pep + 1;
        ack_skb = pep_create_fake_ack(flow, pep_seq, pacer->pending_ack_seq);
        if (ack_skb) {

            if (pep_send_lan_skb(flow, ack_skb) == 0) {
                pep_stats_inc_fake_ack();
                flow->fake_acks_sent++;
                pacer->acks_sent++;
            }
        }
        pacer->bytes_received = 0;
    }
}

/*
 * 功能/Main: 更新pep_ack_pacer_update_interval相关逻辑（Update pep_ack_pacer_update_interval logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；ACK pacing 调度（ACK pacing scheduling）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, bandwidth_kbps
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 中/Medium
 */
void pep_ack_pacer_update_interval(struct pep_flow *flow, u32 bandwidth_kbps)
{
    if (!flow)
        return;

    pep_ack_pacer_recalc(flow, bandwidth_kbps);

    if (pep_ctx && pep_ctx->config.debug_level >= 3) {
        pr_info("pep: ACK Pacing: interval updated to %u us (bw=%u kbps)\n",
                flow->ack_pacer.ack_interval_us, bandwidth_kbps);
    }
}

/*
 * 功能/Main: 处理pep_translate_seq_wan_to_lan相关逻辑（Handle pep_translate_seq_wan_to_lan logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；访问/维护流状态（flow state access/maintenance）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: flow, skb
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
int pep_translate_seq_wan_to_lan(struct pep_flow *flow, struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len, tcp_hdr_len, hdr_total;
    u32 old_seq, new_seq;

    if (!flow || !skb)
        return -EINVAL;

    if (flow->seq_offset == 0)
        return 0;

    /*
     * v77: 只确保 header 可写，不是整个 skb
     *
     * 问题: 之前使用 skb_ensure_writable(skb, skb->len) 要求整个 skb 可写
     *       对于 GRO 聚合后的大包（可能达到 64KB），这会导致内存分配失败
     *
     * 解决: 只需要修改 TCP header 的 seq 字段，所以只需确保 header 可写
     *       skb_ensure_writable 的第二个参数是要确保可写的字节数（从 skb->data 开始）
     */
    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
    tcp_hdr_len = tcph->doff * 4;
    hdr_total = ip_hdr_len + tcp_hdr_len;

    if (skb_ensure_writable(skb, hdr_total))
        return -ENOMEM;

    /* 重新获取指针，skb_ensure_writable 可能重新分配了头部 */
    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

    old_seq = ntohl(tcph->seq);

    new_seq = old_seq + flow->seq_offset;

    tcph->seq = htonl(new_seq);

    if (skb->ip_summed != CHECKSUM_PARTIAL) {

        csum_replace4(&tcph->check, htonl(old_seq), htonl(new_seq));
    }

    if (skb->ip_summed == CHECKSUM_COMPLETE) {
        skb->ip_summed = CHECKSUM_UNNECESSARY;
    }

    pep_dbg("Spoofing: SEQ translated %u -> %u (offset=%d, summed=%d)\n",
            old_seq, new_seq, flow->seq_offset, skb->ip_summed);

    return 0;
}

/*
 * 功能/Main: 处理pep_translate_sack_blocks相关逻辑（Handle pep_translate_sack_blocks logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；流表查找/创建/状态更新（flow lookup/create/update）；校验和处理（checksum adjust）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, skb, tcph
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static int pep_translate_sack_blocks(struct pep_flow *flow, struct sk_buff *skb,
                                     struct tcphdr *tcph)
{
    unsigned char *ptr;
    int length;
    int opcode, opsize;
    int sack_translated = 0;

    if (!flow || !skb || !tcph)
        return 0;

    if (flow->seq_offset == 0)
        return 0;

    if (!test_bit(PEP_FLOW_F_SACK_ENABLED_BIT, &flow->flags))
        return 0;

    ptr = (unsigned char *)(tcph + 1);
    length = (tcph->doff * 4) - sizeof(struct tcphdr);

    while (length > 0) {
        opcode = *ptr++;
        length--;

        switch (opcode) {
        case TCPOPT_EOL:
            return sack_translated;
        case TCPOPT_NOP:
            continue;
        default:
            if (length < 1)
                return sack_translated;
            opsize = *ptr++;
            length--;
            if (opsize < 2 || opsize > length + 2)
                return sack_translated;

            if (opcode == 5 && opsize >= 10 && ((opsize - 2) % 8) == 0) {
                int num_blocks = (opsize - 2) / 8;
                int i;
                __be32 *block_ptr;
                u32 old_start, old_end, new_start, new_end;

                if (num_blocks > 4)
                    num_blocks = 4;

                block_ptr = (__be32 *)ptr;

                for (i = 0; i < num_blocks; i++) {

                    old_start = ntohl(block_ptr[i * 2]);
                    old_end = ntohl(block_ptr[i * 2 + 1]);

                    new_start = old_start - flow->seq_offset;
                    new_end = old_end - flow->seq_offset;

                    block_ptr[i * 2] = htonl(new_start);
                    block_ptr[i * 2 + 1] = htonl(new_end);

                    if (skb->ip_summed != CHECKSUM_PARTIAL) {
                        csum_replace4(&tcph->check, htonl(old_start), htonl(new_start));
                        csum_replace4(&tcph->check, htonl(old_end), htonl(new_end));
                    }

                    sack_translated++;

                    if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                        pr_info("pep: SACK block[%d] translated: [%u,%u) -> [%u,%u)\n",
                                i, old_start, old_end, new_start, new_end);
                    }
                }
            }

            ptr += opsize - 2;
            length -= opsize - 2;
        }
    }

    return sack_translated;
}

/*
 * 功能/Main: 处理pep_translate_ack_lan_to_wan相关逻辑（Handle pep_translate_ack_lan_to_wan logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；访问/维护流状态（flow state access/maintenance）；重传/缓存处理（retransmission/cache）；字节缓存读写（byte cache access）；校验和处理（checksum adjust）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, skb
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
int pep_translate_ack_lan_to_wan(struct pep_flow *flow, struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len;
    u32 old_ack, new_ack;

    if (!flow || !skb)
        return -EINVAL;

    if (flow->seq_offset == 0)
        return 0;

    if (skb_ensure_writable(skb, skb->len))
        return -ENOMEM;

    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

    if (!tcph->ack)
        return 0;

    old_ack = ntohl(tcph->ack_seq);

    if (pep_ctx && pep_ctx->config.byte_cache_enabled) {
        struct pep_tcp_options opts;

        pep_parse_tcp_options(tcph, &opts);
        pep_byte_cache_on_ack(flow, &opts, old_ack);
    }

    if (pep_ctx && pep_ctx->config.local_retrans)
        pep_lan_retrans_on_ack(flow, old_ack);

    new_ack = old_ack - flow->seq_offset;

    tcph->ack_seq = htonl(new_ack);

    if (skb->ip_summed == CHECKSUM_PARTIAL) {

        __wsum tmp;
        tmp = csum_sub(csum_unfold(tcph->check), (__force __wsum)htonl(old_ack));
        tmp = csum_add(tmp, (__force __wsum)htonl(new_ack));
        tcph->check = ~csum_fold(tmp);
    } else {

        csum_replace4(&tcph->check, htonl(old_ack), htonl(new_ack));
    }

    if (pep_ctx && pep_ctx->config.debug_level >= 2) {
        pr_info("pep: ACK translated %u -> %u (offset=%d, summed=%d)\n",
                old_ack, new_ack, flow->seq_offset, skb->ip_summed);
    }

    pep_translate_sack_blocks(flow, skb, tcph);

    return 0;
}

/*
 * 功能/Main: 处理pep_create_fake_synack相关逻辑（Handle pep_create_fake_synack logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；frag/分片结构处理（frag list handling）；流表查找/创建/状态更新（flow lookup/create/update）；PMTU/MSS 更新（PMTU/MSS update）；并发同步（spinlock/atomic/rcu）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
struct sk_buff *pep_create_fake_synack(struct pep_flow *flow)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned char *opt_ptr;
    unsigned int ip_hdr_len = sizeof(struct iphdr);

    unsigned int tcp_hdr_len = sizeof(struct tcphdr) + 12;
    unsigned int total_len;
    unsigned int headroom;
    u32 our_isn;

    #define PEP_WSCALE_FACTOR 7

    if (!flow)
        return NULL;

    our_isn = pep_generate_isn();

    flow->isn_pep = our_isn;

    headroom = LL_MAX_HEADER + ip_hdr_len;
    total_len = ip_hdr_len + tcp_hdr_len;

    skb = alloc_skb(headroom + total_len, GFP_ATOMIC);
    if (!skb)
        return NULL;

    skb_reserve(skb, headroom);
    skb_reset_network_header(skb);

    iph = skb_put(skb, ip_hdr_len);
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = 0;
    iph->frag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;

    iph->saddr = flow->tuple.dst_addr;
    iph->daddr = flow->tuple.src_addr;

    skb_set_transport_header(skb, ip_hdr_len);
    tcph = skb_put(skb, tcp_hdr_len);
    memset(tcph, 0, tcp_hdr_len);

    tcph->source = flow->tuple.dst_port;
    tcph->dest = flow->tuple.src_port;
    tcph->seq = htonl(our_isn);
    tcph->ack_seq = htonl(flow->lan.seq_next);
    tcph->doff = tcp_hdr_len / 4;
    tcph->syn = 1;
    tcph->ack = 1;
    if (flow->ecn_requested)
        tcph->ece = 1;
    tcph->window = htons(65535);

    opt_ptr = (unsigned char *)(tcph + 1);

    *opt_ptr++ = TCPOPT_MSS;
    *opt_ptr++ = TCPOLEN_MSS;
    *opt_ptr++ = (1460 >> 8) & 0xFF;
    *opt_ptr++ = 1460 & 0xFF;

    *opt_ptr++ = TCPOPT_SACK_PERM;
    *opt_ptr++ = TCPOLEN_SACK_PERM;

    *opt_ptr++ = TCPOPT_NOP;
    *opt_ptr++ = TCPOPT_NOP;

    *opt_ptr++ = TCPOPT_WINDOW;
    *opt_ptr++ = TCPOLEN_WINDOW;
    *opt_ptr++ = PEP_WSCALE_FACTOR;

    *opt_ptr++ = TCPOPT_NOP;

    flow->lan.wscale = PEP_WSCALE_FACTOR;

    set_bit(PEP_FLOW_F_SACK_ENABLED_BIT, &flow->flags);

    pep_update_ip_checksum(iph);
    pep_fast_tcp_checksum(skb, iph, tcph, pep_tx_csum_offload_enabled());

    skb->protocol = htons(ETH_P_IP);
    skb->mark = PEP_SKB_MARK_FAKE_ACK;
    skb->priority = 0;

    set_bit(PEP_FLOW_F_SPOOFED_BIT, &flow->flags);
    set_bit(PEP_FLOW_F_SYN_ACKED_BIT, &flow->flags);

    return skb;
}

/*
 * 功能/Main: 处理pep_create_fake_ack相关逻辑（Handle pep_create_fake_ack logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；frag/分片结构处理（frag list handling）；访问/维护流状态（flow state access/maintenance）；并发同步（spinlock/atomic/rcu）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: flow, seq, ack
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
struct sk_buff *pep_create_fake_ack(struct pep_flow *flow, u32 seq, u32 ack)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len = sizeof(struct iphdr);
    unsigned int tcp_hdr_len = sizeof(struct tcphdr);
    unsigned int total_len;
    unsigned int headroom;

    if (!flow)
        return NULL;

    headroom = LL_MAX_HEADER + ip_hdr_len;
    total_len = ip_hdr_len + tcp_hdr_len;

    skb = alloc_skb(headroom + total_len, GFP_ATOMIC);
    if (!skb)
        return NULL;

    skb_reserve(skb, headroom);
    skb_reset_network_header(skb);

    iph = skb_put(skb, ip_hdr_len);
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = 0;
    iph->frag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;

    iph->saddr = flow->tuple.dst_addr;
    iph->daddr = flow->tuple.src_addr;

    skb_set_transport_header(skb, ip_hdr_len);
    tcph = skb_put(skb, tcp_hdr_len);
    memset(tcph, 0, tcp_hdr_len);

    tcph->source = flow->tuple.dst_port;
    tcph->dest = flow->tuple.src_port;
    tcph->seq = htonl(seq);
    tcph->ack_seq = htonl(ack);
    tcph->doff = tcp_hdr_len / 4;
    tcph->ack = 1;

    /*
     * v95 关键修复: 动态窗口计算替代固定 64KB
     *
     * 问题: 之前使用固定 tcph->window = htons(65535) (64KB)
     *       导致大文件上传卡在 64KB 无法继续
     *       客户端发送 64KB 后等待窗口更新，但我们一直通告 64KB
     *
     * 解决: 基于 lan_to_wan 队列剩余空间动态计算窗口
     *       remaining = effective_max - current_bytes
     *       考虑窗口缩放因子 (wscale)
     *
     * 窗口通告策略:
     * - 最小 16KB (避免过小导致性能问题)
     * - 最大 1MB (允许大文件上传)
     * - 动态反映当前队列容量
     */
    {
        u32 queue_bytes = READ_ONCE(flow->lan_to_wan.bytes);
        u32 queue_max = READ_ONCE(flow->lan_to_wan.effective_max);
        u32 remaining;
        u16 win_val;

        /* 计算剩余空间 */
        if (queue_max > queue_bytes)
            remaining = queue_max - queue_bytes;
        else
            remaining = 16384;  /* 最小 16KB */

        /* 应用窗口缩放 (如果启用) */
        if (test_bit(PEP_FLOW_F_WSCALE_ENABLED_BIT, &flow->flags) &&
            flow->lan.wscale > 0) {
            /* 右移 wscale 位来缩小通告值 */
            remaining = remaining >> flow->lan.wscale;
        }

        /* 限制在 u16 范围内 */
        if (remaining > 65535)
            remaining = 65535;
        if (remaining < 8192)
            remaining = 8192;  /* 最小 8KB (未缩放) */

        win_val = (u16)remaining;
        tcph->window = htons(win_val);
    }

    pep_update_ip_checksum(iph);
    pep_fast_tcp_checksum(skb, iph, tcph, pep_tx_csum_offload_enabled());

    skb->protocol = htons(ETH_P_IP);
    skb->mark = PEP_SKB_MARK_FAKE_ACK;
    skb->priority = 0;

    return skb;
}

/*
 * 功能/Main: 处理pep_create_lan_rst相关逻辑（Handle pep_create_lan_rst logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；frag/分片结构处理（frag list handling）；访问/维护流状态（flow state access/maintenance）；并发同步（spinlock/atomic/rcu）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: flow, seq, ack
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static struct sk_buff *pep_create_lan_rst(struct pep_flow *flow, u32 seq, u32 ack)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len = sizeof(struct iphdr);
    unsigned int tcp_hdr_len = sizeof(struct tcphdr);
    unsigned int total_len;
    unsigned int headroom;

    if (!flow)
        return NULL;

    headroom = LL_MAX_HEADER + ip_hdr_len;
    total_len = ip_hdr_len + tcp_hdr_len;

    skb = alloc_skb(headroom + total_len, GFP_ATOMIC);
    if (!skb)
        return NULL;

    skb_reserve(skb, headroom);
    skb_reset_network_header(skb);

    iph = skb_put(skb, ip_hdr_len);
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = 0;
    iph->frag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = flow->tuple.dst_addr;
    iph->daddr = flow->tuple.src_addr;

    skb_set_transport_header(skb, ip_hdr_len);
    tcph = skb_put(skb, tcp_hdr_len);
    memset(tcph, 0, tcp_hdr_len);

    tcph->source = flow->tuple.dst_port;
    tcph->dest = flow->tuple.src_port;
    tcph->seq = htonl(seq);
    tcph->ack_seq = htonl(ack);
    tcph->doff = tcp_hdr_len / 4;
    tcph->rst = 1;
    tcph->ack = 1;
    tcph->window = htons(0);

    pep_update_ip_checksum(iph);
    pep_fast_tcp_checksum(skb, iph, tcph, pep_tx_csum_offload_enabled());

    skb->protocol = htons(ETH_P_IP);
    skb->mark = PEP_SKB_MARK_FAKE_ACK;
    skb->priority = 0;

    return skb;
}

/*
 * 功能/Main: 发送pep_send_lan_rst相关逻辑（Send pep_send_lan_rst logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
static void pep_send_lan_rst(struct pep_flow *flow)
{
    struct sk_buff *skb;
    u32 seq = 0;
    u32 ack = 0;

    if (!flow)
        return;

    if (flow->isn_pep)
        seq = flow->isn_pep + 1;
    else if (flow->isn_client)
        seq = flow->isn_client + 1;

    if (flow->lan.seq_next)
        ack = flow->lan.seq_next;
    else if (flow->isn_client)
        ack = flow->isn_client + 1;

    skb = pep_create_lan_rst(flow, seq, ack);
    if (!skb)
        return;

    if (pep_send_lan_skb(flow, skb) == 0) {
        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
            pr_info_ratelimited("pep: LAN RST sent for %pI4:%u -> %pI4:%u\n",
                    &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
                    &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));
        }
    }
}

/*
 * 功能/Main: 发送pep_send_advance_ack相关逻辑（Send pep_send_advance_ack logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, ack_seq
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
static int pep_send_advance_ack(struct pep_flow *flow, u32 ack_seq)
{
    struct sk_buff *skb;
    int ret;

    if (!flow)
        return -EINVAL;

    skb = pep_create_wan_data_ack(flow, ack_seq);
    if (!skb)
        return -ENOMEM;

    ret = pep_send_wan_skb(skb);
    if (ret == 0) {
        pep_stats_inc_adv_ack();
        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
            pr_info_ratelimited("pep: Advance ACK sent to server: ack_seq=%u\n", ack_seq);
        }
    } else {
        pr_warn_ratelimited("pep: Advance ACK failed: ret=%d\n", ret);
    }
    return ret;
}

/*
 * 功能/Main: 获取pep_adv_ack_get_timeout_us相关逻辑（Get pep_adv_ack_get_timeout_us logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；RTT/RTO 估计（RTT/RTO estimation）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static u32 pep_adv_ack_get_timeout_us(struct pep_flow *flow)
{
    u32 timeout_us = PEP_ADV_ACK_TIMEOUT_US;
    struct pep_context *ctx = READ_ONCE(pep_ctx);

    if (flow && flow->rtt.srtt > 0) {
        u32 srtt_us = flow->rtt.srtt >> 3;
        if (srtt_us > 0)
            timeout_us = srtt_us / 8;
    }

    /* v107: split_dl 模式下更短超时，加速 ACK 反馈 */
    if (ctx && ctx->config.split_dl_enabled)
        timeout_us = timeout_us / 2;

    if (timeout_us < PEP_ADV_ACK_MIN_TIMEOUT_US)
        timeout_us = PEP_ADV_ACK_MIN_TIMEOUT_US;
    if (timeout_us > PEP_ADV_ACK_MAX_TIMEOUT_US)
        timeout_us = PEP_ADV_ACK_MAX_TIMEOUT_US;

    return timeout_us;
}

/*
 * 功能/Main: 定时处理定时任务（timer task）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；定时器/工作队列上下文（timer/workqueue context）；并发同步（spinlock/atomic/rcu）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: timer
 * 影响/Effects: 周期维护状态，影响稳定性（periodic maintenance, affects stability）
 * 重要程度/Importance: 中/Medium
 */
static enum hrtimer_restart pep_adv_ack_timer_callback(struct hrtimer *timer)
{
    struct pep_flow *flow = container_of(timer, struct pep_flow, adv_ack_timer);
    struct pep_context *ctx;
    unsigned long flags;
    bool schedule = false;

    ctx = READ_ONCE(pep_ctx);
    if (!ctx || !atomic_read(&ctx->running)) {
        WRITE_ONCE(flow->adv_ack_timer_active, false);
        return HRTIMER_NORESTART;
    }

    if (pep_flow_is_dead(flow)) {
        WRITE_ONCE(flow->adv_ack_timer_active, false);
        return HRTIMER_NORESTART;
    }

    spin_lock_irqsave(&flow->adv_ack_lock, flags);
    flow->adv_ack_timer_active = false;
    if (flow->adv_ack_pending_bytes > 0 && !flow->adv_ack_send_pending) {
        flow->adv_ack_send_pending = true;
        schedule = true;
    }
    spin_unlock_irqrestore(&flow->adv_ack_lock, flags);

    if (schedule)
        pep_schedule_wan_tx(flow);

    return HRTIMER_NORESTART;
}

/*
 * 功能/Main: 初始化pep_adv_ack_init相关逻辑（Initialize pep_adv_ack_init logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；定时器/工作队列上下文（timer/workqueue context）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
void pep_adv_ack_init(struct pep_flow *flow)
{
    if (!flow)
        return;

    hrtimer_init(&flow->adv_ack_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    flow->adv_ack_timer.function = pep_adv_ack_timer_callback;
    spin_lock_init(&flow->adv_ack_lock);
    flow->adv_ack_timer_active = false;
    flow->adv_ack_send_pending = false;
    flow->adv_ack_pending_bytes = 0;
    flow->adv_ack_pending_seq = 0;
    flow->adv_ack_last_time_ns = 0;
    flow->adv_ack_sent_count = 0;
}

/*
 * 功能/Main: 清理pep_adv_ack_cleanup相关逻辑（Cleanup pep_adv_ack_cleanup logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；定时器/工作队列上下文（timer/workqueue context）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
bool pep_adv_ack_cleanup(struct pep_flow *flow)
{
    if (!flow)
        return true;

    hrtimer_cancel(&flow->adv_ack_timer);

    flow->adv_ack_timer_active = false;
    flow->adv_ack_send_pending = false;
    return true;
}

/*
 * 功能/Main: 处理pep_schedule_advance_ack相关逻辑（Handle pep_schedule_advance_ack logic）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；定时器/工作队列上下文（timer/workqueue context）；并发同步（spinlock/atomic/rcu）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: flow, ack_seq, payload_len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_schedule_advance_ack(struct pep_flow *flow, u32 ack_seq, u32 payload_len)
{
    unsigned long flags;
    bool send_now = false;
    u32 timeout_us;
    ktime_t delay;

    if (!flow || !pep_ctx || payload_len == 0)
        return;

    if (test_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags))
        return;

    spin_lock_irqsave(&flow->adv_ack_lock, flags);

    flow->adv_ack_pending_bytes += payload_len;
    flow->adv_ack_pending_seq = ack_seq;

    /* v107: split_dl 模式下使用更激进的阈值 (2 MSS vs 4 MSS) */
    {
        struct pep_context *ctx_local = READ_ONCE(pep_ctx);
        u32 threshold = PEP_ADV_ACK_BYTES_THRESHOLD;
        if (ctx_local && ctx_local->config.split_dl_enabled)
            threshold = PEP_ADV_ACK_BYTES_THRESHOLD / 2;

        if (flow->adv_ack_pending_bytes >= threshold) {
            send_now = true;
            pep_dbg("Advance ACK: bytes threshold reached (%u >= %u)\n",
                    flow->adv_ack_pending_bytes, threshold);
        }
    }

    if (send_now) {
        if (flow->adv_ack_timer_active) {
            int ret = hrtimer_try_to_cancel(&flow->adv_ack_timer);
            if (ret >= 0)
                flow->adv_ack_timer_active = false;
        }
        flow->adv_ack_send_pending = true;
    } else if (!flow->adv_ack_timer_active && !flow->adv_ack_send_pending) {
        timeout_us = pep_adv_ack_get_timeout_us(flow);
        delay = ktime_set(0, timeout_us * 1000);
        hrtimer_start(&flow->adv_ack_timer, delay, HRTIMER_MODE_REL);
        flow->adv_ack_timer_active = true;
    }

    spin_unlock_irqrestore(&flow->adv_ack_lock, flags);

    if (send_now)
        pep_schedule_wan_tx(flow);
}

/*
 * 功能/Main: 处理pep_adv_ack_flush_pending相关逻辑（Handle pep_adv_ack_flush_pending logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 *
 * v91 优化: ACK Piggyback
 * - 如果 lan_to_wan 队列有待发送数据，跳过纯 ACK
 * - 下一个数据包会携带 ACK (piggyback)，避免双重 ACK
 */
static void pep_adv_ack_flush_pending(struct pep_flow *flow)
{
    unsigned long flags;
    u32 ack_seq = 0;
    bool pending = false;
    u32 queue_len;
    struct pep_context *ctx = READ_ONCE(pep_ctx);

    /*
     * v91 ACK Piggyback 优化:
     * 检查是否有待发送的上传数据，如果有，跳过纯 ACK
     * 因为接下来的数据包会携带 ACK
     *
     * v106: split_dl 模式下不跳过 — advance ACK 是加速核心机制，
     * 必须独立发送给服务器，不能依赖 piggyback
     */
    if (!ctx || !ctx->config.split_dl_enabled) {
        queue_len = pep_queue_len(&flow->lan_to_wan);
        if (queue_len > 0) {
            spin_lock_irqsave(&flow->adv_ack_lock, flags);
            if (flow->adv_ack_send_pending) {
                flow->adv_ack_send_pending = false;
                pep_dbg("Advance ACK: piggyback on data, skipping pure ACK (queue=%u)\n",
                        queue_len);
            }
            spin_unlock_irqrestore(&flow->adv_ack_lock, flags);
            return;
        }
    }

    spin_lock_irqsave(&flow->adv_ack_lock, flags);
    if (flow->adv_ack_send_pending) {
        if (flow->adv_ack_pending_bytes > 0) {
            ack_seq = flow->adv_ack_pending_seq;
            flow->adv_ack_pending_bytes = 0;
            pending = true;
        }
        flow->adv_ack_send_pending = false;
    }
    spin_unlock_irqrestore(&flow->adv_ack_lock, flags);

    if (pending) {
        if (pep_send_advance_ack(flow, ack_seq) == 0) {
            flow->adv_ack_sent_count++;
            flow->adv_ack_last_time_ns = ktime_get_ns();
            pep_dbg("Advance ACK sent: ack_seq=%u, total_sent=%llu\n",
                    ack_seq, flow->adv_ack_sent_count);
        }
    }
}

/*
 * 功能/Main: 发送pep_send_skb_with_dev相关逻辑（Send pep_send_skb_with_dev logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；并发同步（spinlock/atomic/rcu）；Netfilter 钩子处理（netfilter hook）；路由/本地注入处理（routing/injection）；校验和处理（checksum adjust）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: skb, in_dev
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
static int pep_send_skb_with_dev(struct sk_buff *skb, struct net_device *in_dev)
{
    struct pep_context *ctx;
    struct iphdr *iph;
    struct rtable *rt;
    struct flowi4 fl4;
    struct net_device *dev;
    int ret;
    bool is_local_dst;

    if (!skb)
        return -EINVAL;

    ctx = READ_ONCE(pep_ctx);
    if (!ctx || !atomic_read(&ctx->running)) {
        kfree_skb(skb);
        return -ESHUTDOWN;
    }

    iph = ip_hdr(skb);

    pep_dbg("pep_send_skb: sending to %pI4 from %pI4\n",
            &iph->daddr, &iph->saddr);

    is_local_dst = (inet_addr_type(&init_net, iph->daddr) == RTN_LOCAL);

    memset(&fl4, 0, sizeof(fl4));
    fl4.daddr = iph->daddr;
    fl4.saddr = 0;
    fl4.flowi4_proto = IPPROTO_TCP;
    fl4.flowi4_flags = FLOWI_FLAG_ANYSRC;

    rt = ip_route_output_key(&init_net, &fl4);
    if (IS_ERR(rt)) {
        pep_warn("Route lookup failed for %pI4: %ld\n",
                &iph->daddr, PTR_ERR(rt));
        kfree_skb(skb);
        return PTR_ERR(rt);
    }

    if (is_local_dst && in_dev && in_dev != rt->dst.dev) {
        dev = in_dev;
        pep_dbg("Using original interface %s instead of %s for local delivery\n",
                dev->name, rt->dst.dev->name);
    } else {
        dev = rt->dst.dev;
    }

    pep_dbg("Route found, dev=%s is_local=%d\n", dev ? dev->name : "NULL", is_local_dst);

    skb_dst_set(skb, &rt->dst);
    skb->dev = dev;

    if (skb_headroom(skb) < LL_RESERVED_SPACE(dev)) {
        struct sk_buff *skb2;

        skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
        if (!skb2) {
            pep_warn("Failed to realloc headroom\n");
            kfree_skb(skb);
            return -ENOMEM;
        }
        if (skb->sk)
            skb_set_owner_w(skb2, skb->sk);
        consume_skb(skb);
        skb = skb2;

        iph = ip_hdr(skb);
    }

    if (skb->ip_summed == CHECKSUM_PARTIAL &&
        (is_local_dst || !ctx->config.tx_csum_enabled ||
         skb->mark == PEP_SKB_MARK ||
         skb->mark == PEP_SKB_MARK_FAKE_ACK ||
         skb->mark == PEP_SKB_MARK_RETRANS)) {
        if (skb_checksum_help(skb)) {
            pep_warn("pep_send_skb: checksum help failed\n");
            kfree_skb(skb);
            return -EINVAL;
        }
    }

    if (is_local_dst) {

#ifdef CONFIG_NF_CONNTRACK
        nf_reset_ct(skb);
#endif
        skb->_nfct = 0;

        skb->pkt_type = PACKET_HOST;
        skb->ip_summed = CHECKSUM_UNNECESSARY;

        skb_reset_mac_header(skb);

        pep_dbg("Injecting packet via netif_rx to %s\n", dev->name);

        if (in_softirq()) {

            ret = netif_rx(skb);
        } else {

            local_bh_disable();
            ret = netif_rx(skb);
            local_bh_enable();
        }

        if (ret == NET_RX_SUCCESS) {
            pep_dbg("netif_rx success\n");
            ret = 0;
        } else {
            pep_warn("netif_rx failed: %d\n", ret);
            ret = -EIO;
        }
    } else {

#ifdef CONFIG_NF_CONNTRACK
        nf_reset_ct(skb);
#endif
        skb->_nfct = 0;

        skb->pkt_type = PACKET_OUTGOING;

        ret = ip_local_out(&init_net, NULL, skb);
        if (ret < 0) {
            pep_warn("ip_local_out failed: %d (dev=%s)\n",
                     ret, dev ? dev->name : "NULL");
        } else {
            pep_dbg("Packet sent successfully via %s\n",
                    dev ? dev->name : "NULL");
        }
    }

    return ret;
}

/*
 * 功能/Main: 发送pep_send_skb相关逻辑（Send pep_send_skb logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）
 * 输入/Inputs: 参数/Inputs: skb
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
static int pep_send_skb(struct sk_buff *skb)
{
    return pep_send_skb_with_dev(skb, NULL);
}

/*
 * 功能/Main: 发送pep_send_lan_skb相关逻辑（Send pep_send_lan_skb logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, skb
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
int pep_send_lan_skb(struct pep_flow *flow, struct sk_buff *skb)
{
    struct net_device *dev;

    if (!flow || !skb)
        return -EINVAL;

    dev = flow->out_dev;
    if (!dev && pep_ctx)
        dev = pep_ctx->lan_dev;

    if (dev && pep_ctx && pep_ctx->config.debug_level >= 2) {
        pr_info("pep: pep_send_lan_skb: using saved out_dev=%s\n", dev->name);
    }

    return pep_send_skb_with_dev(skb, dev);
}

/*
 * 功能/Main: 发送pep_send_wan_skb相关逻辑（Send pep_send_wan_skb logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；重传/缓存处理（retransmission/cache）；并发同步（spinlock/atomic/rcu）；Netfilter 钩子处理（netfilter hook）；路由/本地注入处理（routing/injection）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: skb
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
int pep_send_wan_skb(struct sk_buff *skb)
{
    struct pep_context *ctx;
    struct iphdr *iph;
    struct rtable *rt;
    struct flowi4 fl4;
    struct net_device *dev;
    int ret;

    if (!skb)
        return -EINVAL;

    ctx = READ_ONCE(pep_ctx);
    if (!ctx || !atomic_read(&ctx->running)) {
        kfree_skb(skb);
        return -ESHUTDOWN;
    }

    iph = ip_hdr(skb);

    memset(&fl4, 0, sizeof(fl4));
    fl4.daddr = iph->daddr;
    fl4.saddr = iph->saddr;
    fl4.flowi4_proto = iph->protocol;
    fl4.flowi4_flags = FLOWI_FLAG_ANYSRC;
    if (ctx && ctx->wan_dev)
        fl4.flowi4_oif = ctx->wan_dev->ifindex;

    rt = ip_route_output_key(&init_net, &fl4);
    if (IS_ERR(rt) && ctx && ctx->wan_dev) {
        fl4.flowi4_oif = 0;
        rt = ip_route_output_key(&init_net, &fl4);
    }
    if (IS_ERR(rt)) {
        pep_warn("WAN send: Route lookup failed for %pI4: %ld\n",
                &iph->daddr, PTR_ERR(rt));
        kfree_skb(skb);
        return PTR_ERR(rt);
    }

    dev = rt->dst.dev;
    skb_dst_set(skb, &rt->dst);
    skb->dev = dev;

    if (skb_headroom(skb) < LL_RESERVED_SPACE(dev)) {
        struct sk_buff *skb2;

        skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
        if (!skb2) {
            pep_warn("WAN send: Failed to realloc headroom\n");
            kfree_skb(skb);
            return -ENOMEM;
        }
        if (skb->sk)
            skb_set_owner_w(skb2, skb->sk);
        consume_skb(skb);
        skb = skb2;
    }

    if (skb->ip_summed == CHECKSUM_PARTIAL &&
        (!ctx || !ctx->config.tx_csum_enabled ||
         skb->mark == PEP_SKB_MARK ||
         skb->mark == PEP_SKB_MARK_FAKE_ACK ||
         skb->mark == PEP_SKB_MARK_RETRANS)) {
        if (skb_checksum_help(skb)) {
            pep_warn("WAN send: checksum help failed\n");
            kfree_skb(skb);
            return -EINVAL;
        }
    }

    skb->pkt_type = PACKET_OUTGOING;
    /* v107: preserve original PEP mark type (ACK/FAKE_ACK/RETRANS) */
    if ((skb->mark & 0xffffff00) != (PEP_SKB_MARK & 0xffffff00))
        skb->mark = PEP_SKB_MARK_RETRANS;

#ifdef CONFIG_NF_CONNTRACK
    nf_reset_ct(skb);
#endif
    skb->_nfct = 0;

    ret = ip_local_out(&init_net, NULL, skb);
    if (ret < 0) {
        pep_warn("WAN send: ip_local_out failed: %d\n", ret);
    }

    return ret;
}
EXPORT_SYMBOL(pep_send_wan_skb);

/*
 * 功能/Main: 处理pep_spoofing_handle_syn相关逻辑（Handle pep_spoofing_handle_syn logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；流表查找/创建/状态更新（flow lookup/create/update）；FEC 编码/映射/恢复（FEC encode/map/recover）；PMTU/MSS 更新（PMTU/MSS update）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: ctx, flow, skb, dir, out_dev
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
int pep_spoofing_handle_syn(struct pep_context *ctx, struct pep_flow *flow,
                             struct sk_buff *skb, enum pep_direction dir,
                             struct net_device *out_dev)
{
    struct sk_buff *synack;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len;

    if (!ctx || !flow || !skb)
        return -EINVAL;

    if (dir != PEP_DIR_LAN_TO_WAN)
        return 0;

    flow->out_dev = out_dev;
    if (out_dev && pep_ctx && pep_ctx->config.debug_level >= 2) {
        pr_info("pep: SYN handler: saved out_dev=%s for flow %pI4:%u -> %pI4:%u\n",
                out_dev->name,
                &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
                &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));
    }

    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

    flow->ecn_requested = (ctx && ctx->config.ecn_enabled &&
                           tcph->ece && tcph->cwr) ? 1 : 0;
    flow->lan.seq_una = ntohl(tcph->seq);
    flow->lan.seq_next = ntohl(tcph->seq) + 1;
    flow->lan.win = ntohs(tcph->window);

    if (tcph->doff > 5) {
        unsigned int tcp_hdr_len_full = tcph->doff * 4;

        if (!pskb_may_pull(skb, ip_hdr_len + tcp_hdr_len_full)) {
            pr_warn_ratelimited("pep: SYN: failed to pull TCP options, doff=%u\n",
                                tcph->doff);

            goto skip_syn_options;
        }

        iph = ip_hdr(skb);
        tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

        pep_parse_tcp_options(tcph, &flow->lan_opts);

        if (flow->lan_opts.mss > 0) {
            flow->mss = flow->lan_opts.mss;
            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                pr_info("pep: Client SYN: MSS=%u\n", flow->mss);
            }
        }

        if (flow->lan_opts.wscale > 0) {
            set_bit(PEP_FLOW_F_WSCALE_ENABLED_BIT, &flow->flags);
            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                pr_info("pep: Client SYN: Window Scale=%u (effective window multiplier=%u)\n",
                        flow->lan_opts.wscale, 1 << flow->lan_opts.wscale);
            }
        }

        if (flow->lan_opts.sack_ok) {
            set_bit(PEP_FLOW_F_SACK_ENABLED_BIT, &flow->flags);
            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                pr_info("pep: Client SYN: SACK Permitted\n");
            }
        }

        if (flow->lan_opts.ts_val != 0) {
            set_bit(PEP_FLOW_F_TIMESTAMP_BIT, &flow->flags);
            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                pr_info("pep: Client SYN: Timestamp enabled (ts_val=%u)\n",
                        flow->lan_opts.ts_val);
            }
        }
    }

skip_syn_options:
    pep_fec_adjust_mss(flow);

    synack = pep_create_fake_synack(flow);
    if (!synack) {
        pep_warn("Failed to create fake SYN-ACK\n");
        return -ENOMEM;
    }

    if (pep_send_skb_with_dev(synack, out_dev) < 0) {
        pep_warn("Failed to send fake SYN-ACK\n");
        return -EIO;
    }

    pep_stats_inc_fake_ack();
    flow->fake_acks_sent++;

    pep_dbg("Spoofing: SYN-ACK sent for %pI4:%u -> %pI4:%u\n",
            &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
            &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));

    return 0;
}

static struct sk_buff *

/*
 * 功能/Main: 处理pep_create_wan_data_ack相关逻辑（Handle pep_create_wan_data_ack logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；frag/分片结构处理（frag list handling）；访问/维护流状态（flow state access/maintenance）；并发同步（spinlock/atomic/rcu）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: flow, ack_seq
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
pep_create_wan_data_ack(struct pep_flow *flow, u32 ack_seq)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len = sizeof(struct iphdr);
    unsigned int tcp_hdr_len = sizeof(struct tcphdr);
    unsigned int total_len;
    unsigned int headroom;

    if (!flow)
        return NULL;

    headroom = LL_MAX_HEADER + ip_hdr_len;
    total_len = ip_hdr_len + tcp_hdr_len;

    skb = alloc_skb(headroom + total_len, GFP_ATOMIC);
    if (!skb)
        return NULL;

    skb_reserve(skb, headroom);
    skb_reset_network_header(skb);

    iph = skb_put(skb, ip_hdr_len);
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = 0;
    iph->frag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = flow->tuple.src_addr;
    iph->daddr = flow->tuple.dst_addr;

    skb_set_transport_header(skb, ip_hdr_len);
    tcph = skb_put(skb, tcp_hdr_len);
    memset(tcph, 0, tcp_hdr_len);

    tcph->source = flow->tuple.src_port;
    tcph->dest = flow->tuple.dst_port;
    tcph->seq = htonl(flow->wan_snd_nxt);
    tcph->ack_seq = htonl(ack_seq);
    tcph->doff = tcp_hdr_len / 4;
    tcph->ack = 1;
    tcph->window = htons(65535);

    pep_ecn_apply_wan_ack(flow, tcph);

    pep_update_ip_checksum(iph);
    pep_fast_tcp_checksum(skb, iph, tcph, pep_tx_csum_offload_enabled());

    skb->protocol = htons(ETH_P_IP);
    skb->mark = PEP_SKB_MARK;
    skb->priority = 0;

    return skb;
}

/*
 * 功能/Main: 处理pep_create_wan_ack相关逻辑（Handle pep_create_wan_ack logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；frag/分片结构处理（frag list handling）；访问/维护流状态（flow state access/maintenance）；并发同步（spinlock/atomic/rcu）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static struct sk_buff *pep_create_wan_ack(struct pep_flow *flow)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len = sizeof(struct iphdr);
    unsigned int tcp_hdr_len = sizeof(struct tcphdr);
    unsigned int total_len;
    unsigned int headroom;

    if (!flow)
        return NULL;

    headroom = LL_MAX_HEADER + ip_hdr_len;
    total_len = ip_hdr_len + tcp_hdr_len;

    skb = alloc_skb(headroom + total_len, GFP_ATOMIC);
    if (!skb)
        return NULL;

    skb_reserve(skb, headroom);
    skb_reset_network_header(skb);

    iph = skb_put(skb, ip_hdr_len);
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = 0;
    iph->frag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;

    iph->saddr = flow->tuple.src_addr;
    iph->daddr = flow->tuple.dst_addr;

    skb_set_transport_header(skb, ip_hdr_len);
    tcph = skb_put(skb, tcp_hdr_len);
    memset(tcph, 0, tcp_hdr_len);

    tcph->source = flow->tuple.src_port;
    tcph->dest = flow->tuple.dst_port;

    tcph->seq = htonl(flow->isn_pep_wan + 1);
    tcph->ack_seq = htonl(flow->wan.seq_una + 1);
    tcph->doff = tcp_hdr_len / 4;
    tcph->ack = 1;
    tcph->window = htons(65535);

    pep_ecn_apply_wan_ack(flow, tcph);

    pep_update_ip_checksum(iph);
    pep_fast_tcp_checksum(skb, iph, tcph, pep_tx_csum_offload_enabled());

    skb->protocol = htons(ETH_P_IP);
    skb->mark = PEP_SKB_MARK;
    skb->priority = 0;

    return skb;
}

/*
 * v89 新增: 创建 WAN 侧 FIN 包
 *
 * 功能/Main: 创建发送给 WAN 服务器的 FIN 包（Create FIN packet for WAN server）
 * 细节/Details: 当客户端发送 FIN 时，PEP 需要向 WAN 服务器也发送 FIN 以正确关闭连接
 *              FIN 消耗一个序列号，所以使用 wan_snd_nxt 作为 SEQ
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 创建 FIN+ACK 包用于优雅关闭 WAN 连接
 * 重要程度/Importance: 高/High
 */
static struct sk_buff *pep_create_wan_fin(struct pep_flow *flow)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len = sizeof(struct iphdr);
    unsigned int tcp_hdr_len = sizeof(struct tcphdr);
    unsigned int total_len;
    unsigned int headroom;

    if (!flow)
        return NULL;

    headroom = LL_MAX_HEADER + ip_hdr_len;
    total_len = ip_hdr_len + tcp_hdr_len;

    skb = alloc_skb(headroom + total_len, GFP_ATOMIC);
    if (!skb)
        return NULL;

    skb_reserve(skb, headroom);
    skb_reset_network_header(skb);

    iph = skb_put(skb, ip_hdr_len);
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = 0;
    iph->frag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;

    /* WAN 方向: src=client, dst=server */
    iph->saddr = flow->tuple.src_addr;
    iph->daddr = flow->tuple.dst_addr;

    skb_set_transport_header(skb, ip_hdr_len);
    tcph = skb_put(skb, tcp_hdr_len);
    memset(tcph, 0, tcp_hdr_len);

    tcph->source = flow->tuple.src_port;
    tcph->dest = flow->tuple.dst_port;

    /*
     * v89: FIN 包序列号处理
     * - SEQ: 使用 wan_snd_nxt (下一个要发送的序列号)
     * - ACK: 使用 wan.seq_next (期望从服务器收到的下一个序列号)
     * - FIN 消耗一个序列号，发送后 wan_snd_nxt 需要 +1
     */
    tcph->seq = htonl(flow->wan_snd_nxt);
    tcph->ack_seq = htonl(flow->wan.seq_next);
    tcph->doff = tcp_hdr_len / 4;
    tcph->fin = 1;  /* 设置 FIN 标志 */
    tcph->ack = 1;  /* FIN+ACK */
    tcph->window = htons(65535);

    pep_update_ip_checksum(iph);
    pep_fast_tcp_checksum(skb, iph, tcph, pep_tx_csum_offload_enabled());

    skb->protocol = htons(ETH_P_IP);
    skb->mark = PEP_SKB_MARK;
    skb->priority = 0;

    return skb;
}

/*
 * v89 新增: 发送 WAN 侧 FIN
 *
 * 功能/Main: 向 WAN 服务器发送 FIN 包（Send FIN to WAN server）
 * 细节/Details: 当客户端发送 FIN 时调用，实现完整的 Split-TCP 连接终止
 *              RFC 3135 要求 PEP 正确终止两侧连接
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 向 WAN 发送 FIN，设置 wan_state = PEP_WAN_FIN_WAIT
 * 重要程度/Importance: 高/High
 */
int pep_send_wan_fin(struct pep_flow *flow)
{
    struct sk_buff *skb;
    enum pep_wan_state ws;
    int ret;

    if (!flow)
        return -EINVAL;

    ws = READ_ONCE(flow->wan_state);

    /*
     * v102 关键修复: 允许在 ESTABLISHED 或 CLOSE_WAIT 状态发送 FIN
     *
     * 问题: 之前只在 wan_state == ESTABLISHED 时发送 FIN
     *       当服务器主动关闭时，wan_state 已经是 CLOSE_WAIT
     *       客户端发送 FIN 时，此函数直接返回 0，WAN FIN 永不发送
     *       导致 WAN 侧连接挂起，服务器等待超时
     *
     * 解决: 同时允许 ESTABLISHED 和 CLOSE_WAIT 状态
     *       - ESTABLISHED: 客户端主动关闭 → wan_state = FIN_WAIT
     *       - CLOSE_WAIT: 服务器主动关闭后客户端响应 → wan_state = CLOSED
     */
    if (ws != PEP_WAN_ESTABLISHED && ws != PEP_WAN_CLOSE_WAIT) {
        if (pep_ctx && pep_ctx->config.debug_level >= 1) {
            pr_info("pep: v102 pep_send_wan_fin: wan_state=%d, skipping (not ESTABLISHED or CLOSE_WAIT)\n", ws);
        }
        return 0;
    }

    skb = pep_create_wan_fin(flow);
    if (!skb) {
        pep_warn("Failed to create WAN FIN for %pI4:%u -> %pI4:%u\n",
                 &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
                 &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));
        return -ENOMEM;
    }

    ret = pep_send_wan_skb(skb);
    if (ret == 0) {
        /* FIN 消耗一个序列号 */
        flow->wan_snd_nxt++;

        /*
         * v102: 根据当前 wan_state 设置新状态
         * - ESTABLISHED → FIN_WAIT (客户端主动关闭)
         * - CLOSE_WAIT → CLOSED (服务器主动关闭后客户端响应，四次挥手完成)
         */
        if (ws == PEP_WAN_ESTABLISHED) {
            WRITE_ONCE(flow->wan_state, PEP_WAN_FIN_WAIT);
            pr_info("pep: v102 WAN FIN sent (client-initiated): %pI4:%u wan_state ESTABLISHED -> FIN_WAIT\n",
                    &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));
        } else {
            /* CLOSE_WAIT -> 发送 FIN 后进入 CLOSED */
            WRITE_ONCE(flow->wan_state, PEP_WAN_CLOSED);
            pr_info("pep: v102 WAN FIN sent (server-initiated response): %pI4:%u wan_state CLOSE_WAIT -> CLOSED\n",
                    &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));
        }
    } else {
        pep_warn("WAN FIN send failed: ret=%d\n", ret);
    }

    return ret;
}

/*
 * 功能/Main: 处理pep_spoofing_handle_synack相关逻辑（Handle pep_spoofing_handle_synack logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；FEC 编码/映射/恢复（FEC encode/map/recover）；RTT/RTO 估计（RTT/RTO estimation）；PMTU/MSS 更新（PMTU/MSS update）
 * 输入/Inputs: 参数/Inputs: ctx, flow, skb
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
int pep_spoofing_handle_synack(struct pep_context *ctx, struct pep_flow *flow,
                                struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct sk_buff *ack_skb;
    unsigned int ip_hdr_len;

    if (!ctx || !flow || !skb)
        return -EINVAL;

    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

    flow->isn_server = ntohl(tcph->seq);
    pep_stats_inc_wan_syn_synack();

    WRITE_ONCE(flow->seq_offset, (s32)(flow->isn_pep - flow->isn_server));

    flow->wan.seq_una = flow->isn_server;
    flow->wan.seq_next = flow->isn_server + 1;
    flow->wan.ack_seq = ntohl(tcph->ack_seq);

    if (flow->reseq_enabled) {
        unsigned long flags;

        spin_lock_irqsave(&flow->reseq_lock, flags);
        flow->reseq_next = flow->wan.seq_next;
        flow->reseq_initialized = 1;
        spin_unlock_irqrestore(&flow->reseq_lock, flags);
    }
    flow->wan.win = ntohs(tcph->window);

    {
        ktime_t now = ktime_get();
        s64 diff_ns = ktime_to_ns(ktime_sub(now, flow->create_time));

        if (diff_ns > 0 && diff_ns < 30000000000LL) {
            u32 wan_rtt_us = (u32)(diff_ns / 1000);
            pep_rtt_update(&flow->rtt, wan_rtt_us);
            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                pr_info("pep: Initial WAN RTT from handshake: %u us (%u ms)\n",
                        wan_rtt_us, wan_rtt_us / 1000);
            }
        }
    }

    if (tcph->doff > 5) {
        unsigned int tcp_hdr_len_full = tcph->doff * 4;

        if (!pskb_may_pull(skb, ip_hdr_len + tcp_hdr_len_full)) {
            pr_warn_ratelimited("pep: SYN-ACK: failed to pull TCP options, doff=%u\n",
                                tcph->doff);

            goto skip_synack_options;
        }

        iph = ip_hdr(skb);
        tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

        pep_parse_tcp_options(tcph, &flow->wan_opts);

        if (flow->wan_opts.wscale > 0) {
            flow->wan.wscale = flow->wan_opts.wscale;
            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                pr_info("pep: Server SYN-ACK: Window Scale=%u (effective window multiplier=%u)\n",
                        flow->wan.wscale, 1 << flow->wan.wscale);
            }
        }

        if (flow->wan_opts.mss > 0) {

            if (flow->mss == 0 || flow->wan_opts.mss < flow->mss) {
                flow->mss = flow->wan_opts.mss;
            }
            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                pr_info("pep: Server SYN-ACK: MSS=%u (effective MSS=%u)\n",
                        flow->wan_opts.mss, flow->mss);
            }
        }

        pep_pmtu_adjust_mss(flow);
    }

skip_synack_options:
    pep_fec_adjust_mss(flow);
    flow->ecn_ece_pending = 0;
    if (flow->ecn_requested && ctx->config.ecn_enabled && tcph->ece) {
        set_bit(PEP_FLOW_F_ECN_BIT, &flow->flags);
        flow->cc.ecn_state = PEP_ECN_STATE_OK;
    } else {
        clear_bit(PEP_FLOW_F_ECN_BIT, &flow->flags);
    }

    if (pep_ctx && pep_ctx->config.debug_level >= 2) {
        pr_info("pep: SYN-ACK from server %pI4, seq=%u ack=%u, "
                 "isn_pep=%u isn_server=%u seq_offset=%d wan.seq_next=%u\n",
                 &flow->tuple.dst_addr,
                 ntohl(tcph->seq), ntohl(tcph->ack_seq),
                 flow->isn_pep, flow->isn_server, flow->seq_offset,
                 flow->wan.seq_next);
    }

    ack_skb = pep_create_wan_ack(flow);
    if (ack_skb) {
        int ret = pep_send_wan_skb(ack_skb);
        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
            pr_info("pep: WAN ACK to server: seq=%u (isn_pep_wan+1) ack=%u ret=%d\n",
                    flow->isn_pep_wan + 1, flow->wan.seq_una + 1, ret);
        }
    } else {
        pr_warn("pep: Failed to create WAN ACK!\n");
    }

    pep_wan_syn_timer_stop(flow);
    flow->wan_snd_nxt = flow->isn_pep_wan + 1;
    WRITE_ONCE(flow->wan_state, PEP_WAN_ESTABLISHED);

    if (pep_ctx && pep_ctx->config.debug_level >= 2) {
        pr_info("pep: Complete Split-TCP: WAN connection ESTABLISHED to %pI4:%u "
                "(isn_pep_wan=%u, isn_server=%u, c2w_offset=%d)\n",
                &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port),
                flow->isn_pep_wan, flow->isn_server, flow->c2w_seq_offset);
    }

    if (pep_queue_len(&flow->lan_to_wan) > 0) {
        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
            pr_info("pep: v54 WAN ESTABLISHED: processing %u queued packets\n",
                    pep_queue_len(&flow->lan_to_wan));
        }
        pep_schedule_wan_tx(flow);
    }

    return 0;
}

/*
 * 功能/Main: 处理pep_spoofing_handle_ack相关逻辑（Handle pep_spoofing_handle_ack logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）
 * 输入/Inputs: 参数/Inputs: ctx, flow, skb, dir
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
int pep_spoofing_handle_ack(struct pep_context *ctx, struct pep_flow *flow,
                             struct sk_buff *skb, enum pep_direction dir)
{

    return pep_spoofing_handle_data(ctx, flow, skb, dir);
}

/*
 * 功能/Main: 发送pep_schedule_wan_tx相关逻辑（Send pep_schedule_wan_tx logic）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；并发同步（spinlock/atomic/rcu）；配置/参数应用（config/params）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
void pep_schedule_wan_tx(struct pep_flow *flow)
{
    if (!flow || !pep_ctx || !pep_ctx->wq) {
        pr_warn("pep: schedule_wan_tx: invalid params flow=%p ctx=%p\n",
                flow, pep_ctx);
        return;
    }

    if (!atomic_read(&pep_ctx->running))
        return;

    /*
     * v88 关键修复: 死亡流仍需调度以刷新队列数据
     *
     * 问题: 之前死亡流直接 return，但 lan_to_wan 队列中可能有数据等待发送
     *       如果新数据在 handler 运行期间入队，然后 DEAD_BIT 被设置，
     *       数据永远不会被发送（pep_schedule_wan_tx 拒绝调度）
     *
     * 解决: 只有当死亡流 且 队列为空时才跳过调度
     *       这确保死亡流的队列数据能够被完全刷新
     *       与 v87 pep_schedule_lan_tx 修复对称
     */
    if (test_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags) &&
        pep_queue_len(&flow->lan_to_wan) == 0)
        return;

    if (pep_ctx->config.sched_enabled) {
        if (atomic_cmpxchg(&flow->wan_tx_pending, 0, 1) == 0) {
            struct pep_scheduler *sched = NULL;

            pep_flow_get(flow);
            if (pep_ctx->engine_num > 0 && pep_ctx->sched_wan) {
                u32 idx = flow->engine_id % pep_ctx->engine_num;
                sched = &pep_ctx->sched_wan[idx];
            }
            if (sched) {
                pep_scheduler_enqueue(sched, flow);
            } else {
                /*
                 * v72: 调度器应该总是可用的
                 *
                 * pep_engine_init() 会自动将 engine_num=0 转换为 CPU 数量
                 * 所以当 sched_enabled=1 时，sched_wan/sched_lan 总是会被初始化
                 *
                 * 如果到达这里，说明配置有问题，记录警告并释放引用
                 */
                pr_warn_ratelimited("pep: schedule_wan_tx: no scheduler available (config error?)\n");
                atomic_set(&flow->wan_tx_pending, 0);
                pep_flow_put(flow);
            }
        }
        return;
    }

    if (atomic_cmpxchg(&flow->wan_tx_pending, 0, 1) == 0) {
        pep_flow_get(flow);

        if (!queue_work(pep_ctx->wq, &flow->wan_tx_work)) {
            atomic_set(&flow->wan_tx_pending, 0);
            pep_flow_put(flow);
            pr_warn_ratelimited("pep: schedule_wan_tx: queue_work failed\n");
            return;
        }
        pep_dbg("WAN TX Worker scheduled, queue_len=%u\n",
                pep_queue_len(&flow->lan_to_wan));
    } else {
        pep_dbg("WAN TX Worker already pending, queue_len=%u\n",
                pep_queue_len(&flow->lan_to_wan));
    }
}

/*
 * 功能/Main: 发送pep_schedule_lan_tx相关逻辑（Send pep_schedule_lan_tx logic）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；并发同步（spinlock/atomic/rcu）；配置/参数应用（config/params）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
void pep_schedule_lan_tx(struct pep_flow *flow)
{
    if (!flow || !pep_ctx || !pep_ctx->wq)
        return;

    if (!atomic_read(&pep_ctx->running))
        return;

    /*
     * v87 关键修复: 死亡流仍需调度以刷新队列数据
     *
     * 问题: 之前死亡流直接 return，但队列中可能有数据等待发送
     *       如果新数据在 handler 运行期间入队，然后 DEAD_BIT 被设置，
     *       数据永远不会被发送（pep_schedule_lan_tx 拒绝调度）
     *
     * 解决: 只有当死亡流 且 队列为空时才跳过调度
     *       这确保死亡流的队列数据能够被完全刷新
     */
    if (test_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags) &&
        pep_queue_len(&flow->wan_to_lan) == 0)
        return;

    if (pep_ctx->config.sched_enabled) {
        if (atomic_cmpxchg(&flow->lan_tx_pending, 0, 1) == 0) {
            struct pep_scheduler *sched = NULL;

            pep_flow_get(flow);
            if (pep_ctx->engine_num > 0 && pep_ctx->sched_lan) {
                u32 idx = flow->engine_id % pep_ctx->engine_num;
                sched = &pep_ctx->sched_lan[idx];
            }
            if (sched) {
                pep_scheduler_enqueue(sched, flow);
            } else {
                /*
                 * v72: 调度器应该总是可用的
                 *
                 * pep_engine_init() 会自动将 engine_num=0 转换为 CPU 数量
                 * 所以当 sched_enabled=1 时，sched_wan/sched_lan 总是会被初始化
                 *
                 * 如果到达这里，说明配置有问题，记录警告并释放引用
                 */
                pr_warn_ratelimited("pep: schedule_lan_tx: no scheduler available (config error?)\n");
                atomic_set(&flow->lan_tx_pending, 0);
                pep_flow_put(flow);
            }
        }
        return;
    }

    if (atomic_cmpxchg(&flow->lan_tx_pending, 0, 1) == 0) {
        pep_flow_get(flow);

        if (!queue_work(pep_ctx->wq, &flow->lan_tx_work)) {
            atomic_set(&flow->lan_tx_pending, 0);
            pep_flow_put(flow);
            pr_warn_ratelimited("pep: schedule_lan_tx: queue_work failed\n");
            return;
        }
    }
}

/*
 * 功能/Main: 处理pep_create_wan_data_packet相关逻辑（Handle pep_create_wan_data_packet logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；frag/分片结构处理（frag list handling）；访问/维护流状态（flow state access/maintenance）；并发同步（spinlock/atomic/rcu）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: flow, data, data_len, seq
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static struct sk_buff *pep_create_wan_data_packet(struct pep_flow *flow,
                                                   void *data, u32 data_len,
                                                   u32 seq)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len = sizeof(struct iphdr);
    unsigned int tcp_hdr_len = sizeof(struct tcphdr);
    unsigned int total_len;
    unsigned int headroom;

    if (!flow || !data || data_len == 0)
        return NULL;

    headroom = LL_MAX_HEADER + ip_hdr_len;
    total_len = ip_hdr_len + tcp_hdr_len + data_len;

    skb = alloc_skb(headroom + total_len, GFP_ATOMIC);
    if (!skb)
        return NULL;

    skb_reserve(skb, headroom);
    skb_reset_network_header(skb);

    iph = skb_put(skb, ip_hdr_len);
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = 0;
    iph->frag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;

    iph->saddr = flow->tuple.src_addr;
    iph->daddr = flow->tuple.dst_addr;

    skb_set_transport_header(skb, ip_hdr_len);
    tcph = skb_put(skb, tcp_hdr_len);
    memset(tcph, 0, tcp_hdr_len);

    tcph->source = flow->tuple.src_port;
    tcph->dest = flow->tuple.dst_port;
    tcph->seq = htonl(seq);
    tcph->ack_seq = htonl(flow->wan.seq_next);
    tcph->doff = tcp_hdr_len / 4;
    tcph->ack = 1;
    tcph->psh = 1;
    tcph->window = htons(65535);

    pep_ecn_apply_wan_tx(flow, iph, tcph);

    pep_dbg("WAN DATA PKT: seq=%u ack_seq=%u (wan.seq_next) isn_server=%u isn_pep=%u\n",
            seq, flow->wan.seq_next, flow->isn_server, flow->isn_pep);

    skb_put_data(skb, data, data_len);

    pep_update_ip_checksum(iph);
    pep_fast_tcp_checksum(skb, iph, tcph, pep_tx_csum_offload_enabled());

    skb->protocol = htons(ETH_P_IP);
    skb->mark = PEP_SKB_MARK;
    skb->priority = 0;

    return skb;
}

#define PEP_WAN_MSS_DEFAULT 1460

/*
 * 功能/Main: 发送工作队列任务（Send workqueue task）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；frag/分片结构处理（frag list handling）；流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；ACK pacing 调度（ACK pacing scheduling）
 * 输入/Inputs: 参数/Inputs: work
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
void pep_wan_tx_work_handler(struct work_struct *work)
{
    struct pep_flow *flow = container_of(work, struct pep_flow, wan_tx_work);
    struct sk_buff *skb, *tx_skb;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len, tcp_hdr_len;
    unsigned int payload_len;
    unsigned char *payload;
    u32 send_window;
    int sent = 0;
    u32 queue_len_start;

    if (!flow || test_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags)) {
        if (flow) {
            atomic_set(&flow->wan_tx_pending, 0);
            pep_flow_put(flow);
        }
        return;
    }

    if (flow->tlp.is_pending) {
        pep_tlp_send_probe(flow);
    }

    /*
     * v93 关键修复: 允许 closing 状态的流发送队列数据
     *
     * 问题: 之前只允许 ESTABLISHED 状态发送数据
     *       当连接进入 FIN_WAIT 或 CLOSE_WAIT 时，队列中的数据被丢弃
     *       导致 NS_BINDING_ABORTED 错误
     *
     * 解决: 对于 ESTABLISHED, CLOSE_WAIT, FIN_WAIT 状态都允许发送
     *       只有 CLOSED 和 SYN_SENT 状态才需要延迟
     *
     * 状态说明:
     *   CLOSED (0)       - 未连接，需要等待
     *   SYN_SENT (1)     - 等待 SYN-ACK，需要重传 SYN 或等待
     *   ESTABLISHED (2)  - 正常发送数据 ✓
     *   CLOSE_WAIT (3)   - 服务器关闭，但可以继续发送数据 ✓ (v92)
     *   FIN_WAIT (4)     - 我们发起关闭，但队列可能还有数据 ✓ (v93)
     */
    {
        enum pep_wan_state ws = READ_ONCE(flow->wan_state);

        /* 只有 SYN_SENT 需要特殊处理（重传或等待） */
        if (ws == PEP_WAN_SYN_SENT) {
            if (READ_ONCE(flow->wan_syn_retransmit)) {
                WRITE_ONCE(flow->wan_syn_retransmit, 0);
                pep_stats_inc_wan_syn_retransmit_sent();
                pep_dbg("WAN TX Worker: retransmit SYN for %pI4:%u -> %pI4:%u\n",
                        &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
                        &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));
                pep_wan_syn_send(flow, NULL);
            } else {
                pep_dbg("WAN TX Worker: wan_state=SYN_SENT, waiting for SYN-ACK\n");
            }

            /*
             * v75 关键修复: 提前退出时检查队列并重新调度
             */
            atomic_set(&flow->wan_tx_pending, 0);

            /* 检查 wan_state 是否在我们检查后变为可发送状态 */
            ws = READ_ONCE(flow->wan_state);
            if (ws >= PEP_WAN_ESTABLISHED && ws <= PEP_WAN_FIN_WAIT &&
                pep_queue_len(&flow->lan_to_wan) > 0 &&
                !test_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags)) {
                pep_dbg("WAN TX Worker: wan_state became %d, re-scheduling\n", ws);
                pep_schedule_wan_tx(flow);
            }

            pep_flow_put(flow);
            return;
        }

        /* CLOSED 状态不发送数据 */
        if (ws == PEP_WAN_CLOSED) {
            pep_dbg("WAN TX Worker: wan_state=CLOSED, dropping\n");
            atomic_set(&flow->wan_tx_pending, 0);
            pep_flow_put(flow);
            return;
        }

        /* v93/v105: ESTABLISHED, CLOSE_WAIT, FIN_WAIT, TIME_WAIT 都可以继续发送队列数据 */
        if (ws == PEP_WAN_CLOSE_WAIT || ws == PEP_WAN_FIN_WAIT || ws == PEP_WAN_TIME_WAIT) {
            pep_dbg("WAN TX Worker: wan_state=%d (closing), flushing queue\n", ws);
        }
    }

    pep_adv_ack_flush_pending(flow);

    queue_len_start = pep_queue_len(&flow->lan_to_wan);

    send_window = pep_cc_get_send_window(&flow->cc);

    pep_dbg("WAN TX Worker: queue=%u, window=%u, in_flight=%u, cwnd=%u\n",
            queue_len_start, send_window, flow->cc.bytes_in_flight, flow->cc.cwnd);

    if (!pep_pacing_can_send(flow)) {
        pep_pacing_schedule(flow);
        atomic_set(&flow->wan_tx_pending, 0);
        pep_flow_put(flow);
        return;
    }

    while (send_window > 0 && pep_pacing_can_send(flow)) {
        bool fully_processed = false;

        if (test_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags))
            break;

        skb = pep_queue_dequeue(&flow->lan_to_wan);
        if (!skb)
            break;

        if (skb_linearize(skb)) {
            pr_warn_ratelimited("pep: WAN TX: failed to linearize skb len=%u, dropping\n",
                                skb->len);
            kfree_skb(skb);
            pep_stats_inc_dropped();
            continue;
        }

        iph = ip_hdr(skb);
        ip_hdr_len = iph->ihl * 4;
        tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
        tcp_hdr_len = tcph->doff * 4;
        payload_len = ntohs(iph->tot_len) - ip_hdr_len - tcp_hdr_len;
        payload = (unsigned char *)tcph + tcp_hdr_len;

        if (payload_len > 0) {

            struct pep_skb_cb *skb_cb = pep_skb_cb(skb);
            u32 wan_seq;
            u32 offset = 0;
            u32 mss;
            bool already_translated = (skb_cb->flags & PEP_SKB_F_WAN_SEQ);

            if (already_translated) {

                wan_seq = ntohl(tcph->seq);
                pep_dbg("WAN TX DEQUEUE (REQUEUED): wan_seq=%u payload_len=%u (no translation)\n",
                        wan_seq, payload_len);
            } else {

                u32 client_seq = ntohl(tcph->seq);
                wan_seq = client_seq + flow->c2w_seq_offset;
                pep_dbg("WAN TX DEQUEUE: client_seq=%u -> wan_seq=%u (c2w_offset=%d) payload_len=%u\n",
                        client_seq, wan_seq, flow->c2w_seq_offset, payload_len);
            }

            mss = flow->mss;
            if (mss == 0)
                mss = PEP_WAN_MSS_DEFAULT;

            if (pep_ctx && pep_ctx->config.gso_enabled && pep_gso_needed(skb, mss)) {
                struct sk_buff *segs, *seg, *next;
                u32 seg_offset = 0;

                pep_dbg("WAN TX: Using GSO for large packet (%u bytes)\n", payload_len);

                pep_ecn_apply_wan_tx(flow, iph, tcph);
                pep_update_ip_checksum(iph);
                pep_fast_tcp_checksum(skb, iph, tcph, pep_tx_csum_offload_enabled());

                segs = pep_gso_segment(flow, skb, mss);
                if (!segs) {
                    pep_warn("WAN TX: GSO segmentation failed\n");
                    kfree_skb(skb);
                    continue;
                }

                for (seg = segs; seg; seg = next) {
                    struct iphdr *seg_iph;
                    struct tcphdr *seg_tcph;
                    u32 seg_len, seg_seq;

                    next = seg->next;
                    seg->next = NULL;

                    seg_iph = ip_hdr(seg);
                    seg_tcph = (struct tcphdr *)((unsigned char *)seg_iph + seg_iph->ihl * 4);
                    seg_len = ntohs(seg_iph->tot_len) - seg_iph->ihl * 4 - seg_tcph->doff * 4;
                    seg_seq = wan_seq + seg_offset;

                    if (flow->cc.bytes_in_flight >= flow->cc.cwnd) {

                        pep_dbg("WAN TX: cwnd full, requeuing GSO segments\n");
                        while (seg) {
                            next = seg->next;
                            seg->next = NULL;

                            spin_lock(&flow->lan_to_wan.lock);
                            __skb_queue_head(&flow->lan_to_wan.queue, seg);
                            flow->lan_to_wan.bytes += seg->len;
                            flow->lan_to_wan.packets++;
                            spin_unlock(&flow->lan_to_wan.lock);
                            seg = next;
                        }
                        break;
                    }

                    if (pep_ctx && !pep_shaper_allow(&pep_ctx->shaper_lan_wan, seg_len)) {
                        pep_dbg("WAN TX: shaper limit, requeuing GSO segments\n");

                        while (seg) {
                            next = seg->next;
                            seg->next = NULL;
                            spin_lock(&flow->lan_to_wan.lock);
                            __skb_queue_head(&flow->lan_to_wan.queue, seg);
                            flow->lan_to_wan.bytes += seg->len;
                            flow->lan_to_wan.packets++;
                            spin_unlock(&flow->lan_to_wan.lock);
                            seg = next;
                        }
                        break;
                    }

                    seg_tcph->seq = htonl(seg_seq);

                    if (pep_retrans_queue_skb(flow, seg, seg_seq, seg_len) < 0) {
                        pr_warn("pep: WAN TX: GSO RTX enqueue failed seq=%u len=%u\n",
                                seg_seq, seg_len);
                        kfree_skb(seg);
                        continue;
                    }

                    if (flow->fec.enabled) {
                        struct sk_buff *fec_input = skb_clone(seg, GFP_ATOMIC);
                        if (!fec_input) {
                            pr_warn("pep: WAN TX GSO: FEC clone failed seq=%u len=%u\n",
                                    seg_seq, seg_len);
                        } else {
                            int fec_ret = pep_fec_encoder_add_packet(flow, fec_input,
                                                                      seg_seq, seg_len);
                            kfree_skb(fec_input);

                            if (fec_ret == 1) {
                                struct sk_buff *fec_skb = pep_fec_encoder_generate(flow);
                                if (fec_skb) {
                                    u32 fec_len = fec_skb->len;

                                    if (pep_ctx &&
                                        !pep_shaper_allow(&pep_ctx->shaper_lan_wan, fec_len)) {
                                        pep_dbg("WAN TX GSO: shaper limit, dropping FEC\n");
                                        kfree_skb(fec_skb);
                                    } else {
                                        int fec_send_ret = pep_send_wan_skb(fec_skb);
                                        if (fec_send_ret == 0) {
                                            if (pep_ctx) {
                                                pep_shaper_consume(&pep_ctx->shaper_lan_wan, fec_len);
                                            }
                                            pep_dbg("WAN TX GSO: FEC sent len=%u\n", fec_len);
                                        } else {
                                            pr_warn("pep: WAN TX GSO: FEC send failed ret=%d\n",
                                                    fec_send_ret);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (pep_send_wan_skb(seg) == 0) {
                        flow->wan_snd_nxt = seg_seq + seg_len;
                        flow->cc.bytes_sent += seg_len;
                        sent++;
                        seg_offset += seg_len;

                        pep_pacing_packet_sent(flow, seg_len);
                        if (pep_ctx) {
                            pep_shaper_consume(&pep_ctx->shaper_lan_wan, seg_len);
                        }

                        pep_dbg("WAN TX: GSO sent segment seq=%u len=%u\n", seg_seq, seg_len);
                    }
                }

                if (segs != skb)
                    kfree_skb(skb);
                offset = payload_len;

            } else {

                while (offset < payload_len && flow->cc.bytes_in_flight < flow->cc.cwnd) {
                    u32 seg_len = min_t(u32, payload_len - offset, mss);
                    u32 seg_seq = wan_seq + offset;

                    if (test_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags))
                        break;

                    if (pep_ctx && !pep_shaper_allow(&pep_ctx->shaper_lan_wan, seg_len)) {
                        pep_dbg("WAN TX: shaper rate limit, waiting (seg_len=%u)\n", seg_len);
                        break;
                    }

                /*
                 * v81: 快速路径 - 直连模式下保留原始 TCP 选项
                 *
                 * 问题: pep_create_wan_data_packet() 创建的包只有 20 字节 TCP 头
                 *       不包含 Timestamp 选项。如果客户端 SYN 协商了 Timestamp，
                 *       根据 RFC 7323 PAWS 规则，服务器会静默丢弃没有 Timestamp 的包
                 *
                 * 解决: 在直连模式 (c2w_seq_offset==0) 且不需要分段时，
                 *       直接修改原始包，保留所有 TCP 选项（包括 Timestamp）
                 *
                 * 条件:
                 *   1. c2w_seq_offset == 0 (直连模式，不需要 seq 转换)
                 *   2. offset == 0 && seg_len == payload_len (整包发送，不分段)
                 *   3. !already_translated (还没被处理过)
                 */
                /*
                 * v82: 直连模式快速路径（修复 v81 校验和 bug）
                 *
                 * v81 问题: 调用 pep_ecn_apply_wan_tx() 后没有重新计算校验和
                 *          - ECN 修改 iph->tos 但 IP 校验和没更新
                 *          - ECN 可能修改 tcph->cwr 但 TCP 校验和没更新
                 *
                 * v82 解决: 修改 ack_seq 和应用 ECN 后，重新计算 IP/TCP 校验和
                 */
                if (flow->c2w_seq_offset == 0 && offset == 0 && seg_len == payload_len &&
                    !already_translated) {
                    /* 直接使用原始 skb，只修改必要字段 */
                    u32 old_ack = ntohl(tcph->ack_seq);
                    u32 new_ack = flow->wan.seq_next;

                    if (skb_ensure_writable(skb, ip_hdr_len + tcp_hdr_len)) {
                        pr_warn("pep: WAN TX v82: failed to make skb writable\n");
                        kfree_skb(skb);
                        break;
                    }

                    /* 重新获取指针 (skb_ensure_writable 可能重新分配) */
                    iph = ip_hdr(skb);
                    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

                    /* 更新 ack_seq */
                    tcph->ack_seq = htonl(new_ack);

                    /* 应用 ECN（可能修改 iph->tos 和 tcph->cwr）*/
                    pep_ecn_apply_wan_tx(flow, iph, tcph);

                    /*
                     * v82 关键修复: 重新计算校验和
                     *
                     * 必须在所有修改（ack_seq, TOS, CWR）完成后重新计算
                     * 使用与 pep_create_wan_data_packet 相同的方法确保一致性
                     */
                    pep_update_ip_checksum(iph);
                    pep_fast_tcp_checksum(skb, iph, tcph, pep_tx_csum_offload_enabled());

                    /* 设置 skb 标记 */
                    skb->mark = PEP_SKB_MARK;

                    pep_dbg("WAN TX v82: direct forward, ack %u->%u, tcp_hdr_len=%u\n",
                            old_ack, new_ack, tcp_hdr_len);

                    tx_skb = skb;
                    skb = NULL;  /* 防止后面 kfree_skb */
                } else {
                    pep_dbg("WAN TX: using pep_create_wan_data_packet, c2w_off=%d offset=%u\n",
                            flow->c2w_seq_offset, offset);
                    tx_skb = pep_create_wan_data_packet(flow, payload + offset, seg_len, seg_seq);
                }
                if (tx_skb) {
                    int send_ret;
                    struct sk_buff *fec_input = NULL;
                    u32 pmtu_required;

                    pmtu_required = pep_pmtu_check_fragmentation(tx_skb, flow->tuple.dst_addr);
                    if (pmtu_required > 0) {
                        pep_dbg("WAN TX: Packet exceeds PMTU (%u bytes), required=%u\n",
                                tx_skb->len, pmtu_required);

                        if (pep_pmtu_send_icmp_frag_needed(tx_skb, pmtu_required) < 0) {
                            pep_warn("WAN TX: Failed to send ICMP Frag Needed\n");
                        }

                        pep_pmtu_update(flow->tuple.dst_addr, pmtu_required);

                        u32 new_mss = pmtu_required - 40;
                        if (flow->mss > new_mss) {
                            flow->mss = new_mss;
                            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                                pr_info("pep: WAN TX: PMTU adjusted MSS to %u for flow %pI4:%u\n",
                                        new_mss, &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));
                            }
                        }
                        pep_fec_adjust_mss(flow);

                        kfree_skb(tx_skb);
                        break;
                    }

                    if (pep_retrans_queue_skb(flow, tx_skb, seg_seq, seg_len) < 0) {
                        pr_warn("pep: WAN TX: RTX enqueue failed seq=%u len=%u, NOT sending\n",
                                seg_seq, seg_len);
                        kfree_skb(tx_skb);
                        break;
                    }

                    if (flow->fec.enabled) {
                        fec_input = skb_clone(tx_skb, GFP_ATOMIC);
                        if (!fec_input) {
                            pr_warn("pep: WAN TX: FEC clone failed seq=%u len=%u\n",
                                    seg_seq, seg_len);
                        }
                    }

                    send_ret = pep_send_wan_skb(tx_skb);
                    if (send_ret == 0) {
                        flow->wan_snd_nxt = seg_seq + seg_len;
                        flow->cc.bytes_sent += seg_len;
                        sent++;
                        offset += seg_len;

                        pep_pacing_packet_sent(flow, seg_len);

                        if (pep_ctx) {
                            pep_shaper_consume(&pep_ctx->shaper_lan_wan, seg_len);
                        }

                        if (fec_input) {
                            int fec_ret = pep_fec_encoder_add_packet(flow, fec_input,
                                                                      seg_seq, seg_len);
                            kfree_skb(fec_input);
                            fec_input = NULL;

                            if (fec_ret == 1) {
                                struct sk_buff *fec_skb = pep_fec_encoder_generate(flow);

                                if (fec_skb) {
                                    u32 fec_len = fec_skb->len;

                                    if (pep_ctx &&
                                        !pep_shaper_allow(&pep_ctx->shaper_lan_wan, fec_len)) {
                                        pep_dbg("WAN TX: shaper rate limit, dropping FEC (len=%u)\n",
                                                fec_len);
                                        kfree_skb(fec_skb);
                                    } else {
                                        int fec_send_ret = pep_send_wan_skb(fec_skb);

                                        if (fec_send_ret == 0) {
                                            if (pep_ctx) {
                                                pep_shaper_consume(&pep_ctx->shaper_lan_wan, fec_len);
                                            }
                                        } else {
                                            pr_warn("pep: WAN TX: FEC send failed ret=%d len=%u\n",
                                                    fec_send_ret, fec_len);
                                        }
                                    }
                                }
                            } else if (fec_ret < 0) {
                                pr_warn("pep: WAN TX: FEC encode failed ret=%d seq=%u len=%u\n",
                                        fec_ret, seg_seq, seg_len);
                            }
                        }

                        if (seg_len < payload_len) {

                            if (offset == seg_len) {
                                pep_dbg("WAN TX: segmenting %u bytes into MSS chunks, wan_seq=%u\n",
                                        payload_len, wan_seq);
                            }
                        } else {
                            pep_dbg("WAN TX: sent %u bytes, seq=%u, in_flight=%u\n",
                                    seg_len, seg_seq, flow->cc.bytes_in_flight);
                        }
                    } else {
                        if (fec_input) {
                            kfree_skb(fec_input);
                        }
                        pr_warn("pep: WAN TX: send failed ret=%d seq=%u len=%u\n",
                                send_ret, seg_seq, seg_len);
                        break;
                    }
                } else {
                    pr_warn("pep: WAN TX: failed to create packet seq=%u len=%u\n",
                            seg_seq, seg_len);
                    break;
                }
            }
            }

            if (offset >= payload_len) {
                fully_processed = true;
            } else {

                struct sk_buff *remaining_skb;
                u32 remaining_len = payload_len - offset;
                u32 remaining_seq = wan_seq + offset;

                pep_dbg("WAN TX: partial send, saving %u bytes at seq=%u for later\n",
                        remaining_len, remaining_seq);

                remaining_skb = pep_create_wan_data_packet(flow,
                                                            payload + offset,
                                                            remaining_len,
                                                            remaining_seq);
                if (remaining_skb) {

                    struct pep_skb_cb *remaining_cb = pep_skb_cb(remaining_skb);
                    remaining_cb->flags |= PEP_SKB_F_WAN_SEQ;
                    remaining_cb->seq = remaining_seq;
                    remaining_cb->len = remaining_len;

                    unsigned long requeue_flags;
                    spin_lock_irqsave(&flow->lan_to_wan.lock, requeue_flags);
                    __skb_queue_head(&flow->lan_to_wan.queue, remaining_skb);
                    flow->lan_to_wan.bytes += remaining_skb->len;
                    flow->lan_to_wan.packets++;
                    spin_unlock_irqrestore(&flow->lan_to_wan.lock, requeue_flags);

                    pep_dbg("WAN TX: remaining %u bytes re-queued (skb_len=%u, WAN_SEQ marked), queue_len=%u\n",
                            remaining_len, remaining_skb->len, pep_queue_len(&flow->lan_to_wan));
                } else {
                    pr_err("pep: WAN TX: CRITICAL - failed to save remaining %u bytes, DATA LOST!\n",
                           remaining_len);
                }
                fully_processed = true;
            }
        } else {
            fully_processed = true;
        }

        if (fully_processed) {
            kfree_skb(skb);
        } else {

            unsigned long fallback_flags;
            pr_warn("pep: WAN TX: unexpected state, re-queuing original skb\n");
            spin_lock_irqsave(&flow->lan_to_wan.lock, fallback_flags);
            __skb_queue_head(&flow->lan_to_wan.queue, skb);
            flow->lan_to_wan.bytes += skb->len;
            flow->lan_to_wan.packets++;
            spin_unlock_irqrestore(&flow->lan_to_wan.lock, fallback_flags);
            break;
        }

        send_window = pep_cc_get_send_window(&flow->cc);

        cond_resched();
    }

    atomic_set(&flow->wan_tx_pending, 0);

    /*
     * v88 关键修复: 移除死亡流检查，允许死亡流重新调度
     *
     * 问题: 之前只对非死亡流重新调度，但如果在 handler 处理期间：
     *       1. handler 检查 DEAD_BIT 为 false，开始处理
     *       2. 新数据入队，pep_schedule_wan_tx() 的 cmpxchg 失败
     *       3. RST 到达，DEAD_BIT 被设置
     *       4. handler 完成，到达这里，因为 is_dead 为 true 所以不重新调度
     *       5. 数据被永久遗留在 lan_to_wan 队列中
     *
     * 解决: 移除死亡流检查，让 pep_schedule_wan_tx() 的 v88 修复决定是否调度
     *       pep_schedule_wan_tx() 现在只在死亡流 且 队列为空时才拒绝调度
     *       与 v87 pep_lan_tx_work_handler 修复对称
     */
    if (pep_queue_len(&flow->lan_to_wan) > 0) {
        pep_schedule_wan_tx(flow);
    }

    /*
     * v103 优化: TIME_WAIT 状态下，缓冲区为空时设置 DEAD_BIT
     * (与 pep_lan_tx_work_handler 中的修复对称)
     */
    if (flow->state == PEP_TCP_TIME_WAIT &&
        !pep_flow_is_dead(flow) &&
        pep_queue_len(&flow->wan_to_lan) == 0 &&
        pep_queue_len(&flow->lan_to_wan) == 0) {
        pr_info("pep: v103 TIME_WAIT buffers now empty (WAN TX), setting DEAD_BIT port=%u\n",
                ntohs(flow->tuple.src_port));
        set_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags);
    }

    if (sent > 0) {
        pep_tlp_schedule(flow);
    }

    pep_flow_put(flow);

    if (sent > 0) {
        pep_dbg("WAN TX Worker done: sent %d packets, queue_remaining=%u\n",
                sent, pep_queue_len(&flow->lan_to_wan));
    } else {
        pep_dbg("WAN TX Worker done: no packets sent, queue=%u, window=%u\n",
                pep_queue_len(&flow->lan_to_wan), send_window);
    }
}

/*
 * 功能/Main: 发送工作队列任务（Send workqueue task）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；ACK pacing 调度（ACK pacing scheduling）；带宽整形/速率限制（shaping/rate limit）
 * 输入/Inputs: 参数/Inputs: work
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
void pep_lan_tx_work_handler(struct work_struct *work)
{
    struct pep_flow *flow = container_of(work, struct pep_flow, lan_tx_work);
    struct sk_buff *skb;
    int sent = 0;
    bool is_dead;

    if (!flow) {
        return;
    }

    is_dead = pep_flow_is_dead(flow);

    /*
     * v86 关键修复: 即使 flow 已死亡，也要刷新 wan_to_lan 队列
     *
     * 问题: 之前当 flow 死亡时（RST 收到后），直接 return
     *       导致 wan_to_lan 队列中的数据丢失
     *       客户端收到 RST 但缺少之前的数据 → NS_ERROR_NET_INTERRUPT
     *
     * 解决: 先发送队列中的数据，再清理 flow
     *       只跳过 ACK pacer 等新数据操作
     */

    /* v86: 死亡流跳过 ACK pacer */
    if (!is_dead && flow->ack_pacer.is_pending) {
        struct pep_ack_pacer *pacer = &flow->ack_pacer;
        struct sk_buff *ack_skb;
        u32 pep_seq;

        pacer->is_pending = 0;

        if (pacer->bytes_received > 0) {
            pep_seq = flow->isn_pep + 1;
            ack_skb = pep_create_fake_ack(flow, pep_seq, pacer->pending_ack_seq);
            if (ack_skb) {

                if (pep_send_lan_skb(flow, ack_skb) == 0) {
                    pep_stats_inc_fake_ack();
                    flow->fake_acks_sent++;
                    pacer->acks_sent++;

                    pacer->last_ack_seq = pacer->pending_ack_seq;
                    pacer->last_ack_time_ns = ktime_get_ns();
                    pacer->bytes_received = 0;

                    if (pep_ctx && pep_ctx->config.debug_level >= 3) {
                        pr_info("pep: ACK Pacing: sent paced ACK seq=%u ack=%u (via LAN TX worker)\n",
                                pep_seq, pacer->pending_ack_seq);
                    }
                }
            }
        }
    }

    while (true) {
        struct sk_buff *rsc_result = NULL;
        bool from_rsc = false;
        u32 skb_len_saved;
        u32 payload_len = 0;
        u32 seq = 0;
        struct sk_buff *cache_skb = NULL;
        struct sk_buff *byte_cache_skb = NULL;

        skb = pep_queue_dequeue(&flow->wan_to_lan);
        if (!skb) {
            if (flow->rsc_enabled) {
                spin_lock(&flow->rsc_lock);
                skb = __skb_dequeue(&flow->rsc_queue);
                spin_unlock(&flow->rsc_lock);
                from_rsc = skb != NULL;
            }
            if (!skb)
                break;
        }

        if (pep_flow_is_dead(flow)) {
            /*
             * v86: 不要丢弃数据，继续发送
             *
             * 问题: 之前直接 kfree_skb(skb) 丢弃数据
             *       导致客户端收到 RST 但缺少之前的数据
             *
             * 解决: 继续发送数据，让 break 在发送后执行
             *       确保客户端收到完整数据后再处理 RST
             */
        }

        if (!from_rsc && flow->rsc_enabled && pep_ctx && pep_ctx->config.rsc_enabled) {
            struct iphdr *rsc_iph;
            struct tcphdr *rsc_tcph;
            unsigned int rsc_ip_hdr_len;
            unsigned int rsc_tcp_hdr_len;
            unsigned int rsc_payload_len;
            u32 orig_len = skb->len;

            rsc_iph = ip_hdr(skb);
            rsc_ip_hdr_len = rsc_iph->ihl * 4;
            rsc_tcph = (struct tcphdr *)((unsigned char *)rsc_iph + rsc_ip_hdr_len);
            rsc_tcp_hdr_len = rsc_tcph->doff * 4;
            rsc_payload_len = ntohs(rsc_iph->tot_len) - rsc_ip_hdr_len - rsc_tcp_hdr_len;

            if (rsc_payload_len > 0 && !rsc_tcph->syn &&
                !rsc_tcph->fin && !rsc_tcph->rst) {
                spin_lock(&flow->rsc_lock);
                rsc_result = pep_gro_receive(flow, skb, &flow->rsc_queue,
                                             flow->rsc_max_size);
                spin_unlock(&flow->rsc_lock);

                if (rsc_result == NULL) {
                    flow->rsc_pkts_aggregated++;
                    flow->rsc_bytes_aggregated += orig_len;
                    continue;
                }
                if (!IS_ERR(rsc_result)) {
                    skb = rsc_result;
                }
            }
        }

        skb_len_saved = skb->len;

        /*
         * v86: 死亡流跳过 shaper 检查，立即发送数据
         *
         * 问题: 之前 shaper 限制触发时，数据包被重新入队并 break
         *       对于死亡流，不会重新调度 → 数据永远丢失
         *
         * 解决: 死亡流跳过 shaper 检查，确保数据发送
         */
        if (!is_dead && pep_ctx && !pep_shaper_allow(&pep_ctx->shaper_wan_lan, skb_len_saved)) {

            unsigned long requeue_flags;
            spin_lock_irqsave(&flow->wan_to_lan.lock, requeue_flags);
            __skb_queue_head(&flow->wan_to_lan.queue, skb);
            flow->wan_to_lan.bytes += skb_len_saved;
            flow->wan_to_lan.packets++;
            spin_unlock_irqrestore(&flow->wan_to_lan.lock, requeue_flags);
            break;
        }

        /*
         * v86: 死亡流跳过 retrans/byte cache 操作
         * 死亡流不需要缓存，减少开销
         */
        if (!is_dead && pep_ctx && (pep_ctx->config.local_retrans ||
                        pep_ctx->config.byte_cache_enabled)) {
            struct iphdr *iph = ip_hdr(skb);
            unsigned int ip_hdr_len = iph->ihl * 4;
            struct tcphdr *tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
            unsigned int tcp_hdr_len = tcph->doff * 4;

            payload_len = ntohs(iph->tot_len) - ip_hdr_len - tcp_hdr_len;
            seq = ntohl(tcph->seq);

            if (payload_len > 0) {
                if (pep_ctx->config.local_retrans)
                    cache_skb = skb_copy(skb, GFP_ATOMIC);
                if (pep_ctx->config.byte_cache_enabled)
                    byte_cache_skb = skb_copy(skb, GFP_ATOMIC);
            }
        }

        if (pep_send_lan_skb(flow, skb) == 0) {

            if (pep_ctx) {
                pep_shaper_consume(&pep_ctx->shaper_wan_lan, skb_len_saved);
            }
            sent++;
            if (payload_len > 0) {
                if (PEP_SEQ_AFTER(seq + payload_len, flow->lan_snd_nxt))
                    flow->lan_snd_nxt = seq + payload_len;
                if (cache_skb) {
                    pep_lan_retrans_cache_add(flow, cache_skb, seq, payload_len);
                    cache_skb = NULL;
                }
                if (byte_cache_skb) {
                    pep_byte_cache_add(flow, byte_cache_skb, seq, payload_len);
                    byte_cache_skb = NULL;
                }
            }
        } else {
            if (cache_skb)
                kfree_skb(cache_skb);
            if (byte_cache_skb)
                kfree_skb(byte_cache_skb);
        }

        cond_resched();
    }

    atomic_set(&flow->lan_tx_pending, 0);

    /*
     * v87 关键修复: 移除死亡流检查，允许死亡流重新调度
     *
     * 问题: 之前只对非死亡流重新调度，但如果在 handler 处理期间：
     *       1. handler 检查 DEAD_BIT 为 false，开始处理
     *       2. 新数据入队，pep_schedule_lan_tx() 的 cmpxchg 失败
     *       3. RST 到达，DEAD_BIT 被设置
     *       4. handler 完成，到达这里，因为 is_dead 为 true 所以不重新调度
     *       5. 数据被永久遗留在队列中
     *
     * 解决: 移除死亡流检查，让 pep_schedule_lan_tx() 的 v87 修复决定是否调度
     *       pep_schedule_lan_tx() 现在只在死亡流 且 队列为空时才拒绝调度
     */
    if (pep_queue_len(&flow->wan_to_lan) > 0) {
        pep_schedule_lan_tx(flow);
    }

    /*
     * v103 优化: TIME_WAIT 状态下，缓冲区为空时设置 DEAD_BIT
     *
     * 背景: v103 修复中，LAST_ACK+ACK 时如果缓冲区有数据，
     *       会进入 TIME_WAIT 而不是 CLOSED+DEAD
     *
     * 优化: 当数据传输完成（缓冲区为空）时，提前设置 DEAD_BIT
     *       不必等待 10 秒 GC 超时
     */
    if (flow->state == PEP_TCP_TIME_WAIT &&
        !pep_flow_is_dead(flow) &&
        pep_queue_len(&flow->wan_to_lan) == 0 &&
        pep_queue_len(&flow->lan_to_wan) == 0) {
        pr_info("pep: v103 TIME_WAIT buffers now empty, setting DEAD_BIT port=%u\n",
                ntohs(flow->tuple.src_port));
        set_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags);
    }

    pep_flow_put(flow);

    if (sent > 0) {
        pep_dbg("LAN TX: sent %d packets\n", sent);
    }
}

/*
 * 功能/Main: 处理pep_spoofing_handle_data相关逻辑（Handle pep_spoofing_handle_data logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；FEC 编码/映射/恢复（FEC encode/map/recover）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: ctx, flow, skb, dir
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
int pep_spoofing_handle_data(struct pep_context *ctx, struct pep_flow *flow,
                              struct sk_buff *skb, enum pep_direction dir)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len, tcp_hdr_len;
    unsigned int payload_len;
    u32 seq, ack_seq;

    if (!ctx || !flow || !skb)
        return -1;

    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
    tcp_hdr_len = tcph->doff * 4;
    payload_len = ntohs(iph->tot_len) - ip_hdr_len - tcp_hdr_len;
    seq = ntohl(tcph->seq);

    if (dir == PEP_DIR_LAN_TO_WAN) {

        pep_dbg("handle_data LAN->WAN: seq=%u payload=%u fake_ack=%d\n",
                seq, payload_len, ctx->config.fake_ack);

        if (payload_len == 0)
            return -1;

        if (!ctx->config.fake_ack) {

            pr_info_ratelimited("pep: handle_data: fake_ack disabled, passing through\n");
            return -1;
        }

        {
            struct sk_buff *clone;

            clone = skb_copy(skb, GFP_ATOMIC);
            if (!clone) {
                pr_warn("pep: Split-TCP: failed to clone skb\n");
                return -1;
            }

            pep_skb_cb(clone)->flags = 0;

            if (pep_queue_enqueue(&flow->lan_to_wan, clone) < 0) {
                pr_warn("pep: Split-TCP: queue full! len=%u bytes=%u effective_max=%u bdp=%u skb_len=%u\n",
                        pep_queue_len(&flow->lan_to_wan),
                        flow->lan_to_wan.bytes,
                        flow->lan_to_wan.effective_max,
                        flow->lan_to_wan.bdp_estimate,
                        clone->len);
                kfree_skb(clone);
                pep_stats_inc_dropped();
                return -1;
            }
        }

        ack_seq = seq + payload_len;

        if (PEP_SEQ_AFTER(ack_seq, flow->lan.ack_seq)) {
            flow->lan.ack_seq = ack_seq;
        }

        /*
         * v110: Send immediate fake ACK for upload — bypass ACK pacer.
         *
         * The ACK pacer batches multiple packets into one ACK (up to 8*MSS),
         * which dramatically slows the client's cwnd growth during upload:
         * client gets 1 ACK per 8 packets instead of 1 per packet, turning
         * exponential slow-start into near-linear growth.
         *
         * For upload, fake ACKs go via netif_rx (local delivery, zero network
         * cost), so there's no reason to batch them. Immediate ACKs let the
         * client's TCP stack grow cwnd normally.
         */
        {
            struct sk_buff *ack_skb;
            u32 pep_seq = flow->isn_pep + 1;

            ack_skb = pep_create_fake_ack(flow, pep_seq, ack_seq);
            if (ack_skb) {
                if (pep_send_lan_skb(flow, ack_skb) == 0) {
                    pep_stats_inc_fake_ack();
                    flow->fake_acks_sent++;
                    flow->ack_pacer.acks_sent++;
                    flow->ack_pacer.last_ack_seq = ack_seq;
                    flow->ack_pacer.last_ack_time_ns = ktime_get_ns();
                    flow->ack_pacer.bytes_received = 0;
                }
            }
        }

        pep_schedule_wan_tx(flow);

        pep_dbg("SPLIT_TCP LAN->WAN: %u bytes queued, seq=%u, queue_len=%u\n",
                payload_len, seq, pep_queue_len(&flow->lan_to_wan));

        return 0;

    } else {

        if (payload_len > 0) {

            u32 server_seq = seq - flow->seq_offset;
            u32 new_ack_seq = server_seq + payload_len;
            u32 contig_ack_seq = 0;
            bool ack_advanced = false;

            if (flow->reseq_enabled) {
                if (pep_reseq_update(flow, server_seq, payload_len, &contig_ack_seq)) {
                    if (PEP_SEQ_AFTER(contig_ack_seq, flow->wan.seq_next))
                        flow->wan.seq_next = contig_ack_seq;
                    ack_advanced = true;
                }
            } else if (PEP_SEQ_AFTER(new_ack_seq, flow->wan.seq_next)) {
                flow->wan.seq_next = new_ack_seq;
                contig_ack_seq = new_ack_seq;
                ack_advanced = true;
            }

            if (ack_advanced) {
                pep_dbg("WAN seq_next updated: %u (server space), translated_seq=%u\n",
                        flow->wan.seq_next, seq);

                if (ctx->config.aggressive_ack) {
                    /* v108: Always send advance ACK — cache uses forced eviction,
                     * no backpressure needed. Server never sees loss. */
                    pep_schedule_advance_ack(flow, flow->wan.seq_next, payload_len);
                }
            }

            if (ctx->config.downlink_reorder_enabled && flow->reorder_enabled) {
                if (pep_reorder_queue(flow, skb, seq, payload_len) == 0)
                    return 1;
            }

            /*
             * Split DL acceleration: clone skb, deliver clone to local TCP
             * stack via netif_rx (bypasses physical interface), consume
             * original via NF_STOLEN. PEP's advance ACK reaches server
             * faster than client's own ACK (which we filter in POST_ROUTING).
             */
            if (ctx->config.split_dl_enabled) {
                /* v108.2: No per-packet caching in split_dl path.
                 * split_dl delivers via netif_rx (local loopback) — no real
                 * network loss between PEP and client. Caching every packet
                 * at 89+ Mbps causes memory pressure that kills the network
                 * stack on sustained high-throughput tests.
                 * Advance ACK (above) is the real acceleration mechanism. */
                struct sk_buff *clone = skb_clone(skb, GFP_ATOMIC);
                if (clone) {
                    clone->mark = PEP_SKB_MARK;
                    clone->pkt_type = PACKET_HOST;
                    clone->ip_summed = CHECKSUM_UNNECESSARY;
                    skb_reset_mac_header(clone);
                    netif_rx(clone);
                }
                /* free original — caller returns NF_STOLEN */
                kfree_skb(skb);
                return 1;
            }

            return -1;
        }

        /* v108.2: FIN/RST from server must reach client — never swallow them.
         * Without this, server-initiated close (FIN) is silently dropped,
         * client thinks connection is alive, refresh/reuse fails. */
        if (tcph->fin || tcph->rst) {
            if (ctx->config.split_dl_enabled) {
                /* Deliver FIN/RST to client via netif_rx (same as data path) */
                struct sk_buff *clone = skb_clone(skb, GFP_ATOMIC);
                if (clone) {
                    clone->mark = PEP_SKB_MARK;
                    clone->pkt_type = PACKET_HOST;
                    clone->ip_summed = CHECKSUM_UNNECESSARY;
                    skb_reset_mac_header(clone);
                    netif_rx(clone);
                }
                kfree_skb(skb);
                return 1;
            }
            /* Non-split_dl: let FIN/RST pass through normally */
            return -1;
        }

        if (ctx->config.fake_ack) {
            pep_dbg("SPLIT_TCP WAN pure ACK stolen: ack=%u\n",
                    ntohl(tcph->ack_seq));
            return 0;
        }

        return -1;
    }
}

/*
 * 功能/Main: 定时处理定时任务（timer task）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；RTT/RTO 估计（RTT/RTO estimation）；定时器/工作队列上下文（timer/workqueue context）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）；配置/参数应用（config/params）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: timer
 * 影响/Effects: 周期维护状态，影响稳定性（periodic maintenance, affects stability）
 * 重要程度/Importance: 中/Medium
 */
static enum hrtimer_restart pep_wan_syn_timer_callback(struct hrtimer *timer)
{
    struct pep_flow *flow = container_of(timer, struct pep_flow, wan_syn_timer);
    struct pep_context *ctx;

    ctx = READ_ONCE(pep_ctx);
    if (!ctx || !atomic_read(&ctx->running)) {
        flow->wan_syn_timer_active = false;
        return HRTIMER_NORESTART;
    }

    if (pep_flow_is_dead(flow)) {
        flow->wan_syn_timer_active = false;
        return HRTIMER_NORESTART;
    }

    if (flow->wan_state == PEP_WAN_ESTABLISHED) {
        flow->wan_syn_timer_active = false;
        return HRTIMER_NORESTART;
    }

    pep_stats_inc_wan_syn_timeouts();

    if (ctx && ctx->config.wan_syn_fail_open_ms > 0 && flow->wan_syn_start_ns) {
        u64 elapsed = ktime_get_ns() - flow->wan_syn_start_ns;
        if (elapsed >= (u64)ctx->config.wan_syn_fail_open_ms * NSEC_PER_MSEC) {
            /*
             * v96 关键修复: 再次检查 wan_state 避免竞态条件
             *
             * 问题: 在第一次 wan_state 检查 (line 3260) 和触发 fail-open 之间，
             *       SYN-ACK 可能已经到达并设置了 wan_state = ESTABLISHED
             *       如果不重新检查，会错误触发 fail-open
             *
             * 竞态时序:
             * T1: 定时器检查 wan_state == SYN_SENT (通过)
             * T2: 【并发】SYN-ACK 到达，设置 wan_state = ESTABLISHED
             * T3: 定时器继续，错误触发 fail-open
             *
             * 解决: 在触发 fail-open 前再次检查 wan_state
             *       使用 READ_ONCE 确保读取最新值
             */
            if (READ_ONCE(flow->wan_state) == PEP_WAN_ESTABLISHED) {
                if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                    pr_info("pep: v96 WAN SYN timer: race avoided, wan_state became ESTABLISHED\n");
                }
                flow->wan_syn_timer_active = false;
                return HRTIMER_NORESTART;
            }

            pep_warn("WAN SYN timeout %llu ms for %pI4:%u -> %pI4:%u, fail-open\n",
                     div_u64(elapsed, NSEC_PER_MSEC),
                     &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
                     &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));
            pep_stats_inc_wan_syn_fail_open();
            WRITE_ONCE(ctx->syn_fail_open_until_ns,
                       ktime_get_ns() +
                       (u64)ctx->config.wan_syn_fail_open_ms * NSEC_PER_MSEC);
            /*
             * v80: 不能在 timer callback (softirq) 中直接调用 pep_send_lan_rst
             * 因为 ip_route_output_flow 会调用 local_bh_enable，导致 WARNING
             * 解决: 调度 work 在 process context 中发送 RST
             */
            WRITE_ONCE(flow->wan_syn_rst_pending, 1);
            if (pep_ctx && pep_ctx->wq)
                queue_work(pep_ctx->wq, &flow->wan_syn_rst_work);
            flow->wan_syn_timer_active = false;
            return HRTIMER_NORESTART;
        }
    }

    if (flow->wan_syn_direct) {
        hrtimer_forward_now(timer, ms_to_ktime(flow->wan_syn_rto_ms));
        return HRTIMER_RESTART;
    }

    if (flow->wan_syn_retries >= ctx->config.wan_syn_max_retries) {
        pep_warn("WAN SYN max retries reached (%u) for %pI4:%u -> %pI4:%u, giving up\n",
                 flow->wan_syn_retries,
                 &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
                 &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));
        pep_stats_inc_wan_syn_max_retries();
        if (ctx && ctx->config.wan_syn_fail_open_ms > 0) {
            u64 until = ktime_get_ns() +
                        (u64)ctx->config.wan_syn_fail_open_ms * NSEC_PER_MSEC;
            pep_stats_inc_wan_syn_fail_open();
            WRITE_ONCE(ctx->syn_fail_open_until_ns, until);
        }
        /*
         * v80: 不能在 timer callback (softirq) 中直接调用 pep_send_lan_rst
         * 因为 ip_route_output_flow 会调用 local_bh_enable，导致 WARNING
         * 解决: 调度 work 在 process context 中发送 RST
         */
        WRITE_ONCE(flow->wan_syn_rst_pending, 1);
        if (pep_ctx && pep_ctx->wq)
            queue_work(pep_ctx->wq, &flow->wan_syn_rst_work);
        flow->wan_syn_timer_active = false;
        return HRTIMER_NORESTART;
    }

    pep_dbg("WAN SYN timeout, retry %u for %pI4:%u -> %pI4:%u\n",
            flow->wan_syn_retries + 1,
            &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
            &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));

    pep_stats_inc_wan_syn_retries();
    WRITE_ONCE(flow->wan_syn_retransmit, 1);

    if (refcount_inc_not_zero(&flow->refcnt)) {
        pep_schedule_wan_tx(flow);
        pep_flow_put(flow);
    }

    flow->wan_syn_retries++;
    flow->wan_syn_rto_ms = min(flow->wan_syn_rto_ms * 2,
                               ctx->config.wan_syn_max_rto_ms);

    hrtimer_forward_now(timer, ms_to_ktime(flow->wan_syn_rto_ms));
    return HRTIMER_RESTART;
}

/*
 * v80: WAN SYN RST work handler
 *
 * 功能/Main: 在工作队列上下文中发送 LAN RST
 * 细节/Details: 解决 timer callback 中调用 ip_route_output_flow 导致的
 *              __local_bh_enable_ip WARNING 问题
 *
 * 问题根源: pep_wan_syn_timer_callback 在 softirq 上下文运行，
 *          但 pep_send_lan_rst -> ip_route_output_flow 需要 process context
 *
 * 解决: 将 RST 发送延迟到 workqueue 执行
 */
static void pep_wan_syn_rst_work_handler(struct work_struct *work)
{
    struct pep_flow *flow = container_of(work, struct pep_flow, wan_syn_rst_work);

    if (!flow || !READ_ONCE(flow->wan_syn_rst_pending))
        return;

    /* 清除待发送标志 */
    WRITE_ONCE(flow->wan_syn_rst_pending, 0);

    /* 检查 flow 是否仍然有效 */
    if (pep_flow_is_dead(flow))
        return;

    /* 发送 RST 给客户端 */
    pep_send_lan_rst(flow);
    pep_stats_inc_wan_syn_rst();

    /* 标记 flow 为 dead */
    pep_flow_mark_dead(flow);
}

/*
 * 功能/Main: 初始化定时任务（Initialize timer task）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；RTT/RTO 估计（RTT/RTO estimation）；定时器/工作队列上下文（timer/workqueue context）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
void pep_wan_syn_timer_init(struct pep_flow *flow)
{
    if (!flow)
        return;

    hrtimer_init(&flow->wan_syn_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    flow->wan_syn_timer.function = pep_wan_syn_timer_callback;
    flow->wan_syn_timer_active = false;
    flow->wan_syn_retransmit = 0;
    flow->wan_syn_direct = 0;
    flow->wan_syn_retries = 0;
    flow->wan_syn_rst_pending = 0;  /* v80: 初始化 RST 标志 */
    INIT_WORK(&flow->wan_syn_rst_work, pep_wan_syn_rst_work_handler);  /* v80 */
    flow->wan_syn_rto_ms = pep_ctx ?
                           pep_ctx->config.wan_syn_init_rto_ms :
                           PEP_WAN_SYN_INIT_RTO_MS;
    flow->wan_syn_start_ns = 0;
    flow->wan_state = PEP_WAN_CLOSED;
}

/*
 * 功能/Main: 定时处理定时任务（timer task）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；RTT/RTO 估计（RTT/RTO estimation）；定时器/工作队列上下文（timer/workqueue context）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 周期维护状态，影响稳定性（periodic maintenance, affects stability）
 * 重要程度/Importance: 中/Medium
 */
void pep_wan_syn_timer_start(struct pep_flow *flow)
{
    if (!flow)
        return;

    if (flow->wan_syn_timer_active)
        return;

    flow->wan_syn_timer_active = true;
    hrtimer_start(&flow->wan_syn_timer,
                  ms_to_ktime(flow->wan_syn_rto_ms),
                  HRTIMER_MODE_REL);
}

/*
 * 功能/Main: 定时处理定时任务（timer task）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；定时器/工作队列上下文（timer/workqueue context）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 周期维护状态，影响稳定性（periodic maintenance, affects stability）
 * 重要程度/Importance: 中/Medium
 */
void pep_wan_syn_timer_stop(struct pep_flow *flow)
{
    if (!flow)
        return;

    if (flow->wan_syn_timer_active) {
        hrtimer_cancel(&flow->wan_syn_timer);
        flow->wan_syn_timer_active = false;
    }
    /* v80: 清除 RST 待发送标志，阻止 work 执行 */
    WRITE_ONCE(flow->wan_syn_rst_pending, 0);
    flow->wan_syn_retransmit = 0;
    flow->wan_syn_start_ns = 0;
}

/*
 * 功能/Main: 清理定时任务（Cleanup timer task）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；定时器/工作队列上下文（timer/workqueue context）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
bool pep_wan_syn_timer_cleanup(struct pep_flow *flow)
{
    int ret;
    int retries = 0;
    const int max_retries = 1000;

    if (!flow)
        return true;

    /* v80: 取消待执行的 RST work */
    cancel_work_sync(&flow->wan_syn_rst_work);
    flow->wan_syn_rst_pending = 0;

    if (!flow->wan_syn_timer_active)
        return true;

    while ((ret = hrtimer_try_to_cancel(&flow->wan_syn_timer)) == -1) {
        if (++retries > max_retries) {
            pr_warn_ratelimited("pep: wan_syn_timer_cleanup: callback running after %d retries\n",
                                max_retries);
            break;
        }
        cpu_relax();
    }

    flow->wan_syn_timer_active = false;
    return (ret != -1);
}

/*
 * 功能/Main: 处理pep_create_wan_syn相关逻辑（Handle pep_create_wan_syn logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；frag/分片结构处理（frag list handling）；访问/维护流状态（flow state access/maintenance）；PMTU/MSS 更新（PMTU/MSS update）；并发同步（spinlock/atomic/rcu）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static struct sk_buff *pep_create_wan_syn(struct pep_flow *flow)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned char *opt_ptr;
    unsigned int ip_hdr_len = sizeof(struct iphdr);

    unsigned int tcp_hdr_len = sizeof(struct tcphdr) + 12;
    unsigned int total_len;
    unsigned int headroom;

    if (!flow)
        return NULL;

    headroom = LL_MAX_HEADER + ip_hdr_len;
    total_len = ip_hdr_len + tcp_hdr_len;

    skb = alloc_skb(headroom + total_len, GFP_ATOMIC);
    if (!skb)
        return NULL;

    skb_reserve(skb, headroom);
    skb_reset_network_header(skb);

    iph = skb_put(skb, ip_hdr_len);
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = 0;
    iph->frag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;

    iph->saddr = flow->tuple.src_addr;
    iph->daddr = flow->tuple.dst_addr;

    skb_set_transport_header(skb, ip_hdr_len);
    tcph = skb_put(skb, tcp_hdr_len);
    memset(tcph, 0, tcp_hdr_len);

    tcph->source = flow->tuple.src_port;
    tcph->dest = flow->tuple.dst_port;
    tcph->seq = htonl(flow->isn_pep_wan);
    tcph->ack_seq = 0;
    tcph->doff = tcp_hdr_len / 4;
    tcph->syn = 1;
    if (flow->ecn_requested) {
        tcph->ece = 1;
        tcph->cwr = 1;
    }
    tcph->window = htons(65535);

    opt_ptr = (unsigned char *)(tcph + 1);

    *opt_ptr++ = TCPOPT_MSS;
    *opt_ptr++ = TCPOLEN_MSS;
    *opt_ptr++ = (1460 >> 8) & 0xFF;
    *opt_ptr++ = 1460 & 0xFF;

    *opt_ptr++ = TCPOPT_SACK_PERM;
    *opt_ptr++ = TCPOLEN_SACK_PERM;

    *opt_ptr++ = TCPOPT_NOP;
    *opt_ptr++ = TCPOPT_NOP;

    *opt_ptr++ = TCPOPT_WINDOW;
    *opt_ptr++ = TCPOLEN_WINDOW;
    *opt_ptr++ = 7;

    *opt_ptr++ = TCPOPT_NOP;

    pep_update_ip_checksum(iph);
    pep_fast_tcp_checksum(skb, iph, tcph, pep_tx_csum_offload_enabled());

    skb->protocol = htons(ETH_P_IP);
    skb->mark = PEP_SKB_MARK;
    skb->priority = 6;

    return skb;
}

/*
 * 功能/Main: 复用原始 SYN 进行 WAN 握手（Rewrite original SYN for WAN handshake）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；定时器/工作队列上下文（timer/workqueue context）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, skb
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
int pep_wan_syn_rewrite(struct pep_flow *flow, struct sk_buff *skb)
{
    struct pep_context *ctx;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len;
    u32 old_seq;
    u32 new_seq;

    if (!flow || !skb)
        return -EINVAL;

    ctx = READ_ONCE(pep_ctx);
    if (!ctx || !atomic_read(&ctx->running))
        return -ESHUTDOWN;

    if (ctx->wan_dev && ctx->lan_dev && ctx->wan_dev == ctx->lan_dev) {
        flow->wan_syn_direct = 1;
        flow->isn_pep_wan = flow->isn_client;
        flow->c2w_seq_offset = 0;
        flow->wan_state = PEP_WAN_SYN_SENT;

        if (!flow->wan_syn_start_ns)
            flow->wan_syn_start_ns = ktime_get_ns();

        pep_wan_syn_timer_start(flow);
        pep_stats_inc_wan_syn_sent();
        return 0;
    }

    flow->wan_syn_direct = 0;

    if (flow->isn_pep_wan == 0)
        flow->isn_pep_wan = pep_generate_isn();

    flow->c2w_seq_offset = (s32)(flow->isn_pep_wan - flow->isn_client);
    flow->wan_state = PEP_WAN_SYN_SENT;

    if (skb_ensure_writable(skb, skb->len))
        return -ENOMEM;

    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

    if (!tcph->syn || tcph->ack)
        return -EINVAL;

    old_seq = ntohl(tcph->seq);
    new_seq = flow->isn_pep_wan;
    if (old_seq != new_seq) {
        tcph->seq = htonl(new_seq);
        pep_incremental_csum_update(&tcph->check, htonl(old_seq),
                                    htonl(new_seq), true);
    }

    tcph->ack = 0;
    tcph->ack_seq = 0;

    if (flow->ecn_requested && ctx->config.ecn_enabled) {
        tcph->ece = 1;
        tcph->cwr = 1;
    } else {
        tcph->ece = 0;
        tcph->cwr = 0;
    }

    pep_update_ip_checksum(iph);
    pep_update_tcp_checksum(skb, iph, tcph);

    if (!flow->wan_syn_start_ns)
        flow->wan_syn_start_ns = ktime_get_ns();

    pep_wan_syn_timer_start(flow);
    pep_stats_inc_wan_syn_sent();

    return 0;
}

/*
 * 功能/Main: 发送pep_wan_syn_send相关逻辑（Send pep_wan_syn_send logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；定时器/工作队列上下文（timer/workqueue context）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, orig_syn
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
int pep_wan_syn_send(struct pep_flow *flow, struct sk_buff *orig_syn)
{
    struct sk_buff *syn_skb;
    int ret;

    if (!flow)
        return -EINVAL;

    flow->wan_syn_direct = 0;

    if (flow->isn_pep_wan == 0) {
        flow->isn_pep_wan = pep_generate_isn();
    }

    flow->c2w_seq_offset = (s32)(flow->isn_pep_wan - flow->isn_client);

    pep_dbg("WAN SYN: Creating SYN to %pI4:%u, isn_pep_wan=%u, isn_client=%u, c2w_offset=%d\n",
            &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port),
            flow->isn_pep_wan, flow->isn_client, flow->c2w_seq_offset);

    syn_skb = pep_create_wan_syn(flow);
    if (!syn_skb) {
        pep_warn("WAN SYN: Failed to create SYN packet\n");
        return -ENOMEM;
    }

    flow->wan_state = PEP_WAN_SYN_SENT;

    ret = pep_send_wan_skb(syn_skb);
    if (ret < 0) {
        pep_stats_inc_wan_syn_send_fail();
        pep_warn("WAN SYN: Failed to send SYN: %d\n", ret);
        flow->wan_state = PEP_WAN_CLOSED;
        return ret;
    }

    pep_stats_inc_wan_syn_sent();

    if (!flow->wan_syn_start_ns)
        flow->wan_syn_start_ns = ktime_get_ns();

    pep_wan_syn_timer_start(flow);

    if (pep_ctx && pep_ctx->config.debug_level >= 2) {
        pep_info("WAN SYN sent to %pI4:%u, isn_pep_wan=%u\n",
                 &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port),
                 flow->isn_pep_wan);
    }

    return 0;
}

/*
 * 功能/Main: 处理pep_translate_seq_client_to_wan相关逻辑（Handle pep_translate_seq_client_to_wan logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；访问/维护流状态（flow state access/maintenance）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: flow, skb
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
int pep_translate_seq_client_to_wan(struct pep_flow *flow, struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    u32 old_seq, new_seq;
    unsigned int ip_hdr_len;

    if (!flow || !skb)
        return -EINVAL;

    if (flow->c2w_seq_offset == 0)
        return 0;

    if (skb_ensure_writable(skb, skb->len))
        return -ENOMEM;

    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

    old_seq = ntohl(tcph->seq);
    new_seq = old_seq + flow->c2w_seq_offset;

    pep_incremental_csum_update(&tcph->check, htonl(old_seq), htonl(new_seq), true);

    tcph->seq = htonl(new_seq);

    pep_dbg("C2W SEQ: %u -> %u (offset=%d)\n", old_seq, new_seq, flow->c2w_seq_offset);

    return 0;
}

/*
 * 功能/Main: 处理pep_translate_ack_wan_to_client相关逻辑（Handle pep_translate_ack_wan_to_client logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；访问/维护流状态（flow state access/maintenance）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: flow, skb
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
int pep_translate_ack_wan_to_client(struct pep_flow *flow, struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    u32 old_ack, new_ack;
    unsigned int ip_hdr_len, tcp_hdr_len, hdr_total;

    if (!flow || !skb)
        return -EINVAL;

    if (flow->c2w_seq_offset == 0)
        return 0;

    /*
     * v77: 只确保 header 可写，不是整个 skb
     * (与 pep_translate_seq_wan_to_lan 相同的修复)
     */
    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
    tcp_hdr_len = tcph->doff * 4;
    hdr_total = ip_hdr_len + tcp_hdr_len;

    if (skb_ensure_writable(skb, hdr_total))
        return -ENOMEM;

    /* 重新获取指针，skb_ensure_writable 可能重新分配了头部 */
    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

    if (!tcph->ack)
        return 0;

    old_ack = ntohl(tcph->ack_seq);
    new_ack = old_ack - flow->c2w_seq_offset;

    pep_incremental_csum_update(&tcph->check, htonl(old_ack), htonl(new_ack), true);

    tcph->ack_seq = htonl(new_ack);

    pep_dbg("W2C ACK: %u -> %u (offset=%d)\n", old_ack, new_ack, flow->c2w_seq_offset);

    return 0;
}
