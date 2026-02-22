/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"

extern struct pep_context *pep_ctx;

#define PEP_CC_ALPHA_SHIFT      3
#define PEP_CC_BETA_SHIFT       2
#define PEP_CC_MSS              1460

/*
 * 功能/Main: 初始化pep_cc_init相关逻辑（Initialize pep_cc_init logic）
 * 细节/Details: 重传/缓存处理（retransmission/cache）；PMTU/MSS 更新（PMTU/MSS update）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: cc, config
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
void pep_cc_init(struct pep_congestion *cc, struct pep_config *config)
{
    if (!cc || !config)
        return;

    memset(cc, 0, sizeof(*cc));

    cc->cwnd = config->init_cwnd * PEP_CC_MSS;
    cc->ssthresh = config->max_cwnd * PEP_CC_MSS;

    cc->bytes_in_flight = 0;
    cc->bytes_acked = 0;
    cc->bytes_sent = 0;

    cc->snd_nxt = 0;
    cc->snd_una = 0;
    cc->high_seq = 0;

    cc->ca_state = PEP_CA_OPEN;
    cc->retrans_count = 0;
    cc->dup_ack_count = 0;
    cc->loss_recovery = 0;

    cc->ecn_enabled = config->ecn_enabled ? 1 : 0;
    cc->ecn_state = PEP_ECN_STATE_UNKNOWN;
    cc->ce_count = 0;
    cc->ce_last_seq = 0;
    cc->undo_marker = 0;
    cc->prior_cwnd = 0;
    cc->prior_ssthresh = 0;
    cc->undo_pending = 0;
}

/*
 * 功能/Main: 处理pep_cc_growth相关逻辑（Handle pep_cc_growth logic）
 * 细节/Details: PMTU/MSS 更新（PMTU/MSS update）
 * 输入/Inputs: 参数/Inputs: cc, acked
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static u32 pep_cc_growth(struct pep_congestion *cc, u32 acked)
{
    u32 increase;

    if (cc->cwnd < cc->ssthresh) {

        increase = acked;
    } else {

        increase = (acked * PEP_CC_MSS) / cc->cwnd;
        if (increase == 0)
            increase = 1;
    }

    return increase;
}

/*
 * 功能/Main: 处理拥塞控制（Handle congestion control）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；RTT/RTO 估计（RTT/RTO estimation）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新拥塞参数，影响吞吐/时延（update congestion params, affects throughput/latency）
 * 重要程度/Importance: 中/Medium
 */
static bool pep_cc_is_congestion_loss(struct pep_flow *flow)
{
    u32 srtt_us;
    u32 min_rtt_us;
    u32 rtt_inflation_pct = PEP_DEFAULT_CC_RTT_INFLATION_PCT;
    u8 bp_level;

    if (!flow)
        return true;

    if (pep_ctx && pep_ctx->config.cc_rtt_inflation_pct > 0)
        rtt_inflation_pct = pep_ctx->config.cc_rtt_inflation_pct;

    bp_level = pep_queue_get_backpressure_level(&flow->lan_to_wan);
    if (bp_level > 0)
        return true;

    if (flow->rtt.samples >= 2 && flow->rtt.srtt > 0 &&
        flow->rtt.min_rtt != UINT_MAX) {
        srtt_us = flow->rtt.srtt >> PEP_CC_ALPHA_SHIFT;
        min_rtt_us = flow->rtt.min_rtt;

        if (pep_ctx && min_rtt_us < PEP_WAN_RTT_MIN_THRESHOLD_US &&
            pep_ctx->config.wan_rtt_ms > 0) {
            min_rtt_us = pep_ctx->config.wan_rtt_ms * 1000;
        }

        if (srtt_us > min_rtt_us +
            (min_rtt_us * rtt_inflation_pct / 100)) {
            return true;
        }
    }

    return false;
}

/*
 * 功能/Main: 处理pep_cc_on_ack相关逻辑（Handle pep_cc_on_ack logic）
 * 细节/Details: PMTU/MSS 更新（PMTU/MSS update）；统计计数更新（stats counters）；配置/参数应用（config/params）；GSO/GRO 分段/合并（GSO/GRO seg/agg）
 * 输入/Inputs: 参数/Inputs: cc, acked_bytes, rtt_us
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_cc_on_ack(struct pep_congestion *cc, u32 acked_bytes, u32 rtt_us)
{
    u32 increase;

    if (!cc || acked_bytes == 0)
        return;

    cc->bytes_acked += acked_bytes;

    cc->dup_ack_count = 0;

    switch (cc->ca_state) {
    case PEP_CA_OPEN:
        increase = pep_cc_growth(cc, acked_bytes);
        cc->cwnd += increase;
        break;

    case PEP_CA_RECOVERY:

        if (PEP_SEQ_GEQ(cc->snd_una, cc->high_seq)) {
            cc->ca_state = PEP_CA_OPEN;
            cc->loss_recovery = 0;
        }
        break;

    case PEP_CA_LOSS:

        cc->cwnd += acked_bytes;
        if (cc->cwnd >= cc->ssthresh) {
            cc->ca_state = PEP_CA_OPEN;
        }
        break;

    case PEP_CA_DISORDER:
    case PEP_CA_CWR:
        cc->ca_state = PEP_CA_OPEN;
        break;
    }

    {
        u32 max_cwnd = PEP_DEFAULT_MAX_CWND;

        if (pep_ctx && pep_ctx->config.max_cwnd > 0)
            max_cwnd = pep_ctx->config.max_cwnd;

        if (cc->cwnd > max_cwnd * PEP_CC_MSS) {
            cc->cwnd = max_cwnd * PEP_CC_MSS;
        }
    }
}

/*
 * 功能/Main: 处理pep_cc_on_loss相关逻辑（Handle pep_cc_on_loss logic）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；PMTU/MSS 更新（PMTU/MSS update）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_cc_on_loss(struct pep_flow *flow)
{
    struct pep_congestion *cc;
    bool congestion_loss;
    u32 reduction_percent;
    struct pep_context *ctx;

    if (!flow)
        return;

    cc = &flow->cc;
    cc->high_seq = cc->snd_nxt;

    switch (cc->ca_state) {
    case PEP_CA_OPEN:
        cc->ca_state = PEP_CA_RECOVERY;
        cc->loss_recovery = 1;
        cc->prior_cwnd = cc->cwnd;
        cc->prior_ssthresh = cc->ssthresh;
        cc->undo_marker = cc->high_seq;
        cc->undo_pending = 1;

        congestion_loss = pep_cc_is_congestion_loss(flow);
        ctx = READ_ONCE(pep_ctx);
        if (ctx) {
            reduction_percent = congestion_loss ?
                ctx->config.cc_cong_reduction_pct :
                ctx->config.cc_ber_reduction_pct;
        } else {
            reduction_percent = congestion_loss ?
                PEP_DEFAULT_CC_CONG_REDUCTION_PCT :
                PEP_DEFAULT_CC_BER_REDUCTION_PCT;
        }

        cc->ssthresh = cc->cwnd * (100 - reduction_percent) / 100;
        if (cc->ssthresh < 2 * PEP_CC_MSS) {
            cc->ssthresh = 2 * PEP_CC_MSS;
        }
        if (cc->cwnd > cc->ssthresh)
            cc->cwnd = cc->ssthresh;
        break;

    case PEP_CA_RECOVERY:

        break;

    default:
        break;
    }
}

/*
 * 功能/Main: 处理pep_cc_on_timeout相关逻辑（Handle pep_cc_on_timeout logic）
 * 细节/Details: 重传/缓存处理（retransmission/cache）；PMTU/MSS 更新（PMTU/MSS update）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: cc
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_cc_on_timeout(struct pep_congestion *cc)
{
    if (!cc)
        return;

    cc->retrans_count++;
    cc->ca_state = PEP_CA_LOSS;

    cc->prior_cwnd = cc->cwnd;
    cc->prior_ssthresh = cc->ssthresh;
    cc->undo_marker = cc->snd_nxt;
    cc->undo_pending = 1;

    cc->ssthresh = cc->cwnd / 2;
    if (cc->ssthresh < 2 * PEP_CC_MSS) {
        cc->ssthresh = 2 * PEP_CC_MSS;
    }

    cc->cwnd = cc->cwnd / 2;
    if (cc->cwnd < 2 * PEP_CC_MSS) {
        cc->cwnd = 2 * PEP_CC_MSS;
    }
}

/*
 * 功能/Main: 处理pep_cc_on_ecn_ce相关逻辑（Handle pep_cc_on_ecn_ce logic）
 * 细节/Details: PMTU/MSS 更新（PMTU/MSS update）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: cc, seq
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
bool pep_cc_on_ecn_ce(struct pep_congestion *cc, u32 seq)
{
    u32 reduction_pct = PEP_DEFAULT_ECN_CE_REDUCTION_PCT;

    if (!cc || !cc->ecn_enabled)
        return false;

    if (pep_ctx && pep_ctx->config.ecn_ce_reduction_pct > 0)
        reduction_pct = pep_ctx->config.ecn_ce_reduction_pct;

    if (cc->ecn_state == PEP_ECN_STATE_CWR &&
        PEP_SEQ_LEQ(seq, cc->ce_last_seq)) {

        return false;
    }

    cc->ce_count++;
    cc->ce_last_seq = seq;

    switch (cc->ca_state) {
    case PEP_CA_OPEN:
        cc->ca_state = PEP_CA_CWR;
        cc->high_seq = cc->snd_nxt;

        cc->ssthresh = cc->cwnd * (100 - reduction_pct) / 100;
        if (cc->ssthresh < 2 * PEP_CC_MSS) {
            cc->ssthresh = 2 * PEP_CC_MSS;
        }

        cc->cwnd = cc->ssthresh;

        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
            pr_info_ratelimited("pep: ECN CE received: cwnd reduced to %u, "
                                "ce_count=%u, seq=%u\n",
                                cc->cwnd, cc->ce_count, seq);
        }

        cc->ecn_state = PEP_ECN_STATE_CWR;
        return true;

    case PEP_CA_CWR:

        return false;

    case PEP_CA_RECOVERY:
    case PEP_CA_LOSS:

        return false;

    default:
        return false;
    }
}

/*
 * 功能/Main: 处理pep_cc_ecn_cwr_acked相关逻辑（Handle pep_cc_ecn_cwr_acked logic）
 * 细节/Details: 统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: cc, ack_seq
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_cc_ecn_cwr_acked(struct pep_congestion *cc, u32 ack_seq)
{
    if (!cc || !cc->ecn_enabled)
        return;

    if (cc->ecn_state == PEP_ECN_STATE_CWR &&
        PEP_SEQ_AFTER(ack_seq, cc->ce_last_seq)) {

        cc->ecn_state = PEP_ECN_STATE_OK;

        if (cc->ca_state == PEP_CA_CWR) {
            cc->ca_state = PEP_CA_OPEN;
        }
    }
}

/*
 * 功能/Main: 获取pep_get_ecn_bits相关逻辑（Get pep_get_ecn_bits logic）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: iph
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static inline u8 pep_get_ecn_bits(const struct iphdr *iph)
{
    return iph->tos & PEP_ECN_MASK;
}

/*
 * 功能/Main: 处理pep_is_ecn_ce相关逻辑（Handle pep_is_ecn_ce logic）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: iph
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
bool pep_is_ecn_ce(const struct iphdr *iph)
{
    return pep_get_ecn_bits(iph) == PEP_ECN_CE;
}

/*
 * 功能/Main: 处理pep_is_ecn_capable相关逻辑（Handle pep_is_ecn_capable logic）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: iph
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
bool pep_is_ecn_capable(const struct iphdr *iph)
{
    u8 ecn = pep_get_ecn_bits(iph);
    return ecn == PEP_ECN_ECT0 || ecn == PEP_ECN_ECT1;
}

/*
 * 功能/Main: 发送pep_cc_get_send_window相关逻辑（Send pep_cc_get_send_window logic）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: cc
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
u32 pep_cc_get_send_window(struct pep_congestion *cc)
{
    u32 win;

    if (!cc)
        return 0;

    if (cc->cwnd > cc->bytes_in_flight) {
        win = cc->cwnd - cc->bytes_in_flight;
    } else {
        win = 0;
    }

    return win;
}

/*
 * 功能/Main: 更新RTT 探测/估计（Update RTT probing/estimation）
 * 细节/Details: FEC 编码/映射/恢复（FEC encode/map/recover）；RTT/RTO 估计（RTT/RTO estimation）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: rtt, sample_us
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 中/Medium
 */
void pep_rtt_update(struct pep_rtt_estimator *rtt, u32 sample_us)
{
    s32 delta;
    u32 effective_sample_us;

    if (!rtt || sample_us == 0)
        return;

    rtt->samples++;

    effective_sample_us = sample_us;
    if (pep_ctx && sample_us < PEP_WAN_RTT_MIN_THRESHOLD_US &&
        pep_ctx->config.wan_rtt_ms > 0) {
        effective_sample_us = pep_ctx->config.wan_rtt_ms * 1000;
        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
            pr_info_ratelimited("pep: RTT using fallback WAN RTT: "
                                "measured=%u us, using=%u us (%u ms)\n",
                                sample_us, effective_sample_us,
                                pep_ctx->config.wan_rtt_ms);
        }
    }

    if (sample_us < rtt->min_rtt || rtt->min_rtt == UINT_MAX) {
        rtt->min_rtt = sample_us;
    }
    if (sample_us > rtt->max_rtt) {
        rtt->max_rtt = sample_us;
    }

    if (rtt->srtt == 0) {

        rtt->srtt = effective_sample_us << PEP_CC_ALPHA_SHIFT;
        rtt->rttvar = (effective_sample_us / 2) << PEP_CC_BETA_SHIFT;
    } else {

        delta = effective_sample_us - (rtt->srtt >> PEP_CC_ALPHA_SHIFT);
        rtt->srtt += delta;

        if (delta < 0)
            delta = -delta;
        delta -= rtt->rttvar >> PEP_CC_BETA_SHIFT;
        rtt->rttvar += delta;
    }

    rtt->rto = ((rtt->srtt >> PEP_CC_ALPHA_SHIFT) +
                (rtt->rttvar >> (PEP_CC_BETA_SHIFT - 2))) / 1000;

    {
        u32 rto_min_ms = PEP_DEFAULT_RTO_MIN_MS;
        u32 rto_max_ms = PEP_DEFAULT_RTO_MAX_MS;

        if (pep_ctx) {
            if (pep_ctx->config.rto_min_ms > 0)
                rto_min_ms = pep_ctx->config.rto_min_ms;
            if (pep_ctx->config.rto_max_ms > 0)
                rto_max_ms = pep_ctx->config.rto_max_ms;
        }

        if (rtt->rto < rto_min_ms)
            rtt->rto = rto_min_ms;
        if (rtt->rto > rto_max_ms)
            rtt->rto = rto_max_ms;
    }

    rtt->last_sample = ktime_get();
}

/*
 * 功能/Main: 更新流表/会话状态（Update flow/session state）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；ACK pacing 调度（ACK pacing scheduling）；FEC 编码/映射/恢复（FEC encode/map/recover）；RTT/RTO 估计（RTT/RTO estimation）；PMTU/MSS 更新（PMTU/MSS update）
 * 输入/Inputs: 参数/Inputs: flow, acked_bytes, rtt_us, loss_detected
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 高/High
 */
void pep_cc_flow_update(struct pep_flow *flow, u32 acked_bytes,
                         u32 rtt_us, bool loss_detected)
{
    struct pep_learning_state *ls;
    struct pep_network_state prev_ns;
    enum pep_cc_action action;
    s32 reward;
    u32 throughput_kbps;
    u32 loss_ppm;
    u32 queue_depth;

    if (!flow || !pep_ctx)
        return;

    if (acked_bytes > 0)
        pep_cc_on_ack(&flow->cc, acked_bytes, rtt_us);
    if (loss_detected)
        pep_cc_on_loss(flow);

    if (!pep_ctx->config.learning_enabled)
        return;

    if (!atomic_read(&pep_ctx->learning.enabled))
        return;

    ls = flow->learning_state;
    if (!ls) {
        ls = pep_learning_get_state(&pep_ctx->learning, flow->hash);
        if (!ls)
            return;
        flow->learning_state = ls;
    }

    if (rtt_us > 0 && acked_bytes > 0) {

        throughput_kbps = (u32)(((u64)acked_bytes * 8 * 1000000) /
                                 (rtt_us * 1000));
    } else {
        throughput_kbps = 0;
    }

    {
        u64 delta_retrans = flow->retrans_packets - ls->prev_retrans_packets;
        u64 delta_bytes = flow->cc.bytes_sent - ls->prev_bytes_sent;

        ls->prev_retrans_packets = flow->retrans_packets;
        ls->prev_bytes_sent = flow->cc.bytes_sent;

        if (delta_bytes > 0) {
            u64 retrans_bytes = delta_retrans * PEP_CC_MSS;
            loss_ppm = (u32)((retrans_bytes * 1000000) / delta_bytes);
        } else {
            loss_ppm = 0;
        }
    }

    if (flow->fec.enabled)
        pep_fec_adjust_params(flow, loss_ppm);

    queue_depth = pep_queue_len(&flow->lan_to_wan);

    if (pep_ctx->config.queue_bdp_enabled && flow->rtt.samples >= 2) {
        u32 srtt_us = flow->rtt.srtt >> 3;
        u32 bdp_rtt_us;
        u64 bandwidth_bps;

        if (srtt_us < PEP_WAN_RTT_MIN_THRESHOLD_US && pep_ctx->config.wan_rtt_ms > 0) {
            bdp_rtt_us = pep_ctx->config.wan_rtt_ms * 1000;
            if (pep_ctx->config.debug_level >= 2) {
                pr_info_ratelimited("pep: BDP using fallback WAN RTT: measured=%u us, using=%u us (%u ms)\n",
                                    srtt_us, bdp_rtt_us, pep_ctx->config.wan_rtt_ms);
            }
        } else {
            bdp_rtt_us = srtt_us;
        }

        if (flow->pacing.pacing_rate_bps > 0) {
            bandwidth_bps = flow->pacing.pacing_rate_bps;
        } else {

            bandwidth_bps = pep_ctx->config.bandwidth_bps;
        }

        if (bdp_rtt_us > 0 && bandwidth_bps > 0) {

            pep_queue_update_bdp(&flow->lan_to_wan, (u32)bandwidth_bps, bdp_rtt_us);
            pep_queue_update_bdp(&flow->wan_to_lan, (u32)bandwidth_bps, bdp_rtt_us);

            if (pep_ctx->config.ack_pacing_enabled) {
                pep_ack_pacer_update_interval(flow, (u32)(bandwidth_bps / 1000));
            }
        }
    }

    memcpy(&prev_ns, &ls->state, sizeof(prev_ns));

    pep_learning_sample(ls, throughput_kbps, rtt_us, loss_ppm,
                        flow->cc.bytes_in_flight, queue_depth);

    pep_learning_extract_features(ls, &ls->state);

    reward = pep_learning_compute_reward(&prev_ns, &ls->state, &pep_ctx->learning);

    if (ls->decisions_made > 0) {
        pep_learning_update_q(&pep_ctx->learning, ls, reward);
    }

    action = pep_learning_select_action(&pep_ctx->learning, ls);

    pep_learning_apply_action(&flow->cc, action);

    if (pep_ctx->config.debug_level >= 3 && ls->decisions_made % 100 == 0) {
        pr_debug("pep: Learning CC: flow=%pI4:%u action=%d reward=%d "
                 "cwnd=%u throughput=%u rtt=%u loss=%u\n",
                 &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port),
                 action, reward, flow->cc.cwnd,
                 throughput_kbps, rtt_us, loss_ppm);
    }
}
