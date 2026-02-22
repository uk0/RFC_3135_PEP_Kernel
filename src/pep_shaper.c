/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"

/*
 * 功能/Main: 处理带宽整形/调度（Handle traffic shaping/scheduling）
 * 细节/Details: 带宽整形/速率限制（shaping/rate limit）
 * 输入/Inputs: 参数/Inputs: shaper
 * 影响/Effects: 更新整形参数，影响带宽（update shaper params, affects bandwidth）
 * 重要程度/Importance: 中/Medium
 */
static void pep_shaper_refill_locked(struct pep_token_bucket *shaper)
{
    ktime_t now;
    s64 elapsed_ns;
    u64 tokens_to_add;

    now = ktime_get();
    elapsed_ns = ktime_to_ns(ktime_sub(now, shaper->last_update));

    if (elapsed_ns <= 0)
        return;

    tokens_to_add = (shaper->rate * elapsed_ns) / NSEC_PER_SEC;

    if (tokens_to_add > 0) {
        shaper->tokens += tokens_to_add;

        if (shaper->tokens > shaper->burst) {
            shaper->tokens = shaper->burst;
        }

        shaper->last_update = now;
    }
}

/*
 * 功能/Main: 初始化带宽整形/调度（Initialize traffic shaping/scheduling）
 * 细节/Details: 带宽整形/速率限制（shaping/rate limit）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: shaper, rate_bps, burst
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
int pep_shaper_init(struct pep_token_bucket *shaper, u64 rate_bps, u64 burst)
{
    if (!shaper)
        return -EINVAL;

    raw_spin_lock_init(&shaper->lock);

    shaper->rate = rate_bps / 8;

    shaper->burst = burst;
    if (shaper->burst == 0) {
        shaper->burst = shaper->rate / 100;
        if (shaper->burst < 64 * 1024) {
            shaper->burst = 64 * 1024;
        }
    }

    shaper->tokens = shaper->burst;
    shaper->last_update = ktime_get();

    pep_info("Shaper initialized: rate=%llu Bps (%llu Mbps), burst=%llu\n",
             shaper->rate, rate_bps / 1000000, shaper->burst);

    return 0;
}

/*
 * 功能/Main: 清理带宽整形/调度（Cleanup traffic shaping/scheduling）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: shaper
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_shaper_exit(struct pep_token_bucket *shaper)
{

}

/*
 * 功能/Main: 处理带宽整形/调度（Handle traffic shaping/scheduling）
 * 细节/Details: 带宽整形/速率限制（shaping/rate limit）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: shaper, bytes
 * 影响/Effects: 更新整形参数，影响带宽（update shaper params, affects bandwidth）
 * 重要程度/Importance: 中/Medium
 */
bool pep_shaper_allow(struct pep_token_bucket *shaper, u32 bytes)
{
    bool allowed = false;
    unsigned long flags;

    if (!shaper || shaper->rate == 0)
        return true;

    raw_spin_lock_irqsave(&shaper->lock, flags);

    pep_shaper_refill_locked(shaper);

    if (shaper->tokens >= bytes) {
        allowed = true;
    }

    raw_spin_unlock_irqrestore(&shaper->lock, flags);

    return allowed;
}

/*
 * 功能/Main: 处理带宽整形/调度（Handle traffic shaping/scheduling）
 * 细节/Details: 带宽整形/速率限制（shaping/rate limit）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: shaper, bytes
 * 影响/Effects: 更新整形参数，影响带宽（update shaper params, affects bandwidth）
 * 重要程度/Importance: 中/Medium
 */
void pep_shaper_consume(struct pep_token_bucket *shaper, u32 bytes)
{
    unsigned long flags;

    if (!shaper || shaper->rate == 0 || bytes == 0)
        return;

    raw_spin_lock_irqsave(&shaper->lock, flags);

    pep_shaper_refill_locked(shaper);

    if (shaper->tokens >= bytes) {
        shaper->tokens -= bytes;
    } else {
        shaper->tokens = 0;
    }

    raw_spin_unlock_irqrestore(&shaper->lock, flags);
}

/*
 * 功能/Main: 更新带宽整形/调度（Update traffic shaping/scheduling）
 * 细节/Details: 带宽整形/速率限制（shaping/rate limit）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: shaper, rate_bps, burst
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 中/Medium
 */
void pep_shaper_update(struct pep_token_bucket *shaper, u64 rate_bps, u64 burst)
{
    unsigned long flags;

    if (!shaper)
        return;

    raw_spin_lock_irqsave(&shaper->lock, flags);

    pep_shaper_refill_locked(shaper);

    shaper->rate = rate_bps / 8;

    if (burst == 0) {
        burst = shaper->rate / 100;
        if (burst < 64 * 1024)
            burst = 64 * 1024;
    }
    shaper->burst = burst;

    if (shaper->tokens > shaper->burst) {
        shaper->tokens = shaper->burst;
    }

    raw_spin_unlock_irqrestore(&shaper->lock, flags);

    pep_info("Shaper rate updated: %llu Mbps\n", rate_bps / 1000000);
}

/*
 * 功能/Main: 更新带宽整形/调度（Update traffic shaping/scheduling）
 * 细节/Details: 带宽整形/速率限制（shaping/rate limit）
 * 输入/Inputs: 参数/Inputs: shaper, rate_bps
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 中/Medium
 */
void pep_shaper_update_rate(struct pep_token_bucket *shaper, u64 rate_bps)
{
    pep_shaper_update(shaper, rate_bps, 0);
}

extern struct pep_context *pep_ctx;

/*
 * 功能/Main: 定时处理ACK pacing 调度（Timer task ACK pacing scheduling）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；ACK pacing 调度（ACK pacing scheduling）；定时器/工作队列上下文（timer/workqueue context）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: timer
 * 影响/Effects: 周期维护状态，影响稳定性（periodic maintenance, affects stability）
 * 重要程度/Importance: 中/Medium
 */
static enum hrtimer_restart pep_pacing_timer_callback(struct hrtimer *timer)
{
    struct pep_pacing_state *pacing = container_of(timer, struct pep_pacing_state, timer);
    struct pep_flow *flow = container_of(pacing, struct pep_flow, pacing);
    struct pep_context *ctx;

    ctx = READ_ONCE(pep_ctx);
    if (!ctx || !atomic_read(&ctx->running)) {
        WRITE_ONCE(pacing->timer_active, false);
        return HRTIMER_NORESTART;
    }

    if (pep_flow_is_dead(flow)) {
        WRITE_ONCE(pacing->timer_active, false);
        return HRTIMER_NORESTART;
    }

    WRITE_ONCE(pacing->timer_active, false);

    pacing->tokens = min(pacing->tokens + 1, pacing->max_tokens);
    pep_schedule_wan_tx(flow);

    return HRTIMER_NORESTART;
}

/*
 * 功能/Main: 初始化ACK pacing 调度（Initialize ACK pacing scheduling）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；ACK pacing 调度（ACK pacing scheduling）；定时器/工作队列上下文（timer/workqueue context）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
void pep_pacing_init(struct pep_flow *flow)
{
    struct pep_pacing_state *pacing;
    struct pep_context *ctx;

    if (!flow)
        return;

    ctx = READ_ONCE(pep_ctx);
    pacing = &flow->pacing;
    memset(pacing, 0, sizeof(*pacing));

    hrtimer_init(&pacing->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    pacing->timer.function = pep_pacing_timer_callback;
    pacing->timer_active = false;

    if (ctx) {
        u64 max_rate_bps;

        if (ctx->config.wan_kbps)
            max_rate_bps = (u64)ctx->config.wan_kbps * 1000ULL;
        else
            max_rate_bps = ctx->config.bandwidth_bps;

        if (ctx->config.max_acc_flow_tx_kbps) {
            u64 cap_bps = (u64)ctx->config.max_acc_flow_tx_kbps * 1000ULL;

            if (max_rate_bps == 0 || cap_bps < max_rate_bps)
                max_rate_bps = cap_bps;
        }

        if (max_rate_bps == 0)
            max_rate_bps = 1000000000ULL;

        pacing->pacing_rate_bps = max_rate_bps;
    } else {
        pacing->pacing_rate_bps = 1000000000ULL;
    }

    pacing->tokens = PEP_PACING_BURST_PACKETS;
    pacing->max_tokens = PEP_PACING_BURST_PACKETS;

    pep_pacing_update_rate(flow);
}

/*
 * 功能/Main: 清理ACK pacing 调度（Cleanup ACK pacing scheduling）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；ACK pacing 调度（ACK pacing scheduling）；定时器/工作队列上下文（timer/workqueue context）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
bool pep_pacing_cleanup(struct pep_flow *flow)
{
    struct pep_pacing_state *pacing;
    struct pep_context *ctx;

    if (!flow)
        return true;

    pacing = &flow->pacing;
    ctx = READ_ONCE(pep_ctx);

    hrtimer_cancel(&pacing->timer);

    pacing->timer_active = false;
    return true;
}

/*
 * 功能/Main: 更新ACK pacing 调度（Update ACK pacing scheduling）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；ACK pacing 调度（ACK pacing scheduling）；RTT/RTO 估计（RTT/RTO estimation）；PMTU/MSS 更新（PMTU/MSS update）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 中/Medium
 */
void pep_pacing_update_rate(struct pep_flow *flow)
{
    struct pep_pacing_state *pacing;
    struct pep_congestion *cc;
    struct pep_rtt_estimator *rtt;
    u64 pacing_rate_bps;
    u64 min_pacing_rate_bps;
    u32 srtt_us;
    u32 inter_packet_us;
    u32 mss;
    u32 gain_pct = PEP_PACING_GAIN_PERCENT;
    u32 min_interval_us = PEP_PACING_MIN_INTERVAL_US;
    u32 max_interval_us = PEP_PACING_MAX_INTERVAL_US;
    u32 min_rate_pct = PEP_PACING_MIN_RATE_PERCENT;

    if (!flow)
        return;

    pacing = &flow->pacing;
    cc = &flow->cc;
    rtt = &flow->rtt;

    srtt_us = rtt->srtt >> 3;
    if (srtt_us == 0)
        srtt_us = 1000;

    mss = flow->mss;
    if (mss == 0 || mss > 1460)
        mss = 1460;

    if (pep_ctx) {
        if (pep_ctx->config.pacing_gain_pct > 0)
            gain_pct = pep_ctx->config.pacing_gain_pct;
        if (pep_ctx->config.pacing_min_interval_us > 0)
            min_interval_us = pep_ctx->config.pacing_min_interval_us;
        if (pep_ctx->config.pacing_max_interval_us > 0)
            max_interval_us = pep_ctx->config.pacing_max_interval_us;
        if (pep_ctx->config.pacing_min_rate_pct > 0)
            min_rate_pct = pep_ctx->config.pacing_min_rate_pct;
    }
    if (min_interval_us > max_interval_us)
        max_interval_us = min_interval_us;
    if (min_rate_pct > 100)
        min_rate_pct = PEP_PACING_MIN_RATE_PERCENT;

    pacing_rate_bps = div64_u64((u64)cc->cwnd * 8 * 1000000ULL, srtt_us);
    pacing_rate_bps = (pacing_rate_bps * gain_pct) / 100;

    if (pep_ctx) {
        u64 max_rate_bps;

        if (pep_ctx->config.wan_kbps)
            max_rate_bps = (u64)pep_ctx->config.wan_kbps * 1000ULL;
        else
            max_rate_bps = pep_ctx->config.bandwidth_bps;

        if (pep_ctx->config.max_acc_flow_tx_kbps) {
            u64 cap_bps = (u64)pep_ctx->config.max_acc_flow_tx_kbps * 1000ULL;

            if (max_rate_bps == 0 || cap_bps < max_rate_bps)
                max_rate_bps = cap_bps;
        }

        if (max_rate_bps > 0) {
            min_pacing_rate_bps = (max_rate_bps * min_rate_pct) / 100;
            if (pacing_rate_bps < min_pacing_rate_bps)
                pacing_rate_bps = min_pacing_rate_bps;

            if (pacing_rate_bps > max_rate_bps)
                pacing_rate_bps = max_rate_bps;
        }
    }

    pacing->pacing_rate_bps = pacing_rate_bps;

    if (pacing_rate_bps > 0) {
        inter_packet_us = div64_u64((u64)mss * 8 * 1000000ULL, pacing_rate_bps);
    } else {
        inter_packet_us = min_interval_us;
    }

    if (inter_packet_us < min_interval_us)
        inter_packet_us = min_interval_us;
    if (inter_packet_us > max_interval_us)
        inter_packet_us = max_interval_us;

    pacing->inter_packet_us = inter_packet_us;

    pep_dbg("Pacing: rate=%llu bps, interval=%u us, cwnd=%u, srtt=%u us\n",
            pacing_rate_bps, inter_packet_us, cc->cwnd, srtt_us);
}

/*
 * 功能/Main: 发送ACK pacing 调度（Send ACK pacing scheduling）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；ACK pacing 调度（ACK pacing scheduling）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
bool pep_pacing_can_send(struct pep_flow *flow)
{
    struct pep_pacing_state *pacing;
    struct pep_congestion *cc;
    ktime_t now;

    if (!flow)
        return true;

    pacing = &flow->pacing;
    cc = &flow->cc;

    if (cc->bytes_in_flight < cc->cwnd / 2) {
        pacing->packets_burst++;
        return true;
    }

    if (pacing->tokens > 0) {
        pacing->packets_burst++;
        return true;
    }

    now = ktime_get();
    if (ktime_compare(now, pacing->next_send_time) >= 0) {
        pacing->packets_paced++;
        return true;
    }

    return false;
}

/*
 * 功能/Main: 处理ACK pacing 调度（Handle ACK pacing scheduling）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；ACK pacing 调度（ACK pacing scheduling）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow, bytes
 * 影响/Effects: 更新 pacing 参数，影响发送节奏（update pacing, affects send timing）
 * 重要程度/Importance: 中/Medium
 */
void pep_pacing_packet_sent(struct pep_flow *flow, u32 bytes)
{
    struct pep_pacing_state *pacing;
    ktime_t now;
    ktime_t interval;

    if (!flow)
        return;

    pacing = &flow->pacing;
    now = ktime_get();

    if (pacing->tokens > 0) {
        pacing->tokens--;
        pacing->packets_burst++;
    } else {
        pacing->packets_paced++;
    }

    interval = ktime_set(0, pacing->inter_packet_us * NSEC_PER_USEC);
    pacing->next_send_time = ktime_add(now, interval);

    pep_pacing_update_rate(flow);
}

/*
 * 功能/Main: 处理ACK pacing 调度（Handle ACK pacing scheduling）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；ACK pacing 调度（ACK pacing scheduling）；定时器/工作队列上下文（timer/workqueue context）；统计计数更新（stats counters）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新 pacing 参数，影响发送节奏（update pacing, affects send timing）
 * 重要程度/Importance: 中/Medium
 */
void pep_pacing_schedule(struct pep_flow *flow)
{
    struct pep_pacing_state *pacing;
    ktime_t now, delay;
    s64 wait_ns;

    if (!flow)
        return;

    if (pep_flow_is_dead(flow))
        return;

    pacing = &flow->pacing;

    if (pep_pacing_can_send(flow)) {
        pep_schedule_wan_tx(flow);
        return;
    }

    if (READ_ONCE(pacing->timer_active))
        return;

    now = ktime_get();
    wait_ns = ktime_to_ns(ktime_sub(pacing->next_send_time, now));

    if (wait_ns <= 0) {

        pep_schedule_wan_tx(flow);
        return;
    }

    delay = ns_to_ktime(wait_ns);
    hrtimer_start(&pacing->timer, delay, HRTIMER_MODE_REL);

    WRITE_ONCE(pacing->timer_active, true);

    pep_dbg("Pacing: scheduled timer, wait=%lld ns\n", wait_ns);
}
