/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"
#include "pep_learning.h"

#define PEP_LEARNING_CACHE_NAME "pep_learning_state"
#define PEP_EPSILON_STABLE_VISITS 64

/*
 * 功能/Main: 初始化学习控制（Initialize learning control）
 * 细节/Details: 学习控制/区域统计（learning/regional stats）；内存池管理（mempool management）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: model
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
int pep_learning_init(struct pep_learning_model *model)
{
    int i, j;

    if (!model)
        return -EINVAL;

    memset(model, 0, sizeof(*model));

    model->state_cache = kmem_cache_create(
        PEP_LEARNING_CACHE_NAME,
        sizeof(struct pep_learning_state),
        0,
        SLAB_HWCACHE_ALIGN | SLAB_PANIC,
        NULL);

    if (!model->state_cache) {
        pr_err("pep_learning: failed to create SLAB cache\n");
        return -ENOMEM;
    }

    hash_init(model->flow_states);
    raw_spin_lock_init(&model->states_lock);
    atomic_set(&model->state_count, 0);

    raw_spin_lock_init(&model->q_lock);
    for (i = 0; i < PEP_STATE_SPACE_SIZE; i++) {
        for (j = 0; j < PEP_ACTION_SPACE_SIZE; j++) {

            if (j == PEP_ACTION_HOLD) {
                model->q_table[i].values[j] = 15 * PEP_FIXED_ONE;
            } else {
                model->q_table[i].values[j] = 10 * PEP_FIXED_ONE;
            }
        }
        model->q_table[i].visit_count = 0;
    }

    model->alpha = PEP_ALPHA_DEFAULT;
    model->gamma = PEP_GAMMA_DEFAULT;
    model->epsilon = PEP_EPSILON_DEFAULT;

    model->w_throughput = PEP_REWARD_THROUGHPUT;
    model->w_delay = PEP_REWARD_DELAY;
    model->w_loss = PEP_REWARD_LOSS;

    atomic_set(&model->enabled, 1);
    atomic_set(&model->learning_enabled, 1);

    pr_info("pep_learning: initialized, state_size=%zu, Q_table_size=%d\n",
            sizeof(struct pep_learning_state), PEP_STATE_SPACE_SIZE);

    return 0;
}

/*
 * 功能/Main: 清理学习控制（Cleanup learning control）
 * 细节/Details: 学习控制/区域统计（learning/regional stats）；内存池管理（mempool management）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: model
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_learning_exit(struct pep_learning_model *model)
{
    struct pep_learning_state *state;
    struct hlist_node *tmp;
    unsigned long flags;
    int bkt;

    if (!model)
        return;

    atomic_set(&model->enabled, 0);
    atomic_set(&model->learning_enabled, 0);

    raw_spin_lock_irqsave(&model->states_lock, flags);
    hash_for_each_safe(model->flow_states, bkt, tmp, state, hnode) {
        hash_del_rcu(&state->hnode);
    }
    raw_spin_unlock_irqrestore(&model->states_lock, flags);

    synchronize_rcu();

    hash_for_each_safe(model->flow_states, bkt, tmp, state, hnode) {
        kmem_cache_free(model->state_cache, state);
    }

    if (model->state_cache) {
        kmem_cache_destroy(model->state_cache);
        model->state_cache = NULL;
    }

    pr_info("pep_learning: cleaned up, total_decisions=%lld\n",
            atomic64_read(&model->total_decisions));
}

/*
 * 功能/Main: 获取学习控制（Get learning control）
 * 细节/Details: 学习控制/区域统计（learning/regional stats）；内存池管理（mempool management）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: model, flow_hash
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
struct pep_learning_state *pep_learning_get_state(
    struct pep_learning_model *model, u32 flow_hash)
{
    struct pep_learning_state *state;
    unsigned long flags;

    if (!model || !atomic_read(&model->enabled))
        return NULL;

    rcu_read_lock();
    hash_for_each_possible_rcu(model->flow_states, state, hnode, flow_hash) {
        if (state->flow_hash == flow_hash) {
            rcu_read_unlock();
            return state;
        }
    }
    rcu_read_unlock();

    state = kmem_cache_zalloc(model->state_cache, GFP_ATOMIC);
    if (!state)
        return NULL;

    state->flow_hash = flow_hash;
    state->create_time = ktime_get();
    state->last_sample_time = state->create_time;
    state->last_decision_time = state->create_time;
    state->prev_action = PEP_ACTION_HOLD;

    state->history_idx = 0;
    state->history_count = 0;

    raw_spin_lock_irqsave(&model->states_lock, flags);
    hash_add_rcu(model->flow_states, &state->hnode, flow_hash);
    atomic_inc(&model->state_count);
    raw_spin_unlock_irqrestore(&model->states_lock, flags);

    return state;
}

/*
 * 功能/Main: 处理学习控制（Handle learning control）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: state
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_learning_put_state(struct pep_learning_state *state)
{

}

/*
 * 功能/Main: 释放学习控制（Free learning control）
 * 细节/Details: 学习控制/区域统计（learning/regional stats）；内存池管理（mempool management）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: rcu
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 中/Medium
 */
static void pep_learning_state_free_rcu(struct rcu_head *rcu)
{
    struct pep_learning_state *state = container_of(rcu, struct pep_learning_state, rcu);
    struct pep_context *ctx = READ_ONCE(pep_ctx);

    if (ctx && ctx->learning.state_cache)
        kmem_cache_free(ctx->learning.state_cache, state);
}

/*
 * 功能/Main: 处理学习控制（Handle learning control）
 * 细节/Details: 学习控制/区域统计（learning/regional stats）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: model, flow_hash
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_learning_remove_state(struct pep_learning_model *model, u32 flow_hash)
{
    struct pep_learning_state *state = NULL;
    unsigned long flags;

    if (!model)
        return;

    raw_spin_lock_irqsave(&model->states_lock, flags);
    hash_for_each_possible(model->flow_states, state, hnode, flow_hash) {
        if (state->flow_hash == flow_hash) {
            hash_del_rcu(&state->hnode);
            atomic_dec(&model->state_count);
            break;
        }
    }
    raw_spin_unlock_irqrestore(&model->states_lock, flags);

    if (state) {
        call_rcu(&state->rcu, pep_learning_state_free_rcu);
    }
}

/*
 * 功能/Main: 处理学习控制（Handle learning control）
 * 细节/Details: 队列/链表维护（queue/list maintenance）；RTT/RTO 估计（RTT/RTO estimation）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: state, throughput_kbps, rtt_us, loss_ppm, in_flight, queue_depth
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_learning_sample(struct pep_learning_state *state,
                          u32 throughput_kbps, u32 rtt_us,
                          u32 loss_ppm, u32 in_flight, u32 queue_depth)
{
    struct pep_sample *sample;
    ktime_t now;

    if (!state)
        return;

    now = ktime_get();

    if (ktime_to_ms(ktime_sub(now, state->last_sample_time)) < PEP_SAMPLE_INTERVAL_MS)
        return;

    sample = &state->history[state->history_idx];
    sample->timestamp = now;
    sample->throughput_kbps = throughput_kbps;
    sample->rtt_us = rtt_us;
    sample->loss_ppm = loss_ppm;
    sample->in_flight = in_flight;
    sample->queue_depth = queue_depth;

    state->history_idx = (state->history_idx + 1) % PEP_HISTORY_SAMPLES;
    if (state->history_count < PEP_HISTORY_SAMPLES)
        state->history_count++;

    state->last_sample_time = now;
}

/*
 * 功能/Main: 处理学习控制（Handle learning control）
 * 细节/Details: 队列/链表维护（queue/list maintenance）；RTT/RTO 估计（RTT/RTO estimation）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: state, ns
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_learning_extract_features(struct pep_learning_state *state,
                                    struct pep_network_state *ns)
{
    u32 i, idx;

    if (!state || !ns)
        return;

    memset(ns, 0, sizeof(*ns));

    if (state->history_count > 0) {
        idx = (state->history_idx + PEP_HISTORY_SAMPLES - 1) % PEP_HISTORY_SAMPLES;
        ns->rtt_us = state->history[idx].rtt_us;
        ns->throughput_kbps = state->history[idx].throughput_kbps;
        ns->loss_ppm = state->history[idx].loss_ppm;
        ns->in_flight = state->history[idx].in_flight;
        ns->queue_depth = state->history[idx].queue_depth;
    }

    ns->rtt_min_us = UINT_MAX;
    for (i = 0; i < state->history_count; i++) {
        if (state->history[i].rtt_us > 0 &&
            state->history[i].rtt_us < ns->rtt_min_us) {
            ns->rtt_min_us = state->history[i].rtt_us;
        }
    }
    if (ns->rtt_min_us == UINT_MAX)
        ns->rtt_min_us = ns->rtt_us > 0 ? ns->rtt_us : 1;

    if (ns->rtt_min_us > 0) {
        ns->rtt_ratio_fixed = pep_fixed_div(ns->rtt_us, ns->rtt_min_us);
    } else {
        ns->rtt_ratio_fixed = PEP_FIXED_ONE;
    }

    if (state->history_count >= 2) {
        u32 prev_idx = (state->history_idx + PEP_HISTORY_SAMPLES - 2) % PEP_HISTORY_SAMPLES;
        ns->throughput_prev_kbps = state->history[prev_idx].throughput_kbps;
    } else {
        ns->throughput_prev_kbps = ns->throughput_kbps;
    }

    if (ns->rtt_min_us > 0 && ns->throughput_kbps > 0) {
        ns->bdp_estimate = (u32)(((u64)ns->throughput_kbps * 1000 / 8) *
                                  ns->rtt_min_us / 1000000);
        if (ns->bdp_estimate == 0)
            ns->bdp_estimate = 1460;
    } else {
        ns->bdp_estimate = 65536;
    }

    if (ns->bdp_estimate > 0) {
        ns->inflight_ratio_fixed = pep_fixed_div(ns->in_flight, ns->bdp_estimate);
    } else {
        ns->inflight_ratio_fixed = PEP_FIXED_ONE;
    }

    if (ns->rtt_ratio_fixed < (PEP_FIXED_ONE * 12 / 10)) {
        ns->rtt_level = PEP_RTT_LOW;
    } else if (ns->rtt_ratio_fixed < (PEP_FIXED_ONE * 2)) {
        ns->rtt_level = PEP_RTT_MEDIUM;
    } else {
        ns->rtt_level = PEP_RTT_HIGH;
    }

    if (ns->loss_ppm < 1000) {
        ns->loss_level = PEP_LOSS_NONE;
    } else if (ns->loss_ppm < 10000) {
        ns->loss_level = PEP_LOSS_LOW;
    } else {
        ns->loss_level = PEP_LOSS_HIGH;
    }

    if (ns->inflight_ratio_fixed < (PEP_FIXED_ONE / 2)) {
        ns->inflight_level = PEP_INFLIGHT_UNDER;
    } else if (ns->inflight_ratio_fixed <= PEP_FIXED_ONE) {
        ns->inflight_level = PEP_INFLIGHT_GOOD;
    } else {
        ns->inflight_level = PEP_INFLIGHT_OVER;
    }

    if (ns->queue_depth < 10) {
        ns->queue_level = PEP_QUEUE_EMPTY;
    } else if (ns->queue_depth < 100) {
        ns->queue_level = PEP_QUEUE_NORMAL;
    } else {
        ns->queue_level = PEP_QUEUE_FULL;
    }

    if (ns->throughput_prev_kbps > 0) {
        s32 diff = (s32)ns->throughput_kbps - (s32)ns->throughput_prev_kbps;
        s32 threshold = (s32)(ns->throughput_prev_kbps / 10);

        if (diff < -threshold) {
            ns->trend_level = PEP_TREND_DOWN;
        } else if (diff > threshold) {
            ns->trend_level = PEP_TREND_UP;
        } else {
            ns->trend_level = PEP_TREND_STABLE;
        }
    } else {
        ns->trend_level = PEP_TREND_STABLE;
    }
}

/*
 * 功能/Main: 处理学习控制（Handle learning control）
 * 细节/Details: 队列/链表维护（queue/list maintenance）；RTT/RTO 估计（RTT/RTO estimation）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: ns
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
u16 pep_learning_state_to_index(const struct pep_network_state *ns)
{
    if (!ns)
        return 0;

    return (u16)(ns->rtt_level +
                 ns->loss_level * PEP_STATE_RTT_BINS +
                 ns->inflight_level * PEP_STATE_RTT_BINS * PEP_STATE_LOSS_BINS +
                 ns->queue_level * PEP_STATE_RTT_BINS * PEP_STATE_LOSS_BINS *
                                   PEP_STATE_INFLIGHT_BINS +
                 ns->trend_level * PEP_STATE_RTT_BINS * PEP_STATE_LOSS_BINS *
                                   PEP_STATE_INFLIGHT_BINS * PEP_STATE_QUEUE_BINS);
}

/*
 * 功能/Main: 处理学习控制（Handle learning control）
 * 细节/Details: 学习控制/区域统计（learning/regional stats）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: model, state
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
enum pep_cc_action pep_learning_select_action(
    struct pep_learning_model *model,
    struct pep_learning_state *state)
{
    struct pep_network_state ns;
    struct pep_q_entry *q_entry;
    u16 state_idx;
    u8 action;
    unsigned long flags;

    if (!model || !state)
        return PEP_ACTION_HOLD;

    if (!atomic_read(&model->enabled))
        return PEP_ACTION_HOLD;

    pep_learning_extract_features(state, &ns);
    state_idx = pep_learning_state_to_index(&ns);

    memcpy(&state->state, &ns, sizeof(ns));
    state->prev_state_idx = state_idx;

    raw_spin_lock_irqsave(&model->q_lock, flags);
    q_entry = &model->q_table[state_idx];

    if (atomic_read(&model->learning_enabled) &&
        q_entry->visit_count < PEP_EPSILON_STABLE_VISITS &&
        pep_should_explore(model->epsilon)) {

        action = get_random_u32() % PEP_ACTION_SPACE_SIZE;
        state->explorations++;
        atomic64_inc(&model->total_explorations);
    } else {

        action = pep_argmax_q(q_entry->values);
        state->exploitations++;
    }

    raw_spin_unlock_irqrestore(&model->q_lock, flags);

    state->prev_action = action;
    state->decisions_made++;
    state->last_decision_time = ktime_get();
    atomic64_inc(&model->total_decisions);

    return (enum pep_cc_action)action;
}

/*
 * 功能/Main: 计算学习控制（Compute learning control）
 * 细节/Details: RTT/RTO 估计（RTT/RTO estimation）
 * 输入/Inputs: 参数/Inputs: prev, curr, model
 * 影响/Effects: 计算派生值，影响策略决策（compute derived values, affects policy decisions）
 * 重要程度/Importance: 低/Low
 */
s32 pep_learning_compute_reward(const struct pep_network_state *prev,
                                 const struct pep_network_state *curr,
                                 struct pep_learning_model *model)
{
    s32 reward = 0;
    s32 throughput_delta, delay_delta, loss_delta;

    if (!prev || !curr || !model)
        return 0;

    if (prev->throughput_kbps > 0) {
        throughput_delta = (s32)curr->throughput_kbps - (s32)prev->throughput_kbps;

        throughput_delta = (throughput_delta * 100) / (s32)prev->throughput_kbps;
        throughput_delta = clamp(throughput_delta, -100, 100);
        reward += model->w_throughput * throughput_delta / 100;
    }

    if (prev->rtt_us > 0) {
        delay_delta = (s32)curr->rtt_us - (s32)prev->rtt_us;
        delay_delta = (delay_delta * 100) / (s32)prev->rtt_us;
        delay_delta = clamp(delay_delta, -100, 100);
        reward += model->w_delay * delay_delta / 100;
    }

    {
        s32 loss_baseline = max((s32)prev->loss_ppm, (s32)curr->loss_ppm);
        if (loss_baseline > 0) {
            loss_delta = (s32)curr->loss_ppm - (s32)prev->loss_ppm;

            loss_delta = (loss_delta * 100) / loss_baseline;
            loss_delta = clamp(loss_delta, -100, 100);

            reward += model->w_loss * loss_delta / 100;
        }

    }

    reward += 20;

    return reward;
}

/*
 * 功能/Main: 更新学习控制（Update learning control）
 * 细节/Details: 学习控制/区域统计（learning/regional stats）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: model, state, reward
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 中/Medium
 */
void pep_learning_update_q(struct pep_learning_model *model,
                            struct pep_learning_state *state,
                            s32 reward)
{
    struct pep_network_state curr_ns;
    struct pep_q_entry *prev_q, *curr_q;
    u16 prev_idx, curr_idx;
    s32 old_q, max_future_q, new_q;
    s32 td_error;
    unsigned long flags;

    if (!model || !state)
        return;

    if (!atomic_read(&model->learning_enabled))
        return;

    pep_learning_extract_features(state, &curr_ns);
    curr_idx = pep_learning_state_to_index(&curr_ns);
    prev_idx = state->prev_state_idx;

    raw_spin_lock_irqsave(&model->q_lock, flags);

    prev_q = &model->q_table[prev_idx];
    curr_q = &model->q_table[curr_idx];

    old_q = prev_q->values[state->prev_action];
    max_future_q = curr_q->values[pep_argmax_q(curr_q->values)];

    td_error = reward + pep_fixed_mul(model->gamma, max_future_q) - old_q;

    new_q = old_q + pep_fixed_mul(model->alpha, td_error);

    new_q = clamp(new_q, -1000 * PEP_FIXED_ONE, 1000 * PEP_FIXED_ONE);

    prev_q->values[state->prev_action] = new_q;
    prev_q->visit_count++;

    raw_spin_unlock_irqrestore(&model->q_lock, flags);

    state->prev_reward = reward;
    memcpy(&state->state, &curr_ns, sizeof(curr_ns));
    state->prev_state_idx = curr_idx;

    atomic64_add(reward, &model->total_rewards);
}

/*
 * 功能/Main: 处理学习控制（Handle learning control）
 * 细节/Details: PMTU/MSS 更新（PMTU/MSS update）
 * 输入/Inputs: 参数/Inputs: cc, action
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_learning_apply_action(struct pep_congestion *cc,
                                enum pep_cc_action action)
{
    u32 mss = 1460;

    if (!cc)
        return;

    switch (action) {
    case PEP_ACTION_DEC_LARGE:

        cc->cwnd = cc->cwnd / 2;
        if (cc->cwnd < 2 * mss)
            cc->cwnd = 2 * mss;
        break;

    case PEP_ACTION_DEC_SMALL:

        cc->cwnd = cc->cwnd * 9 / 10;
        if (cc->cwnd < 2 * mss)
            cc->cwnd = 2 * mss;
        break;

    case PEP_ACTION_HOLD:

        break;

    case PEP_ACTION_INC_SMALL:

        cc->cwnd += mss;
        break;

    case PEP_ACTION_INC_LARGE:

        cc->cwnd += 2 * mss;
        break;
    }

    if (cc->cwnd > PEP_DEFAULT_MAX_CWND * mss)
        cc->cwnd = PEP_DEFAULT_MAX_CWND * mss;
}

/*
 * 功能/Main: 设置学习控制（Set learning control）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: model, alpha
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_learning_set_alpha(struct pep_learning_model *model, u32 alpha)
{
    if (model)
        model->alpha = min_t(u32, alpha, PEP_FIXED_ONE);
}

/*
 * 功能/Main: 设置学习控制（Set learning control）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: model, epsilon
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_learning_set_epsilon(struct pep_learning_model *model, u32 epsilon)
{
    if (model)
        model->epsilon = min_t(u32, epsilon, PEP_FIXED_ONE / 2);
}

/*
 * 功能/Main: 处理学习控制（Handle learning control）
 * 细节/Details: 队列/链表维护（queue/list maintenance）；RTT/RTO 估计（RTT/RTO estimation）；学习控制/区域统计（learning/regional stats）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: model, seq
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_learning_export_q_table(struct pep_learning_model *model,
                                  struct seq_file *seq)
{
    int i, j;
    unsigned long flags;

    if (!model || !seq)
        return;

    seq_printf(seq, "=== Q-Table (state_count=%d) ===\n", PEP_STATE_SPACE_SIZE);
    seq_printf(seq, "State: [RTT][Loss][Inflight][Queue][Trend] -> Q values\n\n");

    raw_spin_lock_irqsave(&model->q_lock, flags);

    for (i = 0; i < PEP_STATE_SPACE_SIZE; i++) {
        struct pep_q_entry *q = &model->q_table[i];

        if (q->visit_count == 0)
            continue;

        u8 rtt = i % PEP_STATE_RTT_BINS;
        u8 loss = (i / PEP_STATE_RTT_BINS) % PEP_STATE_LOSS_BINS;
        u8 inflight = (i / (PEP_STATE_RTT_BINS * PEP_STATE_LOSS_BINS)) % PEP_STATE_INFLIGHT_BINS;
        u8 queue_l = (i / (PEP_STATE_RTT_BINS * PEP_STATE_LOSS_BINS * PEP_STATE_INFLIGHT_BINS)) %
                    PEP_STATE_QUEUE_BINS;
        u8 trend = i / (PEP_STATE_RTT_BINS * PEP_STATE_LOSS_BINS * PEP_STATE_INFLIGHT_BINS *
                       PEP_STATE_QUEUE_BINS);

        seq_printf(seq, "[%d][%d][%d][%d][%d] (visited=%u): ",
                   rtt, loss, inflight, queue_l, trend, q->visit_count);

        for (j = 0; j < PEP_ACTION_SPACE_SIZE; j++) {
            seq_printf(seq, "%d ", q->values[j] >> (PEP_FIXED_SHIFT - 4));
        }
        seq_printf(seq, "\n");
    }

    raw_spin_unlock_irqrestore(&model->q_lock, flags);
}

/*
 * 功能/Main: 处理学习控制（Handle learning control）
 * 细节/Details: 学习控制/区域统计（learning/regional stats）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: model, seq
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_learning_export_stats(struct pep_learning_model *model,
                                struct seq_file *seq)
{
    if (!model || !seq)
        return;

    seq_printf(seq, "=== Learning Statistics ===\n");
    seq_printf(seq, "Enabled: %d\n", atomic_read(&model->enabled));
    seq_printf(seq, "Learning: %d\n", atomic_read(&model->learning_enabled));
    seq_printf(seq, "Active states: %d\n", atomic_read(&model->state_count));
    seq_printf(seq, "Total decisions: %lld\n", atomic64_read(&model->total_decisions));
    seq_printf(seq, "Total explorations: %lld\n", atomic64_read(&model->total_explorations));
    seq_printf(seq, "Total rewards: %lld\n", atomic64_read(&model->total_rewards));
    seq_printf(seq, "\n");
    seq_printf(seq, "Parameters:\n");
    seq_printf(seq, "  Alpha (learning rate): %u / %u\n", model->alpha, PEP_FIXED_ONE);
    seq_printf(seq, "  Gamma (discount): %u / %u\n", model->gamma, PEP_FIXED_ONE);
    seq_printf(seq, "  Epsilon (exploration): %u / %u\n", model->epsilon, PEP_FIXED_ONE);
    seq_printf(seq, "\n");
    seq_printf(seq, "Reward weights:\n");
    seq_printf(seq, "  Throughput: %d\n", model->w_throughput);
    seq_printf(seq, "  Delay: %d\n", model->w_delay);
    seq_printf(seq, "  Loss: %d\n", model->w_loss);
}
