/* SPDX-License-Identifier: GPL-2.0 */
/*
 * RFC 3135 PEP TCP Accelerator v2.0
 * Self-Learning Congestion Control
 *
 * 核心思路:
 * - 使用 Tabular Q-Learning 在内核空间学习
 * - SLAB 缓存存储每流学习状态
 * - 定点数运算避免浮点
 * - 保守探索策略保证稳定性
 */

#ifndef _PEP_LEARNING_H
#define _PEP_LEARNING_H

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/hashtable.h>

/* Forward declarations */
struct pep_congestion;

/*
 * ============== 常量定义 ==============
 */

/* 定点数缩放因子 (避免浮点) */
#define PEP_FIXED_SHIFT         16
#define PEP_FIXED_ONE           (1 << PEP_FIXED_SHIFT)

/* 学习参数 (定点数表示) */
#define PEP_ALPHA_DEFAULT       (PEP_FIXED_ONE / 10)    /* 学习率 0.1 */
#define PEP_GAMMA_DEFAULT       (PEP_FIXED_ONE * 9/10)  /* 折扣因子 0.9 */
#define PEP_EPSILON_DEFAULT     (PEP_FIXED_ONE / 800)   /* 探索率 0.01 */

/* 奖励权重 */
#define PEP_REWARD_THROUGHPUT   140     /* 吞吐权重 */
#define PEP_REWARD_DELAY        -40     /* 延迟惩罚 */
#define PEP_REWARD_LOSS         -80    /* 丢包惩罚 */

/* 状态空间 */
#define PEP_STATE_RTT_BINS      3
#define PEP_STATE_LOSS_BINS     3
#define PEP_STATE_INFLIGHT_BINS 3
#define PEP_STATE_QUEUE_BINS    3
#define PEP_STATE_TREND_BINS    3

#define PEP_STATE_SPACE_SIZE    (PEP_STATE_RTT_BINS * PEP_STATE_LOSS_BINS * \
                                 PEP_STATE_INFLIGHT_BINS * PEP_STATE_QUEUE_BINS * \
                                 PEP_STATE_TREND_BINS)  /* 243 */

/* 动作空间 */
#define PEP_ACTION_SPACE_SIZE   5

/* 历史采样窗口 */
#define PEP_HISTORY_SAMPLES     16
#define PEP_SAMPLE_INTERVAL_MS  10

/*
 * ============== 状态枚举 ==============
 */

enum pep_rtt_level {
    PEP_RTT_LOW = 0,        /* rtt_ratio < 1.2 */
    PEP_RTT_MEDIUM,         /* 1.2 <= rtt_ratio < 2.0 */
    PEP_RTT_HIGH,           /* rtt_ratio >= 2.0 */
};

enum pep_loss_level {
    PEP_LOSS_NONE = 0,      /* < 0.1% (1000 ppm) */
    PEP_LOSS_LOW,           /* 0.1% - 1% */
    PEP_LOSS_HIGH,          /* > 1% */
};

enum pep_inflight_level {
    PEP_INFLIGHT_UNDER = 0, /* < 0.5 * BDP */
    PEP_INFLIGHT_GOOD,      /* 0.5 - 1.0 * BDP */
    PEP_INFLIGHT_OVER,      /* > 1.0 * BDP */
};

enum pep_queue_level {
    PEP_QUEUE_EMPTY = 0,    /* < 10 packets */
    PEP_QUEUE_NORMAL,       /* 10-100 packets */
    PEP_QUEUE_FULL,         /* > 100 packets */
};

enum pep_trend_level {
    PEP_TREND_DOWN = 0,     /* throughput decreasing */
    PEP_TREND_STABLE,       /* stable */
    PEP_TREND_UP,           /* throughput increasing */
};

enum pep_cc_action {
    PEP_ACTION_DEC_LARGE = 0,   /* cwnd *= 0.5 */
    PEP_ACTION_DEC_SMALL,       /* cwnd *= 0.9 */
    PEP_ACTION_HOLD,            /* cwnd 不变 */
    PEP_ACTION_INC_SMALL,       /* cwnd += MSS */
    PEP_ACTION_INC_LARGE,       /* cwnd += 2*MSS */
};

/*
 * ============== 数据结构 ==============
 */

/*
 * 历史采样点
 */
struct pep_sample {
    ktime_t timestamp;
    u32 throughput_kbps;    /* 吞吐率 (kbps) */
    u32 rtt_us;             /* RTT (us) */
    u32 loss_ppm;           /* 丢包率 (ppm, parts per million) */
    u32 in_flight;          /* 在途字节 */
    u32 queue_depth;        /* 队列深度 */
};

/*
 * 网络状态特征 (用于学习)
 */
struct pep_network_state {
    /* 离散化状态索引 */
    u8 rtt_level;           /* 0-2 */
    u8 loss_level;          /* 0-2 */
    u8 inflight_level;      /* 0-2 */
    u8 queue_level;         /* 0-2 */
    u8 trend_level;         /* 0-2 */
    u8 pad[3];

    /* 原始测量值 */
    u32 rtt_us;
    u32 rtt_min_us;
    u32 rtt_var_us;
    u32 rtt_ratio_fixed;    /* 定点数: rtt / rtt_min */

    u32 throughput_kbps;
    u32 throughput_prev_kbps;

    u32 loss_ppm;           /* 丢包率 (ppm) */
    u32 retrans_total;
    u32 sent_total;

    u32 in_flight;
    u32 bdp_estimate;       /* 带宽时延积估计 */
    u32 inflight_ratio_fixed;

    u32 queue_depth;

    /* SACK 信息 (如果启用) */
    u32 sack_blocks;
    u32 sacked_bytes;
    u32 holes_count;
};

/*
 * 每流学习状态 (存储在 SLAB 缓存)
 */
struct pep_learning_state {
    /* 链表节点 (用于 hash table) */
    struct hlist_node hnode;
    struct rcu_head rcu;

    /* 流标识 */
    u32 flow_hash;

    /* 历史采样环形缓冲 */
    struct pep_sample history[PEP_HISTORY_SAMPLES];
    u8 history_idx;
    u8 history_count;
    u16 pad1;

    /* 当前网络状态 */
    struct pep_network_state state;

    /* 上一次动作和状态 (用于 Q-Learning 更新) */
    u16 prev_state_idx;
    u8 prev_action;
    u8 pad2;
    s32 prev_reward;

    /* 学习统计 */
    u64 decisions_made;
    u64 explorations;       /* 探索次数 */
    u64 exploitations;      /* 利用次数 */

    /* 滑动窗口丢包率跟踪 (避免累积计数器导致的负奖励) */
    u64 prev_retrans_packets;   /* 上次采样时的重传包数 */
    u64 prev_bytes_sent;        /* 上次采样时的发送字节数 */

    /* 时间戳 */
    ktime_t last_sample_time;
    ktime_t last_decision_time;
    ktime_t create_time;
};

/*
 * Q 表项
 */
struct pep_q_entry {
    s32 values[PEP_ACTION_SPACE_SIZE];  /* Q(s, a) 值 (定点数) */
    u32 visit_count;                     /* 访问次数 */
};

/*
 * 全局学习模型
 */
struct pep_learning_model {
    /* SLAB 缓存 */
    struct kmem_cache *state_cache;

    /* 每流状态 hash table */
    DECLARE_HASHTABLE(flow_states, 14);  /* 16K buckets */
    raw_spinlock_t states_lock;
    atomic_t state_count;

    /* 全局 Q 表 (所有流共享) */
    struct pep_q_entry q_table[PEP_STATE_SPACE_SIZE];
    raw_spinlock_t q_lock;

    /* 学习参数 (可调) */
    u32 alpha;              /* 学习率 (定点数) */
    u32 gamma;              /* 折扣因子 (定点数) */
    u32 epsilon;            /* 探索率 (定点数) */

    /* 奖励权重 */
    s32 w_throughput;
    s32 w_delay;
    s32 w_loss;

    /* 全局统计 */
    atomic64_t total_decisions;
    atomic64_t total_explorations;
    atomic64_t total_rewards;

    /* 控制标志 */
    atomic_t enabled;
    atomic_t learning_enabled;  /* 是否继续学习 */
};

/*
 * ============== API 函数声明 ==============
 */

/* 初始化/清理 */
int pep_learning_init(struct pep_learning_model *model);
void pep_learning_exit(struct pep_learning_model *model);

/* 每流状态管理 */
struct pep_learning_state *pep_learning_get_state(
    struct pep_learning_model *model, u32 flow_hash);
void pep_learning_put_state(struct pep_learning_state *state);
void pep_learning_remove_state(struct pep_learning_model *model, u32 flow_hash);

/* 数据采样 */
void pep_learning_sample(struct pep_learning_state *state,
                          u32 throughput_kbps, u32 rtt_us,
                          u32 loss_ppm, u32 in_flight, u32 queue_depth);

/* 状态特征提取 */
void pep_learning_extract_features(struct pep_learning_state *state,
                                    struct pep_network_state *ns);
u16 pep_learning_state_to_index(const struct pep_network_state *ns);

/* Q-Learning 核心 */
enum pep_cc_action pep_learning_select_action(
    struct pep_learning_model *model,
    struct pep_learning_state *state);
void pep_learning_update_q(struct pep_learning_model *model,
                            struct pep_learning_state *state,
                            s32 reward);
s32 pep_learning_compute_reward(const struct pep_network_state *prev,
                                 const struct pep_network_state *curr,
                                 struct pep_learning_model *model);

/* 动作执行 */
void pep_learning_apply_action(struct pep_congestion *cc,
                                enum pep_cc_action action);

/* 参数调整 */
void pep_learning_set_alpha(struct pep_learning_model *model, u32 alpha);
void pep_learning_set_epsilon(struct pep_learning_model *model, u32 epsilon);

/* 调试/导出 */
void pep_learning_export_q_table(struct pep_learning_model *model,
                                  struct seq_file *seq);
void pep_learning_export_stats(struct pep_learning_model *model,
                                struct seq_file *seq);

/*
 * ============== 辅助函数 ==============
 */

/* 定点数运算 */
static inline s32 pep_fixed_mul(s32 a, s32 b)
{
    return (s32)(((s64)a * b) >> PEP_FIXED_SHIFT);
}

static inline s32 pep_fixed_div(s32 a, s32 b)
{
    if (b == 0) return 0;
    return (s32)(((s64)a << PEP_FIXED_SHIFT) / b);
}

/* 随机数 (用于 epsilon-greedy) */
static inline bool pep_should_explore(u32 epsilon)
{
    return get_random_u32() < (u32)(((u64)epsilon * U32_MAX) >> PEP_FIXED_SHIFT);
}

/* 找最大 Q 值动作 */
static inline u8 pep_argmax_q(const s32 *q_values)
{
    u8 best = 0;
    s32 max_q = q_values[0];
    int i;

    for (i = 1; i < PEP_ACTION_SPACE_SIZE; i++) {
        if (q_values[i] > max_q) {
            max_q = q_values[i];
            best = i;
        }
    }
    return best;
}

#endif /* _PEP_LEARNING_H */
