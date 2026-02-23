/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */
/*
 * RFC 3135 PEP TCP Accelerator v2.0
 * Performance Enhancing Proxy - Split-TCP Implementation
 *
 * 核心头文件 - 支持 GSO/GRO, 多核并行, TCP Spoofing
 */

#ifndef _PEP_CORE_H
#define _PEP_CORE_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/spinlock.h>
#include <linux/rculist.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/cpumask.h>
#include <linux/rbtree.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/checksum.h>
#include <net/route.h>

/* Self-Learning Congestion Control */
#include "pep_learning.h"

/*
 * 版本信息
 */
#define PEP_VERSION         "2.0.0"
#define PEP_MODULE_NAME     "pep_accelerator"
#define PEP_PROC_ROOT       "pep"

/*
 * 默认配置参数
 */
#define PEP_DEFAULT_FLOW_TABLE_BITS     16          /* 流表哈希桶数: 2^16 = 65536 */
#define PEP_DEFAULT_MAX_FLOWS           131072      /* 最大流数量 */
#define PEP_DEFAULT_FLOW_TIMEOUT_MS     120000      /* 流超时时间: 120秒 */

/* 队列配置 */
#define PEP_DEFAULT_LAN_WAN_QUEUE_MIN   64          /* LAN->WAN 最小队列 */
#define PEP_DEFAULT_LAN_WAN_QUEUE_MAX   8192        /* LAN->WAN 最大队列 (v29: 从 4096 增加) */
#define PEP_DEFAULT_WAN_LAN_QUEUE_MIN   64          /* WAN->LAN 最小队列 */
#define PEP_DEFAULT_WAN_LAN_QUEUE_MAX   8192        /* WAN->LAN 最大队列 (v29: 从 4096 增加) */

/* BDP-aware 动态队列配置 */
#define PEP_QUEUE_BDP_ENABLED           1           /* 默认启用 BDP 感知 */
#define PEP_QUEUE_BDP_MULTIPLIER        2           /* BDP × 2 作为队列上限 */
/*
 * v90 优化: 队列绝对上限从 16MB 增加到 64MB
 *
 * 原因: 高 BDP 场景 (200Mbps × 250ms = 6.25MB) 需要更大缓冲
 *       双队列加速 (lan_to_wan + wan_to_lan) 各需要 BDP × 2 = 12.5MB
 *       16MB 限制会导致队列满时丢包，增加到 64MB 确保充足缓冲
 */
#define PEP_QUEUE_MAX_ABSOLUTE          67108864    /* 绝对上限: 64MB (v90: 16MB -> 64MB) */
#define PEP_QUEUE_BACKPRESSURE_LEVEL1   80          /* 80% 开始减速 ACK */
#define PEP_QUEUE_BACKPRESSURE_LEVEL2   90          /* 90% 强力减速 ACK */

/*
 * WAN RTT Fallback 配置
 *
 * 问题: 当有本地代理 (如 198.18.x.x) 时，PEP 测量的 RTT 是到代理的 (~1ms)
 *       而不是真实 WAN RTT (~250ms)。这导致 BDP 估计过小，队列容量不足。
 *
 * 解决: 当测量 RTT < 阈值时，使用配置的 fallback RTT 进行 BDP 计算
 *
 * v29 修复: 降低阈值避免误触发，将 fallback 设为合理值
 */
#define PEP_WAN_RTT_MIN_THRESHOLD_US    1000        /* RTT < 1ms 才视为代理场景 */
#define PEP_DEFAULT_WAN_RTT_MS          10          /* 默认 fallback WAN RTT: 10ms */

/* RTO 配置 */
#define PEP_DEFAULT_MAX_RETRANS         15          /* 最大重传次数 */
#define PEP_DEFAULT_RTO_MIN_MS          20          /* 最小 RTO: 20ms */
#define PEP_DEFAULT_RTO_MAX_MS          2000        /* 最大 RTO: 2000ms */
#define PEP_DEFAULT_RTO_INIT_MS         300         /* 初始 RTO: 300ms (适应高 RTT) */

/* 拥塞控制 */
#define PEP_DEFAULT_INIT_CWND           32          /* 初始拥塞窗口 (激进) */
#define PEP_DEFAULT_MAX_CWND            262144      /* 最大拥塞窗口 */

/*
 * ECN (Explicit Congestion Notification) 配置
 * RFC 3168: The Addition of Explicit Congestion Notification (ECN) to IP
 */
#define PEP_ECN_MASK            0x03    /* ECN 位掩码 (IP TOS 低2位) */
#define PEP_ECN_NOT_ECT         0x00    /* 不支持 ECN */
#define PEP_ECN_ECT1            0x01    /* ECN-Capable Transport (1) */
#define PEP_ECN_ECT0            0x02    /* ECN-Capable Transport (0) */
#define PEP_ECN_CE              0x03    /* Congestion Experienced */

/* ECN 配置默认值 */
#define PEP_DEFAULT_ECN_ENABLED         1           /* 默认启用 ECN */
#define PEP_ECN_CE_REDUCTION_PERCENT    50          /* CE 标记时 cwnd 减少 50% */

/* Advanced CC tuning defaults */
#define PEP_DEFAULT_CC_CONG_REDUCTION_PCT   20      /* 拥塞丢包时降低 cwnd 比例 */
#define PEP_DEFAULT_CC_BER_REDUCTION_PCT    10      /* 随机丢包时降低 cwnd 比例 */
#define PEP_DEFAULT_CC_RTT_INFLATION_PCT    25      /* RTT 膨胀阈值百分比 */
#define PEP_DEFAULT_ECN_CE_REDUCTION_PCT    50      /* ECN CE 触发降窗比例 */

/*
 * FEC (Forward Error Correction) 配置
 * 用于高丢包链路（卫星、无线）的前向纠错
 */
#define PEP_DEFAULT_FEC_ENABLED         0           /* 默认禁用 FEC */
#define PEP_FEC_DEFAULT_K               10          /* 默认 K 值: 10 个数据包 */
#define PEP_FEC_DEFAULT_N               11          /* 默认 N 值: 10 数据 + 1 FEC */
#define PEP_FEC_MAX_K                   64          /* 最大 K 值 */
#define PEP_FEC_MAX_BLOCK_SIZE          1500        /* 最大块大小 */

/*
 * PMTU (Path MTU Discovery) 配置
 */
#define PEP_PMTU_DEFAULT                1500        /* 默认 PMTU */
#define PEP_PMTU_TIMEOUT_MS             600000      /* PMTU 缓存超时: 10 分钟 */

/*
 * Flowtable/快速路径配置
 */
#define PEP_FASTPATH_ENABLED            1           /* 默认启用快速路径 */
#define PEP_FASTPATH_THRESHOLD_PKTS     5           /* v107: 10 -> 5, 更快进入快速路径 */

/* ACK Pacing 配置 */
#define PEP_DEFAULT_ACK_PACING          1           /* 默认启用 ACK Pacing */
#define PEP_DEFAULT_ACK_DELAY_US        1000        /* 默认 ACK 延迟: 1ms */
#define PEP_DEFAULT_ACK_BYTES_THRESHOLD 16384       /* 默认字节阈值: 16KB */

/*
 * Advance ACK Aggregation 配置 (v46, v90, v91 优化)
 *
 * RFC 1122 Delayed ACK 原则:
 * - 至少每 2 个全尺寸段 ACK 一次
 * - 或在超时时间内发送 ACK（通常 200ms，但高 RTT 链路需要更短）
 *
 * v91 优化: 平衡 ACK 频率，减少过度 ACK
 * - 字节阈值: 4 MSS = 5840 字节 (v91: 1460 -> 5840)
 *   原因: 1 MSS 导致每个包都发 ACK，浪费带宽
 *         4 MSS 平衡丢包检测和带宽效率
 * - 时间阈值: 25ms (v91: 20ms -> 25ms)
 *   原因: 更长超时允许更多 ACK 聚合
 *
 * ACK Piggyback: 如果有待发送的上传数据，跳过纯 ACK
 *                让数据包携带 ACK (pep_spoofing.c:pep_adv_ack_flush_pending)
 */
#define PEP_ADV_ACK_BYTES_THRESHOLD     5840        /* 4 MSS = 5840 字节 (v91: 1460 -> 5840) */
#define PEP_ADV_ACK_TIMEOUT_US          25000       /* 25ms 超时 (v91: 20ms -> 25ms) */
#define PEP_ADV_ACK_MIN_TIMEOUT_US      4000        /* v107: 8ms -> 4ms, split_dl 需要更快响应 */
#define PEP_ADV_ACK_MAX_TIMEOUT_US      60000       /* 最大 60ms (v91: 50ms -> 60ms) */

/* Re-seq (out-of-order tracking) 配置 */
#define PEP_DEFAULT_RESEQ_ENABLED       1           /* 默认启用 re-seq */
#define PEP_DEFAULT_RESEQ_PACKET_CNT    128         /* 最大乱序包跟踪数 */

/* Scheduler / Classifier defaults */
#define PEP_DEFAULT_SCHED_ENABLED       1           /* 默认启用全局调度器 */
#define PEP_DEFAULT_CLASSIFY_SMALL_FLOW_BYTES 131072 /* 128KB 以内视为小流 */

/* Engine scheduling defaults */
#define PEP_DEFAULT_ENGINE_NUM          0           /* 0 = auto (num_online_cpus) */
#define PEP_DEFAULT_TASK_SCHED_DELAY_WAN_MS 0       /* 0 = no delay */
#define PEP_DEFAULT_TASK_SCHED_DELAY_LAN_MS 0       /* 0 = no delay */

/* RTT probe defaults */
#define PEP_DEFAULT_RTT_PROBE_ENABLED       1        /* 默认启用 RTT 主动探测 */
#define PEP_DEFAULT_RTT_PROBE_INTERVAL_MS   1000     /* 探测间隔 1s */
#define PEP_DEFAULT_RTT_PROBE_IDLE_MS       500      /* 空闲超过 500ms 才探测 */

/* Local retrans (downlink cache) defaults */
/* v108: Increased for high-BDP links (200Mbps × 200ms = 5MB BDP) */
#define PEP_DEFAULT_LOCAL_RETRANS_MAX_PKTS  4096
#define PEP_DEFAULT_LOCAL_RETRANS_MAX_BYTES (32 * 1024 * 1024)

/* v111: Anti-hang limits */
#define PEP_WAN_TX_MAX_BATCH            64      /* Max packets per WAN TX work invocation */

/* Shaper / policy defaults */
#define PEP_DEFAULT_SHAPER_ENABLED       1
#define PEP_DEFAULT_WAN_KBPS             0           /* 0 = derive from bandwidth_mbps */
#define PEP_DEFAULT_WAN_IN_KBPS          0           /* 0 = derive from bandwidth_mbps */
#define PEP_DEFAULT_SM_BURST_MS          16
#define PEP_DEFAULT_SM_BURST_MIN         16000
#define PEP_DEFAULT_SM_BURST_TOLERANCE   32768
#define PEP_DEFAULT_BYPASS_OVERFLOWS     1
#define PEP_DEFAULT_MAX_ACC_FLOW_TX_KBPS 0           /* 0 = unlimited */
#define PEP_DEFAULT_SUBNET_ACC           0

/* Byte cache defaults */
#define PEP_DEFAULT_BYTE_CACHE_ENABLED   0
#define PEP_DEFAULT_BYTE_CACHE_MEM_MB    250
#define PEP_DEFAULT_BYTE_CACHE_DISK_MB   0
#define PEP_DEFAULT_BYTE_CACHE_DISK_PATH "/var/AppEx_Cache"

/* Checksum offload defaults */
#define PEP_DEFAULT_TX_CSUM_ENABLED      0
#define PEP_DEFAULT_RX_CSUM_ENABLED      0

/* Memory tuning defaults */
#define PEP_DEFAULT_MEM_TUNE_ENABLED     0
#define PEP_DEFAULT_MEM_TUNE_LOW_MB      512
#define PEP_DEFAULT_MEM_TUNE_HIGH_MB     2048
#define PEP_DEFAULT_MEM_TUNE_MIN_PCT     50
#define PEP_DEFAULT_MEMPOOL_MAX_CACHE_BYTES 0

/* IP reassembly / downlink reordering defaults */
#define PEP_DEFAULT_IP_REASSEMBLY_ENABLED   1
#define PEP_DEFAULT_SPLIT_DL_ENABLED        1       /* 下行分离加速 (单网口模式关键) */
#define PEP_DEFAULT_DL_REORDER_ENABLED      1
#define PEP_DEFAULT_DL_REORDER_MAX_PKTS     256
#define PEP_DEFAULT_DL_REORDER_TIMEOUT_MS   200

/* Regional Learning 配置 */
#define PEP_REGION_HASH_BITS            10          /* 区域哈希桶数: 2^10 = 1024 */
#define PEP_REGION_MAX_ENTRIES          4096        /* 最大区域数量 */
#define PEP_REGION_DEFAULT_PREFIX_LEN   24          /* 默认聚合前缀: /24 */
#define PEP_REGION_MIN_FLOWS_TO_LEARN   3           /* 最少流数量才更新区域 */
#define PEP_REGION_MIN_BYTES_TO_LEARN   65536       /* 最少字节数才更新区域 (64KB) */
#define PEP_REGION_TIMEOUT_MS           3600000     /* 区域超时: 1小时 */

/* GSO/GRO 配置 */
#define PEP_GSO_MAX_SIZE                65536       /* GSO 最大段大小 */
/*
 * v77: GRO 最大聚合大小从 64KB 减小到 16KB
 *
 * 问题: 64KB 的 GRO 聚合包在 pep_translate_seq_wan_to_lan 中
 *       调用 skb_ensure_writable(skb, skb->len) 可能因内存分配失败
 *       导致包丢失，造成网络挂起。
 *
 * 解决: 减小 GRO 最大大小到 16KB，减少内存压力，
 *       同时降低 GRO 延迟（更快刷新）。
 */
#define PEP_GRO_MAX_SIZE                16384       /* GRO 最大聚合大小 (v77: 64KB -> 16KB) */
#define PEP_GRO_MAX_SEGS                64          /* GRO 最大合并段数 */

/* RSC (Receive Segment Coalescing) defaults */
#define PEP_DEFAULT_RSC_ENABLED         0
#define PEP_DEFAULT_RSC_MAX_SIZE        PEP_GRO_MAX_SIZE
#define PEP_DEFAULT_RSC_TIMEOUT_US      2000        /* 2ms */

/*
 * 内存池配置
 */
#define PEP_MEMPOOL_SKB_SIZE            2048
#define PEP_MEMPOOL_FLOW_SIZE           sizeof(struct pep_flow)
#define PEP_MEMPOOL_PKT_CACHE_NAME      "pep_pkt_cache"
#define PEP_MEMPOOL_FLOW_CACHE_NAME     "pep_flow_cache"

/*
 * 令牌桶配置
 */
#define PEP_DEFAULT_BANDWIDTH_MBPS      10000       /* 默认带宽: 10Gbps */
#define PEP_DEFAULT_BURST_SIZE          1048576     /* 默认突发大小: 1MB */

/*
 * SKB 标记
 */
#define PEP_SKB_MARK                    0x50455000  /* "PEP\0" */
#define PEP_SKB_MARK_FAKE_ACK           0x50455001  /* Fake ACK */
#define PEP_SKB_MARK_RETRANS            0x50455002  /* 重传包 */

/* Byte cache flags */
#define PEP_BYTE_CACHE_F_ON_DISK        (1U << 0)
#define PEP_BYTE_CACHE_F_WRITE_PENDING  (1U << 1)
#define PEP_BYTE_CACHE_F_READ_PENDING   (1U << 2)
#define PEP_BYTE_CACHE_F_EVICTING       (1U << 3)

struct file;

/*
 * TCP 状态定义 (LAN 侧 - 与客户端通信)
 */
enum pep_tcp_state {
    PEP_TCP_CLOSED = 0,
    PEP_TCP_LISTEN,
    PEP_TCP_SYN_SENT,
    PEP_TCP_SYN_RECV,
    PEP_TCP_ESTABLISHED,
    PEP_TCP_FIN_WAIT_1,
    PEP_TCP_FIN_WAIT_2,
    PEP_TCP_CLOSE_WAIT,
    PEP_TCP_CLOSING,
    PEP_TCP_LAST_ACK,
    PEP_TCP_TIME_WAIT,
    PEP_TCP_STATE_MAX
};

/*
 * WAN 侧连接状态 (与服务器通信)
 *
 * Complete Split-TCP 需要独立管理 WAN 侧连接状态
 * 因为 PEP 主动向服务器发起 SYN，形成独立的半连接
 */
enum pep_wan_state {
    PEP_WAN_CLOSED = 0,         /* 未连接 */
    PEP_WAN_SYN_SENT,           /* 已发送 SYN，等待 SYN-ACK */
    PEP_WAN_ESTABLISHED,        /* 连接已建立 */
    PEP_WAN_CLOSE_WAIT,         /* v92: 服务器主动关闭，收到 FIN，等待本地数据发送完毕 */
    PEP_WAN_FIN_WAIT,           /* 客户端主动关闭，已发送 FIN */
    PEP_WAN_TIME_WAIT,          /* v105: 收到服务器FIN后等待，处理重传和延迟包 */
    PEP_WAN_STATE_MAX
};

/*
 * 流方向定义
 */
enum pep_direction {
    PEP_DIR_LAN_TO_WAN = 0,     /* LAN -> WAN (出站) */
    PEP_DIR_WAN_TO_LAN = 1,     /* WAN -> LAN (入站) */
    PEP_DIR_MAX
};

/*
 * 流标志位索引 (用于 set_bit/test_bit 原子操作)
 *
 * v18 关键修复: 使用原子位操作代替读-改-写
 *
 * 问题: 之前使用 `flow->flags |= FLAG` 或
 *       `smp_store_release(&flow->flags, flow->flags | FLAG)`
 *       这是非原子的读-改-写操作，跨 CPU 并发时可能丢失标志更新
 *
 * 解决: 使用 set_bit/clear_bit/test_bit 原子操作
 *       这些函数保证在 SMP 环境下的原子性
 */
#define PEP_FLOW_F_ACTIVE_BIT           0
#define PEP_FLOW_F_ACCELERATED_BIT      1
#define PEP_FLOW_F_SACK_ENABLED_BIT     2
#define PEP_FLOW_F_WSCALE_ENABLED_BIT   3
#define PEP_FLOW_F_TIMESTAMP_BIT        4
#define PEP_FLOW_F_ECN_BIT              5    /* ECN 能力已协商 */
#define PEP_FLOW_F_SPOOFED_BIT          6    /* TCP Spoofing 激活 */
#define PEP_FLOW_F_SYN_ACKED_BIT        7    /* SYN 已被本地 ACK */
#define PEP_FLOW_F_ESTABLISHED_BIT      8    /* 三次握手完成 */
#define PEP_FLOW_F_CLOSING_BIT          9
#define PEP_FLOW_F_DEAD_BIT             10   /* 标记待删除 */
#define PEP_FLOW_F_GSO_BIT              11   /* GSO 启用 */
#define PEP_FLOW_F_REGION_INIT_BIT      12   /* 从区域缓存初始化 */
#define PEP_FLOW_F_ACK_TIMER_ACTIVE_BIT 13   /* ACK 定时器活动 */
#define PEP_FLOW_F_ECN_CE_SEEN_BIT      14   /* 已收到 CE 标记 */
#define PEP_FLOW_F_FEC_ENABLED_BIT      15   /* FEC 已启用 */
#define PEP_FLOW_F_FASTPATH_BIT         16   /* 快速路径模式 */

/* 掩码定义 (保留用于兼容和调试输出) */
#define PEP_FLOW_F_ACTIVE           (1UL << PEP_FLOW_F_ACTIVE_BIT)
#define PEP_FLOW_F_ACCELERATED      (1UL << PEP_FLOW_F_ACCELERATED_BIT)
#define PEP_FLOW_F_SACK_ENABLED     (1UL << PEP_FLOW_F_SACK_ENABLED_BIT)
#define PEP_FLOW_F_WSCALE_ENABLED   (1UL << PEP_FLOW_F_WSCALE_ENABLED_BIT)
#define PEP_FLOW_F_TIMESTAMP        (1UL << PEP_FLOW_F_TIMESTAMP_BIT)
#define PEP_FLOW_F_ECN              (1UL << PEP_FLOW_F_ECN_BIT)
#define PEP_FLOW_F_SPOOFED          (1UL << PEP_FLOW_F_SPOOFED_BIT)
#define PEP_FLOW_F_SYN_ACKED        (1UL << PEP_FLOW_F_SYN_ACKED_BIT)
#define PEP_FLOW_F_ESTABLISHED      (1UL << PEP_FLOW_F_ESTABLISHED_BIT)
#define PEP_FLOW_F_CLOSING          (1UL << PEP_FLOW_F_CLOSING_BIT)
#define PEP_FLOW_F_DEAD             (1UL << PEP_FLOW_F_DEAD_BIT)
#define PEP_FLOW_F_GSO              (1UL << PEP_FLOW_F_GSO_BIT)
#define PEP_FLOW_F_REGION_INIT      (1UL << PEP_FLOW_F_REGION_INIT_BIT)
#define PEP_FLOW_F_ACK_TIMER_ACTIVE (1UL << PEP_FLOW_F_ACK_TIMER_ACTIVE_BIT)
#define PEP_FLOW_F_ECN_CE_SEEN      (1UL << PEP_FLOW_F_ECN_CE_SEEN_BIT)
#define PEP_FLOW_F_FEC_ENABLED      (1UL << PEP_FLOW_F_FEC_ENABLED_BIT)
#define PEP_FLOW_F_FASTPATH         (1UL << PEP_FLOW_F_FASTPATH_BIT)

/*
 * 五元组结构
 */
struct pep_tuple {
    __be32 src_addr;
    __be32 dst_addr;
    __be16 src_port;
    __be16 dst_port;
    u8     protocol;
    u8     pad[3];
} __packed;

/*
 * TCP 选项信息
 */
struct pep_tcp_options {
    u16 mss;
    u8  wscale;
    u8  sack_ok;
    u32 ts_val;
    u32 ts_ecr;
    struct {
        u32 start;
        u32 end;
    } sack_blocks[4];
    u8  sack_blocks_count;
    u8  pad[3];
};

/*
 * 序列号映射 - Split-TCP 核心
 */
struct pep_seq_state {
    u32 seq_next;           /* 下一个发送序列号 */
    u32 seq_una;            /* 最小未确认序列号 */
    u32 ack_seq;            /* 期望接收的序列号 */
    u32 win;                /* 通告窗口 */
    u8  wscale;             /* 窗口缩放因子 */
    u8  pad[3];
};

/*
 * RTT 估计器
 */
struct pep_rtt_estimator {
    u32 srtt;               /* 平滑 RTT (us << 3) */
    u32 rttvar;             /* RTT 方差 (us << 2) */
    u32 rto;                /* 重传超时 (ms) */
    u32 min_rtt;            /* 最小 RTT (us) */
    u32 max_rtt;            /* 最大 RTT (us) */
    ktime_t last_sample;
    u32 samples;
};

/*
 * ACK Pacing 状态 - 控制 Fake ACK 发送频率
 *
 * 目的: 平滑数据流，避免客户端突发发送导致的缓冲区溢出
 *
 * 工作原理:
 * 1. 收到客户端数据时不立即发送 ACK
 * 2. 累积一定字节数或等待一定时间后发送批量 ACK
 * 3. ACK 间隔根据估算带宽动态调整
 */
struct pep_ack_pacer {
    u32 bytes_received;         /* 自上次 ACK 以来收到的字节数 */
    u32 pending_ack_seq;        /* 待发送的 ACK 序列号 (最新) */
    u32 last_ack_seq;           /* 上次发送的 ACK 序列号 */
    u64 last_ack_time_ns;       /* 上次发送 ACK 的时间 (纳秒) */

    /* ACK 间隔配置 (动态调整) */
    u32 ack_interval_us;        /* ACK 发送间隔 (微秒) */
    u32 bytes_per_ack;          /* 每个 ACK 确认的字节数阈值 */

    /* 高精度定时器 */
    struct hrtimer timer;       /* 延迟发送 ACK 的定时器 */
    bool timer_active;          /* 定时器是否活动 */
    int is_pending;             /* v44: ACK 待发送标志，用于工作项调度 */

    /* 统计信息 */
    u64 acks_sent;              /* 发送的 ACK 总数 */
    u64 acks_batched;           /* 批量 ACK 次数 */
};

/*
 * Re-seq 节点 (用于乱序段跟踪)
 */
struct pep_reseq_node {
    struct list_head list;
    u32 start;
    u32 end;
};

/*
 * Downlink reordering node
 */
struct pep_reorder_node {
    struct list_head list;
    u32 seq;
    u32 end;
    struct sk_buff *skb;
};

struct pep_byte_cache_entry {
    struct rb_node rb;
    struct list_head lru_node;
    struct list_head flow_node;
    struct pep_flow *flow;
    struct sk_buff *skb;
    u32 seq;
    u32 end;
    u32 len;
    u32 flags;
    loff_t disk_off;
    u32 disk_len;
    refcount_t refcnt;
};

/*
 * Scheduler priority
 */
enum pep_sched_prio {
    PEP_SCHED_PRIO_HIGH = 0,
    PEP_SCHED_PRIO_NORMAL = 1,
    PEP_SCHED_PRIO_BULK = 2,
    PEP_SCHED_PRIO_MAX
};

enum pep_sched_dir {
    PEP_SCHED_DIR_WAN = 0,
    PEP_SCHED_DIR_LAN = 1
};

struct pep_scheduler {
    spinlock_t lock;
    struct list_head queues[PEP_SCHED_PRIO_MAX];
    struct delayed_work work;
    struct workqueue_struct *wq;
    u32 delay_ms;
    u8 dir;
    u8 work_scheduled;
    u8 resched;
    u16 pad;
};

/*
 * 拥塞控制状态 - 激进模式
 */
struct pep_congestion {
    u32 cwnd;               /* 拥塞窗口 (字节) */
    u32 ssthresh;           /* 慢启动阈值 */
    u32 bytes_in_flight;    /* 在途字节数 */
    u64 bytes_acked;        /* 总已确认字节数 */
    u64 bytes_sent;         /* 总发送字节数 */
    u32 snd_nxt;            /* 下一个发送序列号 */
    u32 snd_una;            /* 最小未确认序列号 */
    u32 high_seq;           /* 最高已发送序列号 */
    u8  ca_state;
    u8  retrans_count;
    u8  dup_ack_count;
    u8  loss_recovery;      /* 丢包恢复中 */

    /* ECN 状态 */
    u8  ecn_enabled;        /* ECN 是否启用 */
    u8  ecn_state;          /* ECN 状态机 */
    u16 ce_count;           /* CE 标记计数 */
    u32 ce_last_seq;        /* 上次 CE 对应的序列号 */

    /* DSACK/误判重传回滚 */
    u32 undo_marker;        /* 触发降窗时的最高序列号 */
    u32 prior_cwnd;         /* 回滚前 cwnd */
    u32 prior_ssthresh;     /* 回滚前 ssthresh */
    u8  undo_pending;       /* 等待 DSACK 回滚 */
    u8  undo_pad[3];
};

/* ECN 状态机 */
#define PEP_ECN_STATE_UNKNOWN   0   /* 未知 */
#define PEP_ECN_STATE_OK        1   /* 正常 */
#define PEP_ECN_STATE_CE        2   /* 收到 CE */
#define PEP_ECN_STATE_CWR       3   /* 已发送 CWR */

#define PEP_CA_OPEN         0
#define PEP_CA_DISORDER     1
#define PEP_CA_CWR          2
#define PEP_CA_RECOVERY     3
#define PEP_CA_LOSS         4

/*
 * ============================================================================
 * RACK (Recent ACKnowledgment) - 基于时间的丢包检测
 *
 * 核心思想: 使用时间戳而非 DUPACK 计数来检测丢包
 * 如果一个段的发送时间比最近确认的段早超过 RTT/4，则认为该段丢失
 *
 * 优势:
 * - 更快的丢包检测（不需要等待 3 个 DUPACK）
 * - 对乱序更鲁棒（不会误判乱序为丢包）
 * - 适用于尾丢包场景
 * ============================================================================
 */
struct pep_rack_state {
    /* RACK 核心状态 */
    ktime_t xmit_time;              /* 最近被 ACK 的段的发送时间 */
    u32 end_seq;                    /* 最近被 ACK 的段的结束序列号 */
    u32 rtt_us;                     /* 用于 RACK 检测的 RTT (微秒) */

    /* RACK 检测阈值 */
    u32 reord_wnd_us;               /* 乱序窗口 = RTT/4 (微秒) */
    u32 min_rtt_us;                 /* 最小 RTT (用于计算乱序窗口) */

    /* RACK 丢包检测 */
    u32 sacked;                     /* 已被 SACK 确认的字节数 */
    u32 lost;                       /* RACK 检测到的丢失字节数 */
    u32 reord;                      /* 检测到的乱序程度 */

    /* DSACK 统计 */
    u32 dsack_seen;                 /* 收到的 DSACK 数量 */

    /* 标志位 */
    u8 advanced;                    /* RACK xmit_time 是否有更新 */
    u8 fack_enabled;                /* Forward ACK 启用 */
    u8 pad[2];
};

/*
 * ============================================================================
 * TLP (Tail Loss Probe) - 尾丢包探测
 *
 * 核心思想: 在 PTO (Probe Timeout) 后发送探测包，而不是等待 RTO
 *
 * PTO = max(2*SRTT + max(RTO_MIN, 2*RTTvar), 10ms)
 *
 * 工作流程:
 * 1. 发送完最后一个数据包后启动 PTO 定时器
 * 2. 如果 PTO 超时前没有收到 ACK，发送 TLP
 *    - 如果有新数据: 发送新数据段
 *    - 如果没有新数据: 重传最后一个段
 * 3. TLP 触发 ACK 回复，揭示丢包情况
 *
 * 优势:
 * - 比 RTO 更快发现尾丢包 (RTO 典型 200ms+, PTO 典型 < 50ms)
 * - 避免在尾丢包场景的长时间等待
 * ============================================================================
 */

/* TLP 配置常量 */
#define PEP_TLP_MAX_PROBES          2           /* 最大 TLP 探测次数 */
#define PEP_TLP_MIN_PTO_US          10000       /* 最小 PTO: 10ms */
#define PEP_TLP_PTO_MULTIPLIER      2           /* PTO = 2*SRTT + RTTvar */

/*
 * WAN SYN Timer 配置 (Complete Split-TCP)
 *
 * PEP 主动向服务器发起 SYN，需要超时重传机制
 */
#define PEP_WAN_SYN_MAX_RETRIES     5           /* 最大 SYN 重试次数 */
#define PEP_WAN_SYN_INIT_RTO_MS     1000        /* 初始 SYN RTO: 1秒 */
#define PEP_WAN_SYN_MAX_RTO_MS      32000       /* 最大 SYN RTO: 32秒 */
#define PEP_WAN_SYN_FAIL_OPEN_MS   5000        /* WAN SYN 失败后 fail-open 窗口 */

struct pep_tlp_state {
    /* TLP 定时器 */
    struct hrtimer timer;           /* 高精度 PTO 定时器 */
    bool timer_active;              /* 定时器是否活动 */

    /* TLP 状态 */
    u32 pto_us;                     /* 当前 PTO 值 (微秒) */
    u32 high_seq;                   /* TLP 发送时的最高序列号 */
    ktime_t last_sent;              /* 最后一次发送数据的时间 */

    /* TLP 统计 */
    u8 probes_sent;                 /* 发送的 TLP 探测次数 */
    u8 probes_lost;                 /* TLP 也丢失的次数 */
    u8 is_pending;                  /* 是否有待发送的 TLP */
    u8 pad;

    u64 total_tlp_sent;             /* 总 TLP 发送次数 */
    u64 total_tlp_recoveries;       /* TLP 成功恢复的次数 */
};

/*
 * ============================================================================
 * Pacing Engine - 包发送 Pacing
 *
 * 目的: 平滑发送，避免突发导致的网络拥塞和丢包
 *
 * 原理:
 * - 根据估计的带宽计算每个包的发送间隔
 * - 使用高精度定时器控制发送时机
 * - 与拥塞控制配合，实现平滑的数据发送
 *
 * 公式:
 * - pacing_rate = cwnd / srtt (bytes/second)
 * - inter_packet_interval = packet_size / pacing_rate (seconds)
 * ============================================================================
 */

/* Pacing 配置常量 */
#define PEP_PACING_MIN_INTERVAL_US      50          /* 最小间隔: 50us */
#define PEP_PACING_MAX_INTERVAL_US      10000       /* 最大间隔: 10ms */
#define PEP_PACING_BURST_PACKETS        4           /* 突发允许的包数 */
#define PEP_PACING_GAIN_PERCENT         120         /* Pacing rate 增益: 120% */
#define PEP_PACING_MIN_RATE_PERCENT     50          /* 最小 pacing rate (占链路带宽百分比) */

struct pep_pacing_state {
    /* Pacing 定时器 */
    struct hrtimer timer;           /* 高精度 pacing 定时器 */
    bool timer_active;              /* 定时器是否活动 */

    /* Pacing 速率 */
    u64 pacing_rate_bps;            /* 当前 pacing 速率 (bits/s) */
    u32 inter_packet_us;            /* 包间隔 (微秒) */

    /* 发送时机控制 */
    ktime_t next_send_time;         /* 下一个允许发送的时间 */
    u32 tokens;                     /* 可发送的 token (包数) */
    u32 max_tokens;                 /* 最大 token 数 (burst) */

    /* 统计 */
    u64 packets_paced;              /* Pacing 发送的包数 */
    u64 packets_burst;              /* 突发发送的包数 */
    u64 pacing_delays;              /* Pacing 延迟次数 */
};

/*
 * ============================================================================
 * FEC (Forward Error Correction) - 前向纠错
 *
 * 用于高丢包链路（卫星、无线、蜂窝）的主动冗余保护
 *
 * 原理:
 * - 发送 K 个数据包后，生成 N-K 个 FEC 包
 * - FEC 包是数据包的 XOR 组合
 * - 接收端可以从任意 K 个包（数据或 FEC）恢复所有数据
 *
 * 实现:
 * - 使用简单 XOR 编码（低 CPU 开销）
 * - 支持动态调整 K/N 比例
 * - 自动根据丢包率调整冗余度
 * ============================================================================
 */

/* FEC 包类型 */
#define PEP_FEC_PKT_DATA        0       /* 数据包 */
#define PEP_FEC_PKT_FEC         1       /* FEC 冗余包 */

/* FEC 头部标识 */
#define PEP_FEC_MAGIC           0x50455046  /* 'PEPF' */
#define PEP_FEC_VERSION         1

/* FEC 头部 (添加在 TCP payload 前) */
struct pep_fec_header {
    __be32 magic;           /* 魔术字，用于区分普通 TCP payload */
    u8  version;            /* FEC 头版本 */
    u8  type;               /* 包类型: DATA 或 FEC */
    u8  block_id;           /* 块 ID (0-255 循环) */
    u8  pkt_idx;            /* 包在块内的索引 (0 to N-1) */
    u8  k;                  /* 此块的 K 值 */
    u8  n;                  /* 此块的 N 值 */
    u8  reserved[2];
    __be32 original_len;    /* 原始数据长度 */
} __packed;

#define PEP_FEC_HEADER_SIZE     sizeof(struct pep_fec_header)

/* FEC 编码器状态 (发送端) */
struct pep_fec_encoder {
    u8  block_id;                           /* 当前块 ID */
    u8  pkt_count;                          /* 当前块中的包数 */
    u8  k;                                  /* K 值 */
    u8  n;                                  /* N 值 */

    u32 block_seq_base;                     /* 块起始序列号 */

    /* 数据包缓存 (用于生成 FEC) */
    struct sk_buff *data_pkts[PEP_FEC_MAX_K];
    u32 data_lens[PEP_FEC_MAX_K];

    /* FEC 生成缓冲区 */
    u8  *fec_buffer;                        /* XOR 累积缓冲区 */
    u32 fec_buffer_len;                     /* 缓冲区长度 */

    /* 统计 */
    u64 blocks_encoded;                     /* 编码的块数 */
    u64 fec_pkts_sent;                      /* 发送的 FEC 包数 */
};

/* FEC 解码器状态 (接收端) */
struct pep_fec_decoder {
    u8  block_id;                           /* 当前块 ID */
    u8  received_count;                     /* 已收到的包数 */
    u8  k;                                  /* 期望的 K 值 */
    u8  n;                                  /* 期望的 N 值 */

    u32 block_seq_base;                     /* 块起始序列号 */
    u32 fec_payload_len;                    /* FEC 原始 payload 长度 */

    /* 接收包缓存 */
    struct sk_buff *received_pkts[PEP_FEC_MAX_K + 1];  /* +1 for FEC */
    u64 received_mask;                      /* 已收到包的位掩码 */
    bool has_fec;                           /* 是否收到 FEC 包 */

    /* FEC 恢复缓冲区 */
    u8  *recover_buffer;

    /* 统计 */
    u64 blocks_decoded;                     /* 解码的块数 */
    u64 pkts_recovered;                     /* FEC 恢复的包数 */
    u64 unrecoverable;                      /* 无法恢复的块数 */
};

/* 流的 FEC 状态 */
struct pep_fec_state {
    bool enabled;                           /* 是否启用 */
    struct pep_fec_encoder encoder;         /* 编码器 (LAN->WAN) */
    struct pep_fec_decoder decoder;         /* 解码器 (WAN->LAN) */

    /* 自适应 FEC 参数 */
    u32 loss_rate_ppm;                      /* 观测丢包率 */
    u32 target_recovery_rate;               /* 目标恢复率 */
    ktime_t last_adjust_time;               /* 上次调整时间 */
};

/*
 * 队列管理器 (BDP-aware 动态调整)
 *
 * 核心改进:
 * 1. 动态容量: effective_max = max(config_max, BDP × multiplier)
 * 2. 背压机制: 当队列接近满时，减慢 ACK 发送速度
 * 3. 统计监控: 峰值使用率、背压事件
 */
struct pep_queue {
    struct sk_buff_head queue;
    spinlock_t lock;

    /* 当前状态 */
    u32 bytes;              /* 当前队列字节数 */
    u32 packets;            /* 当前队列包数 */

    /* 容量限制 */
    u32 min_bytes;          /* 最小队列大小 */
    u32 max_bytes;          /* 配置的最大队列大小 */
    u32 effective_max;      /* BDP-aware 动态最大值 */
    u32 absolute_max;       /* 绝对上限 (防止内存耗尽) */

    /* BDP 估计 */
    u32 bdp_estimate;       /* 当前 BDP 估计值 (字节) */
    u32 bdp_multiplier;     /* BDP 乘数 (默认 2) */

    /* 背压状态 */
    u8 backpressure_level;  /* 0=正常, 1=80%, 2=90%+ */
    u8 pad[3];

    /* 统计 */
    u64 total_enqueued;     /* 总入队数 */
    u64 total_dropped;      /* 总丢弃数 (容量不足) */
    u32 peak_bytes;         /* 峰值使用字节 */
    u32 peak_packets;       /* 峰值使用包数 */
    u64 backpressure_events;/* 背压触发次数 */
};

/*
 * SKB Control Block - 存储在 skb->cb 中
 * 用于跟踪重传队列中的包元数据
 */
struct pep_skb_cb {
    ktime_t tx_time;        /* 发送时间 (用于 RTT 计算) */
    u32 seq;                /* 数据起始序列号 */
    u32 len;                /* 数据长度 */
    u8 retrans_count;       /* 重传次数 */
    u8 flags;               /* 标志位 */
    u8 pad[2];
};

/*
 * pep_skb_cb flags
 *
 * v37: 用于标记 SKB 的序列号状态，避免双重翻译
 */
#define PEP_SKB_F_WAN_SEQ       0x01    /* 序列号已在 WAN 空间 (已翻译) */
#define PEP_SKB_F_REQUEUED      0x02    /* 部分发送后重新入队的包 */

/*
 * 流表条目 - 传输控制块 (TCB)
 */
struct pep_flow {
    /* RCU 和链表 - 必须在最前面 */
    struct hlist_node hnode;
    struct rcu_head rcu;
    struct list_head list;          /* 通用链表节点 */

    /* 流标识 */
    struct pep_tuple tuple;
    u32 hash;

    /* 状态 */
    enum pep_tcp_state state;
    unsigned long flags;        /* v18: 使用 unsigned long 支持原子位操作 */

    /* Split-TCP 两端状态 */
    struct pep_seq_state lan;       /* LAN 侧状态 */
    struct pep_seq_state wan;       /* WAN 侧状态 */

    /* TCP 选项 */
    struct pep_tcp_options lan_opts;
    struct pep_tcp_options wan_opts;
    u16 mss;
    u16 pad1;

    /*
     * 序列号偏移量 (Split-TCP 核心)
     *
     * 在 Spoofing 模式下，PEP 向客户端使用自己生成的 ISN (ISN_pep)
     * 而服务器使用自己的 ISN (ISN_server)
     *
     * seq_offset = ISN_pep - ISN_server
     *
     * 转换规则:
     *   WAN -> LAN: new_seq = server_seq + seq_offset
     *   LAN -> WAN: ACK 序列号不需要转换（客户端 ACK 的是 ISN_pep 空间）
     */
    s32 seq_offset;                 /* SEQ 偏移: ISN_pep - ISN_server */
    u32 isn_pep;                    /* PEP 生成的 ISN (用于 LAN 侧) */
    u32 isn_server;                 /* 服务器的 ISN (用于 WAN 侧) */

    /*
     * Complete Split-TCP 扩展字段 (v27)
     *
     * 完整拆分 TCP 需要四个 ISN 空间:
     *   ISN_client:   客户端原始 ISN
     *   ISN_pep_lan:  PEP 向客户端使用的 ISN (即 isn_pep)
     *   ISN_pep_wan:  PEP 向服务器发起的 ISN
     *   ISN_server:   服务器的 ISN
     *
     * 两个序列号偏移:
     *   seq_offset = ISN_pep_lan - ISN_server (WAN->LAN SEQ 转换)
     *   c2w_seq_offset = ISN_pep_wan - ISN_client (Client->WAN SEQ/ACK 转换)
     *
     * 转换规则:
     *   Client DATA -> WAN: new_seq = client_seq + c2w_seq_offset
     *   WAN ACK -> Client:  new_ack = wan_ack - c2w_seq_offset
     */
    u32 isn_client;                 /* 客户端原始 ISN */
    u32 isn_pep_wan;                /* PEP 生成的 ISN (WAN 侧 SYN) */
    s32 c2w_seq_offset;             /* Client<->WAN 偏移: ISN_pep_wan - ISN_client */

    /* WAN 侧连接状态管理 (Complete Split-TCP) */
    enum pep_wan_state wan_state;   /* WAN 侧连接状态 */
    u8 wan_syn_retries;             /* WAN SYN 重试次数 */
    u8 wan_syn_rst_pending;         /* v80: RST 待发送标志 (用于 workqueue) */
    u8 wan_syn_pad[2];              /* 对齐填充 */
    u32 wan_syn_rto_ms;             /* WAN SYN RTO (毫秒) */
    u64 wan_syn_start_ns;           /* WAN SYN 起始时间 */
    struct hrtimer wan_syn_timer;   /* WAN SYN 重传定时器 */
    struct work_struct wan_syn_rst_work;  /* v80: RST 发送工作项 (避免 timer context 问题) */
    bool wan_syn_timer_active;      /* 定时器是否活动 */
    u8 wan_syn_retransmit;          /* WAN SYN 重传触发标志 */
    u8 wan_syn_direct;              /* 复用原始 SYN (单接口直通) */
    u8 ecn_requested;               /* 客户端请求 ECN */
    u8 ecn_ece_pending;             /* 回报 ECE 待发送 */
    u8 ecn_pad[2];

    /* 拥塞控制 */
    struct pep_congestion cc;
    struct pep_rtt_estimator rtt;

    /* ACK Pacing - 控制 Fake ACK 发送频率 */
    struct pep_ack_pacer ack_pacer;

    /* Self-Learning CC state (pointer to avoid large inline struct) */
    struct pep_learning_state *learning_state;

    /* 双向队列 */
    struct pep_queue lan_to_wan;    /* LAN->WAN 队列 */
    struct pep_queue wan_to_lan;    /* WAN->LAN 队列 */

    /* 重传管理 */
    struct sk_buff_head rtx_queue;  /* 待确认队列 */
    spinlock_t rtx_lock;
    u32 rtx_bytes;

    /* LAN 侧本地重传缓存 (下行) */
    struct sk_buff_head lan_rtx_queue;
    spinlock_t lan_rtx_lock;
    u32 lan_rtx_bytes;
    u32 lan_rtx_max_bytes;
    u32 lan_rtx_max_pkts;
    u64 lan_rtx_dropped;
    u64 lan_retrans_packets;
    u32 lan_last_ack;
    u32 lan_dup_acks;

    /* RACK/TLP - 快速丢包检测与恢复 */
    struct pep_rack_state rack;     /* RACK 状态 */
    struct pep_tlp_state tlp;       /* TLP 状态 */

    /* Pacing Engine - 发送速率控制 */
    struct pep_pacing_state pacing; /* Pacing 状态 */

    /* FEC - Forward Error Correction for high-loss links */
    struct pep_fec_state fec;       /* FEC 状态 */

    /* WAN 侧发送状态 (Split-TCP) */
    u32 wan_snd_nxt;                /* WAN 侧下一个发送序列号 */
    u32 wan_snd_una;                /* WAN 侧最小未确认序列号 */
    struct work_struct wan_tx_work; /* WAN 发送工作项 */
    atomic_t wan_tx_pending;        /* 是否有待发送数据 */

    /*
     * Advance ACK Aggregation State (v46)
     *
     * 问题: 之前每收到一个服务器数据包就发送一个 Advance ACK
     *       导致大量 ACK 洪泛（~300 ACK/s），降低下载吞吐
     *
     * 解决: 实现类似 RFC 1122 Delayed ACK 的聚合机制
     *       - 每累积 adv_ack_bytes_threshold 字节发送一个 ACK
     *       - 或者超过 adv_ack_timeout_us 时间发送一个 ACK
     *       - 遵循"至少每 2 个全尺寸段 ACK 一次"原则
     */
    u32 adv_ack_pending_seq;        /* 待发送的 Advance ACK 序列号 */
    u32 adv_ack_pending_bytes;      /* 累积的字节数 */
    u64 adv_ack_last_time_ns;       /* 上次发送 Advance ACK 的时间 */
    u64 adv_ack_sent_count;         /* Advance ACK 发送统计 */
    struct hrtimer adv_ack_timer;   /* Advance ACK 超时定时器 */
    spinlock_t adv_ack_lock;        /* Advance ACK 状态锁 */
    bool adv_ack_timer_active;      /* 定时器是否活动 */
    bool adv_ack_send_pending;      /* 待发送标志 */
    u8 adv_ack_pad[6];

    /* Re-seq 跟踪 (仅用于 ACK 计算，避免错误确认乱序段) */
    struct list_head reseq_list;    /* 乱序段范围列表 */
    spinlock_t reseq_lock;          /* 乱序列表锁 */
    u32 reseq_next;                 /* 下一期待序列号 (服务器空间) */
    u32 reseq_max;                  /* 最大乱序段数量 */
    u32 reseq_queued;               /* 当前乱序段数量 */
    u64 reseq_dropped;              /* 乱序段溢出丢弃 */
    u8 reseq_enabled;               /* 是否启用 re-seq */
    u8 reseq_initialized;           /* 是否已初始化 */
    u16 reseq_pad;

    /* Downlink reordering (WAN->LAN payload sequencing) */
    struct list_head reorder_list;
    spinlock_t reorder_lock;
    u32 reorder_next;
    u32 reorder_max;
    u32 reorder_queued;
    u64 reorder_dropped;
    u8 reorder_enabled;
    u8 reorder_initialized;
    u16 reorder_pad;
    ktime_t reorder_last_activity;

    /* Byte cache (WAN->LAN payload caching) */
    struct rb_root byte_cache_root;
    struct list_head byte_cache_list;
    spinlock_t byte_cache_lock;
    u64 byte_cache_bytes;
    u32 byte_cache_entries;
    u8 byte_cache_enabled;
    u8 byte_cache_pad[3];

    /* RTT probe state */
    u8 rtt_probe_enabled;
    u8 rtt_probe_pending;
    u16 rtt_probe_pad;
    u32 rtt_probe_ack_seq;
    ktime_t rtt_probe_sent_time;
    ktime_t rtt_probe_last_time;

    /* Scheduler state */
    struct list_head sched_node_wan;
    struct list_head sched_node_lan;
    u8 sched_prio;
    u8 sched_queued_wan;
    u8 sched_queued_lan;
    u8 sched_pad;
    u16 engine_id;
    u16 engine_pad;

    /* LAN 侧发送状态 (Split-TCP) */
    u32 lan_snd_nxt;                /* LAN 侧下一个发送序列号 */
    u32 lan_snd_una;                /* LAN 侧最小未确认序列号 */
    struct work_struct lan_tx_work; /* LAN 发送工作项 */
    atomic_t lan_tx_pending;        /* 是否有待发送数据 */

    /*
     * GRO (Generic Receive Offload) 状态
     *
     * 用于聚合接收的小包成大包，减少包处理开销
     * 特别适用于高带宽下载场景
     */
    struct sk_buff_head gro_queue;  /* GRO 聚合队列 */
    spinlock_t gro_lock;            /* GRO 队列锁 */
    u32 gro_max_size;               /* 最大聚合包大小 */
    ktime_t gro_last_flush;         /* 上次冲刷时间 */
    u64 gro_pkts_aggregated;        /* 聚合的包数统计 */
    u64 gro_bytes_aggregated;       /* 聚合的字节数统计 */
    struct hrtimer gro_timer;       /* GRO 超时定时器 */
    bool gro_timer_active;          /* GRO 定时器是否活跃 */
    struct work_struct gro_flush_work; /* GRO 超时冲刷工作项 */
    atomic_t gro_flush_pending;     /* GRO 超时冲刷是否已排队 */

    /*
     * RSC (Receive Segment Coalescing) 状态
     *
     * 用于 WAN->LAN 方向发送前聚合小包
     */
    struct sk_buff_head rsc_queue;  /* RSC 聚合队列 */
    spinlock_t rsc_lock;            /* RSC 队列锁 */
    u32 rsc_max_size;               /* 最大聚合包大小 */
    u32 rsc_timeout_us;             /* 超时冲刷 (us) */
    ktime_t rsc_last_flush;         /* 上次冲刷时间 */
    u64 rsc_pkts_aggregated;        /* 聚合包数 */
    u64 rsc_bytes_aggregated;       /* 聚合字节数 */
    u8 rsc_enabled;                 /* 是否启用 RSC */
    u8 rsc_pad[3];

    /* 统计信息 */
    u64 rx_packets;
    u64 rx_bytes;
    u64 tx_packets;
    u64 tx_bytes;
    u64 retrans_packets;
    u64 fake_acks_sent;

    /* v111: Per-flow fake ACK rate limiter */
    unsigned long fake_ack_jiffies;      /* last jiffies tick when budget reset */
    int           fake_ack_budget;       /* remaining fake ACKs this tick */

    /* 时间戳 */
    ktime_t create_time;
    ktime_t last_activity;
    ktime_t last_rtx_time;          /* 上次重传时间 */

    /* 引用计数和锁 */
    refcount_t refcnt;              /* 使用 refcount_t 更安全 */
    spinlock_t lock;

    /* CPU 亲和性 */
    int cpu;                        /* 处理此流的 CPU */

    /*
     * v50 关键修复: 保存原始出站接口
     *
     * 问题: Fake ACK 需要通过物理接口 (如 enp0s5) 发送给客户端
     *       但 pep_send_skb() 使用路由查找，对本地目的地返回 lo (loopback)
     *       导致 Fake ACK 被注入到 loopback 接口，客户端收不到
     *       客户端 TCP 不断重传，上传速度降至 KB/s 级别
     *
     * 解决: 在处理 SYN 时保存 netfilter state->out (出站接口)
     *       发送 Fake ACK 时使用此接口而非路由查找结果
     */
    struct net_device *out_dev;     /* 出站接口 (用于 Fake ACK) */
};

/*
 * v18 关键修复: 原子化的 DEAD 标志操作
 *
 * 问题: 多 CPU 并发设置/检查 DEAD 标志时，如果操作非原子化，
 *       可能导致 DEAD 标志丢失，进而触发 UAF (Use-After-Free)
 *
 * 解决方案:
 *   1. 使用 set_bit() 原子设置 DEAD 标志
 *   2. 使用 smp_mb__before_atomic() 确保之前的写操作可见
 *   3. 使用 test_bit() 原子检查 DEAD 标志
 *
 * 封装成内联函数确保一致性和正确的内存序
 */
static inline void pep_flow_mark_dead(struct pep_flow *flow)
{
    /* 内存屏障确保之前的写操作对其他 CPU 可见 */
    smp_mb__before_atomic();
    set_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags);
    /* set_bit 自带 release 语义，无需额外屏障 */
}

static inline bool pep_flow_is_dead(const struct pep_flow *flow)
{
    return test_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags);
}

/*
 * Per-CPU 统计 (无锁)
 */
struct pep_percpu_stats {
    u64 rx_packets;
    u64 rx_bytes;
    u64 tx_packets;
    u64 tx_bytes;
    u64 fake_acks;
    u64 acks_filtered;  /* 过滤掉的冗余 ACK */
    u64 retrans;
    u64 dropped;
    u64 errors;
    u64 fastpath_packets;  /* Fast Path 处理的包数 */
    u64 adv_acks;          /* Advance ACK 发送计数 */
};

/*
 * 流表管理器
 */
struct pep_flow_table {
    DECLARE_HASHTABLE(flows, PEP_DEFAULT_FLOW_TABLE_BITS);
    raw_spinlock_t lock;            /* 使用 raw_spinlock 更安全 */
    atomic_t count;
    u32 max_flows;
    u32 timeout_ms;
};

/*
 * 令牌桶限速器
 */
struct pep_token_bucket {
    raw_spinlock_t lock;
    u64 tokens;
    u64 rate;                       /* 字节/秒 */
    u64 burst;                      /* 最大突发 (字节) */
    ktime_t last_update;
};

/*
 * 内存池
 */
struct pep_mempool {
    struct kmem_cache *flow_cache;
    atomic_t flow_alloc;
    atomic_t flow_free;
    u64 max_cache_bytes;
};

/*
 * ============================================================================
 * Regional Learning - 区域学习
 *
 * 按 IP 前缀聚合学习，让新流可以快速继承历史经验
 * ============================================================================
 */

/*
 * 区域状态 - 存储每个目标网络的学习结果
 *
 * 由多个流的历史数据聚合而成，用于初始化新流
 */
struct pep_region_state {
    struct hlist_node hnode;        /* 哈希表节点 */
    struct rcu_head rcu;            /* RCU 释放 */

    /* 区域标识 */
    __be32 dst_prefix;              /* 目标 IP 前缀 (网络字节序) */
    u8 prefix_len;                  /* 前缀长度 (默认 24) */
    u8 pad[3];

    /* === 学习到的网络特性 === */
    u32 base_rtt_us;                /* 最小 RTT (RTprop) */
    u32 avg_rtt_us;                 /* 平均 RTT */
    u32 rtt_variance_us;            /* RTT 方差 */
    u32 estimated_bw_kbps;          /* 估算带宽 (kbps) */
    u32 loss_rate_ppm;              /* 丢包率 (百万分之) */

    /* === 最优参数 (从历史流中学习) === */
    u32 optimal_init_cwnd;          /* 最佳初始 CWND */
    u32 optimal_ssthresh;           /* 最佳慢启动阈值 */
    u32 optimal_rto_min_ms;         /* 此区域的最小 RTO */
    u32 optimal_ack_interval_us;    /* 最佳 ACK 间隔 */

    /* === 统计信息 === */
    u32 flow_count;                 /* 到此区域的流数量 */
    u32 active_flows;               /* 当前活跃流 */
    u64 total_bytes;                /* 总传输字节 */
    u64 total_packets;              /* 总包数 */
    u64 total_retrans;              /* 总重传数 */

    /* === 时间戳 === */
    ktime_t create_time;            /* 创建时间 */
    ktime_t last_update;            /* 最后更新时间 */
    ktime_t last_flow_time;         /* 最后一个流的时间 */

    /* === 锁 === */
    spinlock_t lock;
};

/*
 * 区域表 - 管理所有区域
 */
struct pep_region_table {
    DECLARE_HASHTABLE(regions, PEP_REGION_HASH_BITS);
    raw_spinlock_t lock;
    atomic_t count;
    u32 max_regions;
    u8 default_prefix_len;
    u8 pad[3];
    struct kmem_cache *region_cache;
};

/*
 * 全局统计信息
 */
struct pep_stats {
    struct pep_percpu_stats __percpu *percpu;
    atomic64_t active_flows;
    atomic64_t flow_creates;
    atomic64_t flow_destroys;
    atomic64_t wan_syn_sent;
    atomic64_t wan_syn_synack;
    atomic64_t wan_syn_retries;
    atomic64_t wan_syn_retransmit_sent;
    atomic64_t wan_syn_timeouts;
    atomic64_t wan_syn_fail_open;
    atomic64_t wan_syn_max_retries;
    atomic64_t wan_syn_send_fail;
    atomic64_t wan_syn_bypass;
    atomic64_t wan_syn_rst;
};

/*
 * 全局配置
 */
struct pep_config {
    u32 enabled;
    u32 max_flows;
    u32 flow_timeout_ms;

    /* 队列限制 */
    u32 lan_wan_queue_min;
    u32 lan_wan_queue_max;
    u32 wan_lan_queue_min;
    u32 wan_lan_queue_max;

    /* BDP-aware 动态队列配置 */
    u32 queue_bdp_enabled;          /* 启用 BDP 感知队列 */
    u32 queue_bdp_multiplier;       /* BDP 乘数 */
    u32 queue_max_absolute;         /* 绝对上限 (字节) */
    u32 wan_rtt_ms;                 /* Fallback WAN RTT for proxy scenarios (ms) */

    /* RTO 配置 */
    u32 max_retrans;
    u32 rto_min_ms;
    u32 rto_max_ms;
    u32 rto_init_ms;

    /* 拥塞控制 */
    u32 init_cwnd;
    u32 max_cwnd;
    u32 cc_cong_reduction_pct;     /* 拥塞丢包降窗比例 */
    u32 cc_ber_reduction_pct;      /* 随机丢包降窗比例 */
    u32 cc_rtt_inflation_pct;      /* RTT 膨胀阈值 */
    u32 ecn_ce_reduction_pct;      /* ECN CE 降窗比例 */
    u32 ecn_enabled;               /* ECN 协商/标记开关 */
    u32 wan_syn_fail_open_ms;      /* WAN SYN 失败后 bypass 时间窗 */
    u32 wan_syn_max_retries;       /* WAN SYN 最大重试次数 */
    u32 wan_syn_init_rto_ms;       /* WAN SYN 初始 RTO */
    u32 wan_syn_max_rto_ms;        /* WAN SYN 最大 RTO */

    /* 带宽限制 */
    u64 bandwidth_bps;
    u64 burst_size;

    /* Shaper / policy */
    u32 shaper_enabled;
    u32 wan_kbps;
    u32 wan_in_kbps;
    u32 sm_burst_ms;
    u32 sm_burst_min;
    u32 sm_burst_tolerance;
    u32 bypass_overflows;
    u32 max_acc_flow_tx_kbps;
    u32 subnet_acc;
    u32 lan_segment_prefix;
    __be32 lan_segment_addr;
    __be32 lan_segment_mask;
    char lan_segment_str[64];

    /* Byte cache */
    u32 byte_cache_enabled;
    u32 byte_cache_mem_mb;
    u32 byte_cache_disk_mb;
    char byte_cache_disk_path[128];
    u32 mem_tune_enabled;          /* 系统内存调优开关 */
    u32 mem_tune_low_mb;           /* 低水位 (MB) */
    u32 mem_tune_high_mb;          /* 高水位 (MB) */
    u32 mem_tune_min_pct;          /* 最小缩放百分比 */
    u32 mempool_max_cache_bytes;   /* 缓存上限 (bytes, 0=不限制) */

    /* 功能开关 */
    u32 tcp_spoofing;           /* TCP Spoofing 模式 */
    u32 fake_ack;               /* Fake ACK for upload (危险，需要缓冲支持) */
    u32 local_retrans;          /* 本地重传 */
    u32 aggressive_ack;         /* Advance ACK to server (advacc) */
    u32 gso_enabled;            /* GSO 支持 */
    u32 gro_enabled;            /* GRO 支持 */
    u32 rsc_enabled;            /* RSC 支持 */
    u32 rsc_max_size;           /* RSC 最大聚合大小 */
    u32 rsc_timeout_us;         /* RSC 超时 (us) */
    u32 tx_csum_enabled;        /* TX checksum offload */
    u32 rx_csum_enabled;        /* RX checksum 验证 */
    u32 fec_enabled;            /* FEC 支持 (卫星/高丢包链路) */
    u32 fec_k;                  /* FEC K parameter: data packets per block */
    u32 fec_n;                  /* FEC N parameter: total packets per block */
    u32 pmtu_enabled;           /* PMTU Discovery 支持 (v62) */
    u32 pmtu_timeout_ms;        /* PMTU 缓存超时 (毫秒) */
    u32 pmtu_default;           /* PMTU 默认值 */
    u32 fastpath_enabled;       /* Fast Path 优化 (减少 CPU 开销) */
    u32 fastpath_threshold;     /* 进入 Fast Path 的包数阈值 */
    u32 learning_enabled;       /* Self-Learning CC 启用 */
    u32 debug_level;

    /* ACK Pacing 配置 */
    u32 ack_pacing_enabled;     /* 启用 ACK Pacing */
    u32 ack_delay_us;           /* ACK 延迟时间 (微秒), 0 = 自动计算 */
    u32 ack_bytes_threshold;    /* ACK 字节阈值, 0 = 自动 */
    u32 pacing_gain_pct;        /* Pacing 增益百分比 */
    u32 pacing_min_interval_us; /* Pacing 最小间隔 (us) */
    u32 pacing_max_interval_us; /* Pacing 最大间隔 (us) */
    u32 pacing_min_rate_pct;    /* 最小 pacing rate 百分比 */

    /* Re-seq 配置 */
    u32 reseq_enabled;          /* 启用乱序段跟踪 (用于 ACK) */
    u32 reseq_max_packets;      /* 最大乱序段数量 */

    /* Scheduler / classifier */
    u32 sched_enabled;          /* 启用全局调度器 */
    u32 classify_small_flow_bytes;
    u32 engine_num;             /* 引擎数量 (0=自动) */
    u32 task_sched_delay_wan_ms;
    u32 task_sched_delay_lan_ms;

    /* RTT probe */
    u32 rtt_probe_enabled;
    u32 rtt_probe_interval_ms;
    u32 rtt_probe_idle_ms;

    /* Local retrans cache */
    u32 local_retrans_max_pkts;
    u32 local_retrans_max_bytes;

    /* IP reassembly / downlink reorder / split DL */
    u32 ip_reassembly_enabled;
    u32 split_dl_enabled;               /* 下行分离加速: clone+netif_rx, 过滤客户端ACK */
    u32 downlink_reorder_enabled;
    u32 downlink_reorder_max;
    u32 downlink_reorder_timeout_ms;

    /* Regional Learning 配置 */
    u32 region_learning_enabled;    /* 启用区域学习 */
    u32 region_max_entries;         /* 最大区域数量 */
    u8 region_prefix_len;           /* 区域聚合前缀长度 */
    u8 region_pad[3];

    /* 网卡配置 */
    char wan_ifname[IFNAMSIZ];
    char lan_ifname[IFNAMSIZ];
};

/*
 * 工作队列项
 */
struct pep_work_item {
    struct work_struct work;
    struct pep_flow *flow;
    int action;
};

#define PEP_WORK_DESTROY    1
#define PEP_WORK_RETRANS    2
#define PEP_WORK_TIMEOUT    3

/*
 * 系统内存调优状态
 */
struct pep_mem_tune_state {
    u32 base_queue_absolute;
    u32 base_lan_rtx_max_pkts;
    u32 base_lan_rtx_max_bytes;
    u64 base_byte_cache_max_bytes;
    u32 scale_pct;
    u32 pad;
};

/*
 * 全局上下文
 */
struct pep_context {
    struct pep_config config;
    struct pep_flow_table flow_table;
    struct pep_mempool mempool;
    struct pep_token_bucket shaper_lan_wan;
    struct pep_token_bucket shaper_wan_lan;
    struct pep_stats stats;

    /* Regional Learning - 区域学习表 */
    struct pep_region_table region_table;

    /* Self-Learning Congestion Control */
    struct pep_learning_model learning;

    /* Netfilter 钩子 */
    struct nf_hook_ops nf_ops[4];
    int nf_registered;

    /* 工作队列 */
    struct workqueue_struct *wq;

    /* 定时器工作 */
    struct delayed_work gc_work;        /* 垃圾回收 */
    struct delayed_work rtx_work;       /* 重传检查 */
    struct delayed_work rtt_probe_work; /* RTT 主动探测 */

    /* Byte cache */
    spinlock_t byte_cache_lock;
    struct list_head byte_cache_lru;
    u64 byte_cache_bytes;
    u64 byte_cache_max_bytes;
    u64 byte_cache_disk_max_bytes;
    u64 byte_cache_disk_used;
    struct file *byte_cache_file;
    struct workqueue_struct *byte_cache_wq;
    char byte_cache_disk_path[128];
    struct pep_mem_tune_state mem_tune;

    /* Global schedulers */
    u32 engine_num;
    struct workqueue_struct **engine_wq;
    struct pep_scheduler *sched_wan;
    struct pep_scheduler *sched_lan;

    /* procfs */
    struct proc_dir_entry *proc_root;

    /* 网络设备 */
    struct net_device *wan_dev;
    struct net_device *lan_dev;

    /* 状态 */
    atomic_t running;
    atomic_t initialized;
    u64 syn_fail_open_until_ns;
};

/*
 * 全局变量
 */
extern struct pep_context *pep_ctx;

/*
 * 调试宏
 */
#define pep_dbg(fmt, ...) \
    do { \
        if (pep_ctx && pep_ctx->config.debug_level >= 3) \
            pr_debug(PEP_MODULE_NAME ": " fmt, ##__VA_ARGS__); \
    } while (0)

#define pep_info(fmt, ...) \
    pr_info(PEP_MODULE_NAME ": " fmt, ##__VA_ARGS__)

#define pep_warn(fmt, ...) \
    pr_warn(PEP_MODULE_NAME ": " fmt, ##__VA_ARGS__)

#define pep_err(fmt, ...) \
    pr_err(PEP_MODULE_NAME ": " fmt, ##__VA_ARGS__)

/*
 * 辅助宏
 */
#define PEP_TUPLE_HASH(tuple) \
    jhash_3words((tuple)->src_addr, (tuple)->dst_addr, \
                 ((u32)(tuple)->src_port << 16) | (tuple)->dst_port, 0)

#define PEP_SEQ_BEFORE(a, b) ((s32)((a) - (b)) < 0)
#define PEP_SEQ_AFTER(a, b)  ((s32)((a) - (b)) > 0)
#define PEP_SEQ_LEQ(a, b)    ((s32)((a) - (b)) <= 0)
#define PEP_SEQ_GEQ(a, b)    ((s32)((a) - (b)) >= 0)

/*
 * 内联函数 - Per-CPU 统计更新 (无锁)
 */
static inline void pep_stats_inc_rx(u64 bytes)
{
    struct pep_percpu_stats *stats;

    if (!pep_ctx || !pep_ctx->stats.percpu)
        return;

    stats = this_cpu_ptr(pep_ctx->stats.percpu);
    stats->rx_packets++;
    stats->rx_bytes += bytes;
}

static inline void pep_stats_inc_tx(u64 bytes)
{
    struct pep_percpu_stats *stats;

    if (!pep_ctx || !pep_ctx->stats.percpu)
        return;

    stats = this_cpu_ptr(pep_ctx->stats.percpu);
    stats->tx_packets++;
    stats->tx_bytes += bytes;
}

static inline void pep_stats_inc_fake_ack(void)
{
    struct pep_percpu_stats *stats;

    if (!pep_ctx || !pep_ctx->stats.percpu)
        return;

    stats = this_cpu_ptr(pep_ctx->stats.percpu);
    stats->fake_acks++;
}

static inline void pep_stats_inc_acks_filtered(void)
{
    struct pep_percpu_stats *stats;

    if (!pep_ctx || !pep_ctx->stats.percpu)
        return;

    stats = this_cpu_ptr(pep_ctx->stats.percpu);
    stats->acks_filtered++;
}

static inline void pep_stats_inc_dropped(void)
{
    struct pep_percpu_stats *stats;

    if (!pep_ctx || !pep_ctx->stats.percpu)
        return;

    stats = this_cpu_ptr(pep_ctx->stats.percpu);
    stats->dropped++;
}

static inline void pep_stats_inc_retrans(void)
{
    struct pep_percpu_stats *stats;

    if (!pep_ctx || !pep_ctx->stats.percpu)
        return;

    stats = this_cpu_ptr(pep_ctx->stats.percpu);
    stats->retrans++;
}

static inline void pep_stats_inc_fastpath(void)
{
    struct pep_percpu_stats *stats;

    if (!pep_ctx || !pep_ctx->stats.percpu)
        return;

    stats = this_cpu_ptr(pep_ctx->stats.percpu);
    stats->fastpath_packets++;
}

static inline void pep_stats_inc_adv_ack(void)
{
    struct pep_percpu_stats *stats;

    if (!pep_ctx || !pep_ctx->stats.percpu)
        return;

    stats = this_cpu_ptr(pep_ctx->stats.percpu);
    stats->adv_acks++;
}

static inline void pep_stats_inc_wan_syn_sent(void)
{
    if (!pep_ctx)
        return;

    atomic64_inc(&pep_ctx->stats.wan_syn_sent);
}

static inline void pep_stats_inc_wan_syn_synack(void)
{
    if (!pep_ctx)
        return;

    atomic64_inc(&pep_ctx->stats.wan_syn_synack);
}

static inline void pep_stats_inc_wan_syn_retries(void)
{
    if (!pep_ctx)
        return;

    atomic64_inc(&pep_ctx->stats.wan_syn_retries);
}

static inline void pep_stats_inc_wan_syn_retransmit_sent(void)
{
    if (!pep_ctx)
        return;

    atomic64_inc(&pep_ctx->stats.wan_syn_retransmit_sent);
}

static inline void pep_stats_inc_wan_syn_timeouts(void)
{
    if (!pep_ctx)
        return;

    atomic64_inc(&pep_ctx->stats.wan_syn_timeouts);
}

static inline void pep_stats_inc_wan_syn_fail_open(void)
{
    if (!pep_ctx)
        return;

    atomic64_inc(&pep_ctx->stats.wan_syn_fail_open);
}

static inline void pep_stats_inc_wan_syn_max_retries(void)
{
    if (!pep_ctx)
        return;

    atomic64_inc(&pep_ctx->stats.wan_syn_max_retries);
}

static inline void pep_stats_inc_wan_syn_send_fail(void)
{
    if (!pep_ctx)
        return;

    atomic64_inc(&pep_ctx->stats.wan_syn_send_fail);
}

static inline void pep_stats_inc_wan_syn_bypass(void)
{
    if (!pep_ctx)
        return;

    atomic64_inc(&pep_ctx->stats.wan_syn_bypass);
}

static inline void pep_stats_inc_wan_syn_rst(void)
{
    if (!pep_ctx)
        return;

    atomic64_inc(&pep_ctx->stats.wan_syn_rst);
}

/*
 * 函数声明 - pep_mempool.c
 */
int pep_mempool_init(struct pep_mempool *pool);
void pep_mempool_exit(struct pep_mempool *pool);
struct pep_flow *pep_mempool_alloc_flow(struct pep_mempool *pool);
void pep_mempool_free_flow(struct pep_mempool *pool, struct pep_flow *flow);

/*
 * 函数声明 - pep_flow.c
 */
int pep_flow_table_init(struct pep_flow_table *table, u32 max_flows, u32 timeout_ms);
void pep_flow_table_exit(struct pep_flow_table *table);
void pep_flow_table_cancel_all_timers(struct pep_flow_table *table);
struct pep_flow *pep_flow_find(struct pep_flow_table *table,
                                const struct pep_tuple *tuple);
struct pep_flow *pep_flow_find_reverse(struct pep_flow_table *table,
                                        const struct pep_tuple *tuple);
/* v94: 查找流用于序列号翻译（包括 DEAD 流） */
struct pep_flow *pep_flow_find_for_translation(struct pep_flow_table *table,
                                                const struct pep_tuple *tuple);
struct pep_flow *pep_flow_find_reverse_for_translation(struct pep_flow_table *table,
                                                        const struct pep_tuple *tuple);
struct pep_flow *pep_flow_create(struct pep_flow_table *table,
                                  const struct pep_tuple *tuple);
void pep_flow_destroy(struct pep_flow *flow);
void pep_flow_get(struct pep_flow *flow);
void pep_flow_put(struct pep_flow *flow);
void pep_flow_update_activity(struct pep_flow *flow);
const char *pep_flow_state_str(enum pep_tcp_state state);

/*
 * 函数声明 - pep_netfilter.c
 */
int pep_netfilter_init(struct pep_context *ctx);
void pep_netfilter_exit(struct pep_context *ctx);

/*
 * 函数声明 - pep_engine.c
 */
int pep_engine_init(struct pep_context *ctx);
void pep_engine_exit(struct pep_context *ctx);
unsigned int pep_engine_process(struct pep_context *ctx, struct sk_buff *skb,
                                 enum pep_direction dir);
void pep_parse_tcp_options(const struct tcphdr *tcph,
                           struct pep_tcp_options *opts);

/*
 * 函数声明 - pep_spoofing.c
 */
int pep_spoofing_handle_syn(struct pep_context *ctx, struct pep_flow *flow,
                             struct sk_buff *skb, enum pep_direction dir,
                             struct net_device *out_dev);
int pep_spoofing_handle_synack(struct pep_context *ctx, struct pep_flow *flow,
                                struct sk_buff *skb);
int pep_spoofing_handle_ack(struct pep_context *ctx, struct pep_flow *flow,
                             struct sk_buff *skb, enum pep_direction dir);
int pep_spoofing_handle_data(struct pep_context *ctx, struct pep_flow *flow,
                              struct sk_buff *skb, enum pep_direction dir);
struct sk_buff *pep_create_fake_synack(struct pep_flow *flow);
struct sk_buff *pep_create_fake_ack(struct pep_flow *flow, u32 seq, u32 ack);
int pep_translate_seq_wan_to_lan(struct pep_flow *flow, struct sk_buff *skb);
int pep_translate_ack_lan_to_wan(struct pep_flow *flow, struct sk_buff *skb);
int pep_send_lan_skb(struct pep_flow *flow, struct sk_buff *skb);
int pep_send_wan_skb(struct sk_buff *skb);
void pep_wan_tx_work_handler(struct work_struct *work);
void pep_lan_tx_work_handler(struct work_struct *work);
void pep_schedule_wan_tx(struct pep_flow *flow);
void pep_schedule_lan_tx(struct pep_flow *flow);

/*
 * 函数声明 - Complete Split-TCP WAN SYN Management
 */
int pep_wan_syn_send(struct pep_flow *flow, struct sk_buff *orig_syn);
int pep_wan_syn_rewrite(struct pep_flow *flow, struct sk_buff *skb);
void pep_wan_syn_timer_init(struct pep_flow *flow);
void pep_wan_syn_timer_start(struct pep_flow *flow);
void pep_wan_syn_timer_stop(struct pep_flow *flow);
bool pep_wan_syn_timer_cleanup(struct pep_flow *flow);
int pep_translate_seq_client_to_wan(struct pep_flow *flow, struct sk_buff *skb);
int pep_translate_ack_wan_to_client(struct pep_flow *flow, struct sk_buff *skb);

/*
 * v89: WAN 侧 FIN 发送 (完整 Split-TCP 连接终止)
 *
 * 当客户端发送 FIN 时，PEP 需要向 WAN 服务器也发送 FIN
 * 以正确终止 Split-TCP 的 WAN 侧连接
 */
int pep_send_wan_fin(struct pep_flow *flow);

/*
 * 函数声明 - ACK Pacing
 */
void pep_ack_pacer_init(struct pep_flow *flow);
bool pep_ack_pacer_cleanup(struct pep_flow *flow);
void pep_ack_pacer_queue(struct pep_flow *flow, u32 ack_seq, u32 bytes);
void pep_ack_pacer_flush(struct pep_flow *flow);
void pep_ack_pacer_update_interval(struct pep_flow *flow, u32 bandwidth_kbps);

/* Advance ACK timer */
void pep_adv_ack_init(struct pep_flow *flow);
bool pep_adv_ack_cleanup(struct pep_flow *flow);
void pep_schedule_advance_ack(struct pep_flow *flow, u32 ack_seq, u32 payload_len);

/* Re-seq 跟踪 */
void pep_reseq_init(struct pep_flow *flow, u32 max_packets, bool enabled);
void pep_reseq_cleanup(struct pep_flow *flow);
bool pep_reseq_update(struct pep_flow *flow, u32 seg_start, u32 seg_len, u32 *new_ack);

/* Downlink reordering */
void pep_reorder_init(struct pep_flow *flow, u32 max_packets, bool enabled);
void pep_reorder_cleanup(struct pep_flow *flow);
int pep_reorder_queue(struct pep_flow *flow, struct sk_buff *skb,
                      u32 seq, u32 seg_len);

/* Scheduler / Classifier */
u8 pep_classify_flow(const struct pep_flow *flow);
void pep_scheduler_init(struct pep_scheduler *sched, u8 dir,
                        struct workqueue_struct *wq, u32 delay_ms);
void pep_scheduler_cleanup(struct pep_scheduler *sched);
void pep_scheduler_enqueue(struct pep_scheduler *sched, struct pep_flow *flow);
void pep_scheduler_remove_flow(struct pep_scheduler *sched, struct pep_flow *flow);

/* Local retrans (downlink cache) */
void pep_lan_retrans_init(struct pep_flow *flow, u32 max_pkts, u32 max_bytes, bool enabled);
void pep_lan_retrans_cleanup(struct pep_flow *flow);
int pep_lan_retrans_cache_add(struct pep_flow *flow, struct sk_buff *skb,
                              u32 seq, u32 len);
void pep_lan_retrans_on_ack(struct pep_flow *flow, u32 ack_seq);
bool pep_lan_retrans_can_cache(const struct pep_flow *flow, u32 payload_len);

/* Byte cache */
int pep_byte_cache_init(struct pep_context *ctx);
void pep_byte_cache_exit(struct pep_context *ctx);
void pep_byte_cache_trim(struct pep_context *ctx);
void pep_byte_cache_flow_init(struct pep_flow *flow);
void pep_byte_cache_flow_cleanup(struct pep_flow *flow);
int pep_byte_cache_add(struct pep_flow *flow, struct sk_buff *skb,
                       u32 seq, u32 len);
void pep_byte_cache_on_ack(struct pep_flow *flow,
                           const struct pep_tcp_options *opts,
                           u32 ack_seq);

/* RTT probe */
void pep_rtt_probe_on_ack(struct pep_flow *flow, u32 ack_seq);
void pep_rtt_probe_maybe_send(struct pep_flow *flow);

/*
 * 函数声明 - pep_retrans.c
 */
void pep_retrans_init(struct pep_flow *flow);
int pep_retrans_queue_skb(struct pep_flow *flow, struct sk_buff *skb,
                           u32 seq, u32 len);
u32 pep_retrans_ack_received(struct pep_flow *flow, u32 ack_seq);
int pep_retrans_timeout(struct pep_flow *flow);
u32 pep_retrans_get_next_timeout(struct pep_flow *flow);
int pep_retrans_check_timeouts(struct pep_flow *flow);
void pep_retrans_cleanup(struct pep_flow *flow);
void pep_retrans_get_stats(struct pep_flow *flow, u32 *queued_bytes,
                            u32 *queued_packets);

/*
 * 函数声明 - RACK/TLP (pep_retrans.c)
 */
/* RACK - Recent ACKnowledgment loss detection */
void pep_rack_init(struct pep_flow *flow);
void pep_rack_update(struct pep_flow *flow, u32 acked_seq, ktime_t xmit_time, u32 rtt_us);
int pep_rack_detect_loss(struct pep_flow *flow);
void pep_rack_mark_lost(struct pep_flow *flow, u32 seq, u32 len);

/* TLP - Tail Loss Probe */
void pep_tlp_init(struct pep_flow *flow);
bool pep_tlp_cleanup(struct pep_flow *flow);
void pep_tlp_schedule(struct pep_flow *flow);
void pep_tlp_cancel(struct pep_flow *flow);
int pep_tlp_send_probe(struct pep_flow *flow);
void pep_tlp_on_ack(struct pep_flow *flow, u32 ack_seq);

/* SACK - Selective Acknowledgment */
int pep_retrans_process_sack(struct pep_flow *flow, struct pep_tcp_options *opts,
                             u32 ack_seq);
void pep_sack_mark_lost(struct pep_flow *flow, u32 seq, u32 len);

/*
 * 函数声明 - pep_congestion.c
 */
void pep_cc_init(struct pep_congestion *cc, struct pep_config *config);
void pep_cc_on_ack(struct pep_congestion *cc, u32 acked_bytes, u32 rtt_us);
void pep_cc_on_loss(struct pep_flow *flow);
void pep_cc_on_timeout(struct pep_congestion *cc);
u32 pep_cc_get_send_window(struct pep_congestion *cc);
void pep_rtt_update(struct pep_rtt_estimator *rtt, u32 sample_us);
void pep_cc_flow_update(struct pep_flow *flow, u32 acked_bytes,
                         u32 rtt_us, bool loss_detected);

/* ECN (Explicit Congestion Notification) functions */
bool pep_cc_on_ecn_ce(struct pep_congestion *cc, u32 seq);
void pep_cc_ecn_cwr_acked(struct pep_congestion *cc, u32 ack_seq);
bool pep_is_ecn_ce(const struct iphdr *iph);
bool pep_is_ecn_capable(const struct iphdr *iph);

/*
 * 函数声明 - pep_shaper.c
 */
int pep_shaper_init(struct pep_token_bucket *shaper, u64 rate_bps, u64 burst);
void pep_shaper_exit(struct pep_token_bucket *shaper);
bool pep_shaper_allow(struct pep_token_bucket *shaper, u32 bytes);
void pep_shaper_consume(struct pep_token_bucket *shaper, u32 bytes);
void pep_shaper_update(struct pep_token_bucket *shaper, u64 rate_bps, u64 burst);
void pep_shaper_update_rate(struct pep_token_bucket *shaper, u64 rate_bps);

/* Pacing Engine functions (pep_shaper.c) */
void pep_pacing_init(struct pep_flow *flow);
bool pep_pacing_cleanup(struct pep_flow *flow);
void pep_pacing_update_rate(struct pep_flow *flow);
bool pep_pacing_can_send(struct pep_flow *flow);
void pep_pacing_packet_sent(struct pep_flow *flow, u32 bytes);
void pep_pacing_schedule(struct pep_flow *flow);

/*
 * 函数声明 - pep_queue.c (BDP-aware 动态队列)
 */
void pep_queue_init(struct pep_queue *q, u32 min_bytes, u32 max_bytes);
void pep_queue_init_bdp(struct pep_queue *q, u32 min_bytes, u32 max_bytes,
                        u32 bdp_multiplier, u32 absolute_max);
void pep_queue_destroy(struct pep_queue *q);
int pep_queue_enqueue(struct pep_queue *q, struct sk_buff *skb);
struct sk_buff *pep_queue_dequeue(struct pep_queue *q);
u32 pep_queue_len(struct pep_queue *q);
void pep_queue_update_bdp(struct pep_queue *q, u32 bandwidth_bps, u32 rtt_us);
u8 pep_queue_get_backpressure_level(struct pep_queue *q);

/*
 * 函数声明 - GRO Timer (pep_flow.c)
 */
void pep_gro_timer_start(struct pep_flow *flow);

/*
 * 函数声明 - pep_region.c (Regional Learning)
 */
int pep_region_table_init(struct pep_region_table *table, u32 max_regions, u8 prefix_len);
void pep_region_table_exit(struct pep_region_table *table);
struct pep_region_state *pep_region_lookup(__be32 dst_addr, u8 prefix_len);
struct pep_region_state *pep_region_get_or_create(__be32 dst_addr);
void pep_region_flow_start(struct pep_flow *flow);
void pep_region_flow_end(struct pep_flow *flow);
void pep_region_update_from_flow(struct pep_flow *flow);
void pep_flow_init_from_region(struct pep_flow *flow);

/*
 * 函数声明 - pep_fec.c (Forward Error Correction)
 */
int pep_fec_init(struct pep_flow *flow);
void pep_fec_cleanup(struct pep_flow *flow);
int pep_fec_encoder_add_packet(struct pep_flow *flow, struct sk_buff *skb,
                                u32 seq, u32 len);
struct sk_buff *pep_fec_encoder_generate(struct pep_flow *flow);
bool pep_fec_is_fec_packet(struct sk_buff *skb);
int pep_fec_decoder_add_packet(struct pep_flow *flow, struct sk_buff *skb,
                                u8 block_id, u8 pkt_idx, bool is_fec);
int pep_fec_process_data_packet(struct pep_flow *flow, struct sk_buff *skb, u32 seq);
struct sk_buff *pep_fec_decoder_try_recover(struct pep_flow *flow);
void pep_fec_adjust_params(struct pep_flow *flow, u32 loss_rate_ppm);
void pep_fec_adjust_mss(struct pep_flow *flow);
void pep_fec_get_stats(struct pep_flow *flow, u64 *blocks_encoded,
                        u64 *fec_sent, u64 *pkts_recovered, u64 *unrecoverable);

/*
 * 函数声明 - pep_pmtu.c (Path MTU Discovery)
 */
int pep_pmtu_init(void);
void pep_pmtu_exit(void);
u32 pep_pmtu_get(__be32 dst_addr);
void pep_pmtu_update(__be32 dst_addr, u32 pmtu);
void pep_pmtu_set_defaults(u32 default_pmtu, u32 timeout_ms);
void pep_pmtu_handle_icmp_frag_needed(struct sk_buff *skb);
int pep_pmtu_send_icmp_frag_needed(struct sk_buff *skb, u32 mtu);
u32 pep_pmtu_check_fragmentation(struct sk_buff *skb, __be32 dst_addr);
void pep_pmtu_get_stats(u64 *lookups, u64 *hits, u64 *updates,
                        u64 *icmp_sent, u64 *icmp_received);
void pep_pmtu_adjust_mss(struct pep_flow *flow);

/*
 * 函数声明 - pep_checksum.c
 *
 * 高性能校验和 API:
 * - pep_update_ip_checksum: IP 头校验和
 * - pep_update_tcp_checksum: TCP 校验和 (软件计算)
 * - pep_fast_tcp_checksum: TCP 校验和 (支持硬件 offload)
 * - pep_incremental_csum_update: 增量更新校验和 (用于 SEQ/ACK 修改)
 * - pep_create_tcp_packet: 创建 TCP 包 (软件校验和)
 * - pep_create_tcp_packet_hw: 创建 TCP 包 (硬件 offload)
 */
void pep_update_ip_checksum(struct iphdr *iph);
void pep_update_tcp_checksum(struct sk_buff *skb, struct iphdr *iph,
                             struct tcphdr *tcph);
void pep_fast_tcp_checksum(struct sk_buff *skb, struct iphdr *iph,
                           struct tcphdr *tcph, bool hw_offload);
bool pep_rx_checksum_ok(struct sk_buff *skb);
void pep_incremental_csum_update(__sum16 *sum, __be32 old_val, __be32 new_val,
                                 bool is_partial);
void pep_incremental_csum_update16(__sum16 *sum, __be16 old_val, __be16 new_val,
                                   bool is_partial);
struct sk_buff *pep_create_tcp_packet(struct pep_flow *flow,
                                       u32 seq, u32 ack, u16 flags,
                                       const void *data, u32 data_len);
struct sk_buff *pep_create_tcp_packet_hw(struct pep_flow *flow,
                                          u32 seq, u32 ack, u16 flags,
                                          const void *data, u32 data_len);

/*
 * 函数声明 - pep_main.c
 */
void pep_stats_aggregate(struct pep_stats *stats, struct pep_percpu_stats *total);

/*
 * 函数声明 - pep_gso.c
 * GSO/GRO 硬件卸载支持
 */
struct sk_buff *pep_gso_segment(struct pep_flow *flow, struct sk_buff *skb, u32 mss);
struct sk_buff *pep_gro_receive(struct pep_flow *flow, struct sk_buff *skb,
                                struct sk_buff_head *gro_queue, u32 max_size);
struct sk_buff *pep_gro_timeout_flush(struct sk_buff_head *gro_queue, u32 timeout_us);
bool pep_gso_prepare_tso(struct sk_buff *skb, u32 mss, u32 payload_len);
bool pep_gso_needed(struct sk_buff *skb, u32 mss);
u32 pep_gso_segment_count(struct sk_buff *skb, u32 mss);
int pep_gso_init(void);
void pep_gso_exit(void);

/*
 * 函数声明 - pep_proc.c
 */
int pep_proc_init(struct pep_context *ctx);
void pep_proc_exit(struct pep_context *ctx);

#endif /* _PEP_CORE_H */
