/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"
#include <linux/inet.h>
#include <linux/mm.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("RFC3135 PEP Project");
MODULE_DESCRIPTION("RFC 3135 PEP TCP Accelerator v2.0 - Split-TCP Proxy");
MODULE_VERSION(PEP_VERSION);

static unsigned int enabled = 1;
module_param(enabled, uint, 0644);
MODULE_PARM_DESC(enabled, "Enable PEP (default=1)");

static unsigned int max_flows = PEP_DEFAULT_MAX_FLOWS;
module_param(max_flows, uint, 0644);
MODULE_PARM_DESC(max_flows, "Maximum flows (default=131072)");

static unsigned int flow_timeout = PEP_DEFAULT_FLOW_TIMEOUT_MS;
module_param(flow_timeout, uint, 0644);
MODULE_PARM_DESC(flow_timeout, "Flow timeout ms (default=120000)");

static unsigned int lan_wan_queue_min = PEP_DEFAULT_LAN_WAN_QUEUE_MIN;
module_param(lan_wan_queue_min, uint, 0644);
MODULE_PARM_DESC(lan_wan_queue_min, "LAN->WAN queue min packets");

static unsigned int lan_wan_queue_max = PEP_DEFAULT_LAN_WAN_QUEUE_MAX;
module_param(lan_wan_queue_max, uint, 0644);
MODULE_PARM_DESC(lan_wan_queue_max, "LAN->WAN queue max packets");

static unsigned int wan_lan_queue_min = PEP_DEFAULT_WAN_LAN_QUEUE_MIN;
module_param(wan_lan_queue_min, uint, 0644);
MODULE_PARM_DESC(wan_lan_queue_min, "WAN->LAN queue min packets");

static unsigned int wan_lan_queue_max = PEP_DEFAULT_WAN_LAN_QUEUE_MAX;
module_param(wan_lan_queue_max, uint, 0644);
MODULE_PARM_DESC(wan_lan_queue_max, "WAN->LAN queue max packets");

static unsigned int queue_bdp_enabled = PEP_QUEUE_BDP_ENABLED;
module_param(queue_bdp_enabled, uint, 0644);
MODULE_PARM_DESC(queue_bdp_enabled, "Enable BDP-aware dynamic queue sizing (default=1)");

static unsigned int queue_bdp_multiplier = PEP_QUEUE_BDP_MULTIPLIER;
module_param(queue_bdp_multiplier, uint, 0644);
MODULE_PARM_DESC(queue_bdp_multiplier, "Queue size = BDP * multiplier (default=2)");

static unsigned int queue_max_absolute = PEP_QUEUE_MAX_ABSOLUTE;
module_param(queue_max_absolute, uint, 0644);
MODULE_PARM_DESC(queue_max_absolute, "Absolute max queue size in bytes (default=16MB)");

static unsigned int wan_rtt_ms = PEP_DEFAULT_WAN_RTT_MS;
module_param(wan_rtt_ms, uint, 0644);
MODULE_PARM_DESC(wan_rtt_ms, "Fallback WAN RTT in ms when proxy detected (RTT<10ms) (default=250)");

static unsigned int rto_min = 350;
module_param(rto_min, uint, 0644);
MODULE_PARM_DESC(rto_min, "Minimum RTO ms (default=350)");

static unsigned int rto_max = PEP_DEFAULT_RTO_MAX_MS;
module_param(rto_max, uint, 0644);
MODULE_PARM_DESC(rto_max, "Maximum RTO ms (default=2000)");

static unsigned int rto_init = 400;
module_param(rto_init, uint, 0644);
MODULE_PARM_DESC(rto_init, "Initial RTO ms (default=400)");

static unsigned int wan_syn_fail_open_ms = PEP_WAN_SYN_FAIL_OPEN_MS;
module_param(wan_syn_fail_open_ms, uint, 0644);
MODULE_PARM_DESC(wan_syn_fail_open_ms, "WAN SYN fail-open timeout/window (ms, 0=disable)");

static unsigned int wan_syn_max_retries = PEP_WAN_SYN_MAX_RETRIES;
module_param(wan_syn_max_retries, uint, 0644);
MODULE_PARM_DESC(wan_syn_max_retries, "WAN SYN max retries (default=5)");

static unsigned int wan_syn_init_rto_ms = PEP_WAN_SYN_INIT_RTO_MS;
module_param(wan_syn_init_rto_ms, uint, 0644);
MODULE_PARM_DESC(wan_syn_init_rto_ms, "WAN SYN initial RTO (ms, default=1000)");

static unsigned int wan_syn_max_rto_ms = PEP_WAN_SYN_MAX_RTO_MS;
module_param(wan_syn_max_rto_ms, uint, 0644);
MODULE_PARM_DESC(wan_syn_max_rto_ms, "WAN SYN max RTO (ms, default=32000)");

static unsigned int init_cwnd = PEP_DEFAULT_INIT_CWND;
module_param(init_cwnd, uint, 0644);
MODULE_PARM_DESC(init_cwnd, "Initial CWND (default=32)");

static unsigned int cc_cong_reduction_pct = PEP_DEFAULT_CC_CONG_REDUCTION_PCT;
module_param(cc_cong_reduction_pct, uint, 0644);
MODULE_PARM_DESC(cc_cong_reduction_pct, "CC congestion reduction percent (default=20)");

static unsigned int cc_ber_reduction_pct = PEP_DEFAULT_CC_BER_REDUCTION_PCT;
module_param(cc_ber_reduction_pct, uint, 0644);
MODULE_PARM_DESC(cc_ber_reduction_pct, "CC random loss reduction percent (default=10)");

static unsigned int cc_rtt_inflation_pct = PEP_DEFAULT_CC_RTT_INFLATION_PCT;
module_param(cc_rtt_inflation_pct, uint, 0644);
MODULE_PARM_DESC(cc_rtt_inflation_pct, "CC RTT inflation percent (default=25)");

static unsigned int ecn_ce_reduction_pct = PEP_DEFAULT_ECN_CE_REDUCTION_PCT;
module_param(ecn_ce_reduction_pct, uint, 0644);
MODULE_PARM_DESC(ecn_ce_reduction_pct, "ECN CE reduction percent (default=50)");

static unsigned int ecn_enabled = PEP_DEFAULT_ECN_ENABLED;
module_param(ecn_enabled, uint, 0644);
MODULE_PARM_DESC(ecn_enabled, "Enable ECN negotiation/marking (default=1)");

static unsigned long bandwidth_mbps = PEP_DEFAULT_BANDWIDTH_MBPS;
module_param(bandwidth_mbps, ulong, 0644);
MODULE_PARM_DESC(bandwidth_mbps, "Bandwidth limit Mbps (default=10000)");

static unsigned int shaper_enabled = PEP_DEFAULT_SHAPER_ENABLED;
module_param(shaper_enabled, uint, 0644);
MODULE_PARM_DESC(shaper_enabled, "Enable shaper (default=1)");

static unsigned int wan_kbps = PEP_DEFAULT_WAN_KBPS;
module_param(wan_kbps, uint, 0644);
MODULE_PARM_DESC(wan_kbps, "WAN uplink kbps (0=derive from bandwidth_mbps)");

static unsigned int wan_in_kbps = PEP_DEFAULT_WAN_IN_KBPS;
module_param(wan_in_kbps, uint, 0644);
MODULE_PARM_DESC(wan_in_kbps, "WAN downlink kbps (0=derive from bandwidth_mbps)");

static unsigned int sm_burst_ms = PEP_DEFAULT_SM_BURST_MS;
module_param(sm_burst_ms, uint, 0644);
MODULE_PARM_DESC(sm_burst_ms, "Shaper burst interval ms (default=16)");

static unsigned int sm_burst_min = PEP_DEFAULT_SM_BURST_MIN;
module_param(sm_burst_min, uint, 0644);
MODULE_PARM_DESC(sm_burst_min, "Shaper burst min bytes (default=16000)");

static unsigned int sm_burst_tolerance = PEP_DEFAULT_SM_BURST_TOLERANCE;
module_param(sm_burst_tolerance, uint, 0644);
MODULE_PARM_DESC(sm_burst_tolerance, "Shaper burst tolerance bytes (default=32768)");

static unsigned int bypass_overflows = PEP_DEFAULT_BYPASS_OVERFLOWS;
module_param(bypass_overflows, uint, 0644);
MODULE_PARM_DESC(bypass_overflows, "Bypass acceleration on overload (default=1)");

static unsigned int max_acc_flow_tx_kbps = PEP_DEFAULT_MAX_ACC_FLOW_TX_KBPS;
module_param(max_acc_flow_tx_kbps, uint, 0644);
MODULE_PARM_DESC(max_acc_flow_tx_kbps, "Max per-flow tx kbps (0=unlimited)");

static unsigned int subnet_acc = PEP_DEFAULT_SUBNET_ACC;
module_param(subnet_acc, uint, 0644);
MODULE_PARM_DESC(subnet_acc, "Enable LAN segment filter (default=0)");

static char *lan_segment = NULL;
module_param(lan_segment, charp, 0644);
MODULE_PARM_DESC(lan_segment, "LAN segment CIDR (e.g. 192.168.0.0/24)");

static unsigned int tcp_spoofing = 1;
module_param(tcp_spoofing, uint, 0644);
MODULE_PARM_DESC(tcp_spoofing, "Enable TCP Spoofing (default=1)");

static unsigned int fake_ack = 1;
module_param(fake_ack, uint, 0644);
MODULE_PARM_DESC(fake_ack, "Enable Fake ACK for Split-TCP acceleration (default=1)");

static int advacc = -1;
module_param(advacc, int, 0644);
MODULE_PARM_DESC(advacc, "AppEx advacc: enable advance ACK to server (1=on,0=off,-1=default)");

static int advinacc = -1;
module_param(advinacc, int, 0644);
MODULE_PARM_DESC(advinacc, "AppEx advinacc: enable fake ACK to client (1=on,0=off,-1=use fake_ack)");

static unsigned int local_retrans = 1;
module_param(local_retrans, uint, 0644);
MODULE_PARM_DESC(local_retrans, "Enable local retransmission (default=1)");

static unsigned int local_retrans_max_pkts = PEP_DEFAULT_LOCAL_RETRANS_MAX_PKTS;
module_param(local_retrans_max_pkts, uint, 0644);
MODULE_PARM_DESC(local_retrans_max_pkts, "Local retrans cache max packets (default=1024)");

static unsigned int local_retrans_max_bytes = PEP_DEFAULT_LOCAL_RETRANS_MAX_BYTES;
module_param(local_retrans_max_bytes, uint, 0644);
MODULE_PARM_DESC(local_retrans_max_bytes, "Local retrans cache max bytes (default=8MB)");

static unsigned int byte_cache_enabled = PEP_DEFAULT_BYTE_CACHE_ENABLED;
module_param(byte_cache_enabled, uint, 0644);
MODULE_PARM_DESC(byte_cache_enabled, "Enable byte cache (default=0)");

static unsigned int byte_cache_memory_mb = PEP_DEFAULT_BYTE_CACHE_MEM_MB;
module_param(byte_cache_memory_mb, uint, 0644);
MODULE_PARM_DESC(byte_cache_memory_mb, "Byte cache memory MB (default=250)");

module_param_named(byte_cache_mem_mb, byte_cache_memory_mb, uint, 0644);
MODULE_PARM_DESC(byte_cache_mem_mb, "Alias for byte_cache_memory_mb");

static unsigned int byte_cache_disk_mb = PEP_DEFAULT_BYTE_CACHE_DISK_MB;
module_param(byte_cache_disk_mb, uint, 0644);
MODULE_PARM_DESC(byte_cache_disk_mb, "Byte cache disk MB (default=0)");

static char *byte_cache_disk_path = PEP_DEFAULT_BYTE_CACHE_DISK_PATH;
module_param(byte_cache_disk_path, charp, 0644);
MODULE_PARM_DESC(byte_cache_disk_path, "Byte cache disk path (default=/var/AppEx_Cache)");

static unsigned int mem_tune_enabled = PEP_DEFAULT_MEM_TUNE_ENABLED;
module_param(mem_tune_enabled, uint, 0644);
MODULE_PARM_DESC(mem_tune_enabled, "Enable memory tuning (default=0)");

static unsigned int mem_tune_low_mb = PEP_DEFAULT_MEM_TUNE_LOW_MB;
module_param(mem_tune_low_mb, uint, 0644);
MODULE_PARM_DESC(mem_tune_low_mb, "Memory low watermark MB (default=512)");

static unsigned int mem_tune_high_mb = PEP_DEFAULT_MEM_TUNE_HIGH_MB;
module_param(mem_tune_high_mb, uint, 0644);
MODULE_PARM_DESC(mem_tune_high_mb, "Memory high watermark MB (default=2048)");

static unsigned int mem_tune_min_pct = PEP_DEFAULT_MEM_TUNE_MIN_PCT;
module_param(mem_tune_min_pct, uint, 0644);
MODULE_PARM_DESC(mem_tune_min_pct, "Memory tuning min scale percent (default=50)");

static unsigned int mempool_max_cache_bytes = PEP_DEFAULT_MEMPOOL_MAX_CACHE_BYTES;
module_param(mempool_max_cache_bytes, uint, 0644);
MODULE_PARM_DESC(mempool_max_cache_bytes, "Cache cap in bytes (0=unlimited)");

/* v84: GSO/GRO default disabled - still has stability issues under high load */
static unsigned int gso_enabled = 0;
module_param(gso_enabled, uint, 0644);
MODULE_PARM_DESC(gso_enabled, "Enable GSO support (default=0)");

/* v84: GSO/GRO default disabled - still has stability issues under high load */
static unsigned int gro_enabled = 0;
module_param(gro_enabled, uint, 0644);
MODULE_PARM_DESC(gro_enabled, "Enable GRO support (default=0)");

static unsigned int rsc_enabled = PEP_DEFAULT_RSC_ENABLED;
module_param(rsc_enabled, uint, 0644);
MODULE_PARM_DESC(rsc_enabled, "Enable RSC (default=0)");

static unsigned int rsc_max_size = PEP_DEFAULT_RSC_MAX_SIZE;
module_param(rsc_max_size, uint, 0644);
MODULE_PARM_DESC(rsc_max_size, "RSC max aggregate size (default=65536)");

static unsigned int rsc_timeout_us = PEP_DEFAULT_RSC_TIMEOUT_US;
module_param(rsc_timeout_us, uint, 0644);
MODULE_PARM_DESC(rsc_timeout_us, "RSC timeout us (default=2000)");

static unsigned int tx_csum_enabled = PEP_DEFAULT_TX_CSUM_ENABLED;
module_param(tx_csum_enabled, uint, 0644);
MODULE_PARM_DESC(tx_csum_enabled, "Enable TX checksum offload (default=0)");

static unsigned int rx_csum_enabled = PEP_DEFAULT_RX_CSUM_ENABLED;
module_param(rx_csum_enabled, uint, 0644);
MODULE_PARM_DESC(rx_csum_enabled, "Enable RX checksum validation (default=0)");

static unsigned int pmtu_enabled = 1;
module_param(pmtu_enabled, uint, 0644);
MODULE_PARM_DESC(pmtu_enabled, "Enable PMTU Discovery (default=1)");

static unsigned int pmtu_timeout_ms = PEP_PMTU_TIMEOUT_MS;
module_param(pmtu_timeout_ms, uint, 0644);
MODULE_PARM_DESC(pmtu_timeout_ms, "PMTU cache timeout ms (default=600000)");

static unsigned int pmtu_default = PEP_PMTU_DEFAULT;
module_param(pmtu_default, uint, 0644);
MODULE_PARM_DESC(pmtu_default, "PMTU default size bytes (default=1500)");

static unsigned int fastpath_enabled = PEP_FASTPATH_ENABLED;
module_param(fastpath_enabled, uint, 0644);
MODULE_PARM_DESC(fastpath_enabled, "Enable Fast Path optimization for established flows (default=1)");

static unsigned int fastpath_threshold = PEP_FASTPATH_THRESHOLD_PKTS;
module_param(fastpath_threshold, uint, 0644);
MODULE_PARM_DESC(fastpath_threshold, "Packets threshold to enter Fast Path mode (default=10)");

static unsigned int learning_enabled = 1;
module_param(learning_enabled, uint, 0644);
MODULE_PARM_DESC(learning_enabled, "Enable Self-Learning CC (default=1)");

static unsigned int learning_epsilon_pct = 1;
module_param(learning_epsilon_pct, uint, 0644);
MODULE_PARM_DESC(learning_epsilon_pct, "Self-Learning CC epsilon percent (default=1)");

static unsigned int ack_pacing = PEP_DEFAULT_ACK_PACING;
module_param(ack_pacing, uint, 0644);
MODULE_PARM_DESC(ack_pacing, "Enable ACK pacing for smoother data flow (default=1)");

static unsigned int ack_delay_us = PEP_DEFAULT_ACK_DELAY_US;
module_param(ack_delay_us, uint, 0644);
MODULE_PARM_DESC(ack_delay_us, "ACK delay in microseconds (default=1000, 0=auto)");

static unsigned int ack_bytes_threshold = PEP_DEFAULT_ACK_BYTES_THRESHOLD;
module_param(ack_bytes_threshold, uint, 0644);
MODULE_PARM_DESC(ack_bytes_threshold, "Bytes threshold to trigger immediate ACK (default=16384)");

static unsigned int pacing_gain_pct = PEP_PACING_GAIN_PERCENT;
module_param(pacing_gain_pct, uint, 0644);
MODULE_PARM_DESC(pacing_gain_pct, "Pacing gain percent (default=120)");

static unsigned int pacing_min_interval_us = PEP_PACING_MIN_INTERVAL_US;
module_param(pacing_min_interval_us, uint, 0644);
MODULE_PARM_DESC(pacing_min_interval_us, "Pacing min interval us (default=50)");

static unsigned int pacing_max_interval_us = PEP_PACING_MAX_INTERVAL_US;
module_param(pacing_max_interval_us, uint, 0644);
MODULE_PARM_DESC(pacing_max_interval_us, "Pacing max interval us (default=10000)");

static unsigned int pacing_min_rate_pct = PEP_PACING_MIN_RATE_PERCENT;
module_param(pacing_min_rate_pct, uint, 0644);
MODULE_PARM_DESC(pacing_min_rate_pct, "Min pacing rate percent of link (default=50)");

static unsigned int reseq_enabled = PEP_DEFAULT_RESEQ_ENABLED;
module_param(reseq_enabled, uint, 0644);
MODULE_PARM_DESC(reseq_enabled, "Enable re-seq tracking for WAN ACK (default=1)");

static unsigned int reseq_max_packets = PEP_DEFAULT_RESEQ_PACKET_CNT;
module_param(reseq_max_packets, uint, 0644);
MODULE_PARM_DESC(reseq_max_packets, "Max out-of-order segments tracked (default=128)");

static unsigned int sched_enabled = PEP_DEFAULT_SCHED_ENABLED;
module_param(sched_enabled, uint, 0644);
MODULE_PARM_DESC(sched_enabled, "Enable global scheduler (default=1)");

static unsigned int classify_small_flow_bytes = PEP_DEFAULT_CLASSIFY_SMALL_FLOW_BYTES;
module_param(classify_small_flow_bytes, uint, 0644);
MODULE_PARM_DESC(classify_small_flow_bytes, "Small flow threshold bytes (default=131072)");

static unsigned int engine_num = PEP_DEFAULT_ENGINE_NUM;
module_param(engine_num, uint, 0644);
MODULE_PARM_DESC(engine_num, "Scheduler engine count (0=auto)");

static unsigned int task_sched_delay_wan_ms = PEP_DEFAULT_TASK_SCHED_DELAY_WAN_MS;
module_param(task_sched_delay_wan_ms, uint, 0644);
MODULE_PARM_DESC(task_sched_delay_wan_ms, "WAN scheduler delay ms (default=0)");

static unsigned int task_sched_delay_lan_ms = PEP_DEFAULT_TASK_SCHED_DELAY_LAN_MS;
module_param(task_sched_delay_lan_ms, uint, 0644);
MODULE_PARM_DESC(task_sched_delay_lan_ms, "LAN scheduler delay ms (default=0)");

static unsigned int rtt_probe_enabled = PEP_DEFAULT_RTT_PROBE_ENABLED;
module_param(rtt_probe_enabled, uint, 0644);
MODULE_PARM_DESC(rtt_probe_enabled, "Enable active RTT probe (default=1)");

static unsigned int rtt_probe_interval_ms = PEP_DEFAULT_RTT_PROBE_INTERVAL_MS;
module_param(rtt_probe_interval_ms, uint, 0644);
MODULE_PARM_DESC(rtt_probe_interval_ms, "RTT probe interval ms (default=1000)");

static unsigned int rtt_probe_idle_ms = PEP_DEFAULT_RTT_PROBE_IDLE_MS;
module_param(rtt_probe_idle_ms, uint, 0644);
MODULE_PARM_DESC(rtt_probe_idle_ms, "RTT probe idle threshold ms (default=500)");

static unsigned int ip_reassembly_enabled = PEP_DEFAULT_IP_REASSEMBLY_ENABLED;
module_param(ip_reassembly_enabled, uint, 0644);
MODULE_PARM_DESC(ip_reassembly_enabled, "Enable IP reassembly (default=1)");

static unsigned int split_dl_enabled = PEP_DEFAULT_SPLIT_DL_ENABLED;
module_param(split_dl_enabled, uint, 0644);
MODULE_PARM_DESC(split_dl_enabled, "Enable split downlink acceleration: clone+deliver via netif_rx, filter client ACKs (default=1)");

static unsigned int downlink_reorder_enabled = PEP_DEFAULT_DL_REORDER_ENABLED;
module_param(downlink_reorder_enabled, uint, 0644);
MODULE_PARM_DESC(downlink_reorder_enabled, "Enable downlink reordering (default=1)");

static unsigned int downlink_reorder_max = PEP_DEFAULT_DL_REORDER_MAX_PKTS;
module_param(downlink_reorder_max, uint, 0644);
MODULE_PARM_DESC(downlink_reorder_max, "Max downlink reorder packets (default=256)");

static unsigned int downlink_reorder_timeout_ms = PEP_DEFAULT_DL_REORDER_TIMEOUT_MS;
module_param(downlink_reorder_timeout_ms, uint, 0644);
MODULE_PARM_DESC(downlink_reorder_timeout_ms, "Downlink reorder timeout ms (default=200)");

static unsigned int region_learning = 1;
module_param(region_learning, uint, 0644);
MODULE_PARM_DESC(region_learning, "Enable regional learning for faster flow init (default=1)");

static unsigned int region_max = PEP_REGION_MAX_ENTRIES;
module_param(region_max, uint, 0644);
MODULE_PARM_DESC(region_max, "Maximum number of regions to track (default=4096)");

static unsigned int region_prefix = PEP_REGION_DEFAULT_PREFIX_LEN;
module_param(region_prefix, uint, 0644);
MODULE_PARM_DESC(region_prefix, "Region IP prefix length for aggregation (default=24)");

static unsigned int fec_enabled = 1;
module_param(fec_enabled, uint, 0644);
MODULE_PARM_DESC(fec_enabled, "Enable FEC for high-loss links (default=1)");

static unsigned int fec_k = 10;
module_param(fec_k, uint, 0644);
MODULE_PARM_DESC(fec_k, "FEC K parameter: data packets per block (default=10)");

static unsigned int fec_n = 11;
module_param(fec_n, uint, 0644);
MODULE_PARM_DESC(fec_n, "FEC N parameter: total packets per block (default=11, means 10% redundancy)");

static unsigned int debug_level = 0;
module_param(debug_level, uint, 0644);
MODULE_PARM_DESC(debug_level, "Debug level 0-3 (default=0)");

static char *wan_if = "";
module_param(wan_if, charp, 0644);
MODULE_PARM_DESC(wan_if, "WAN interface name");

static char *lan_if = "";
module_param(lan_if, charp, 0644);
MODULE_PARM_DESC(lan_if, "LAN interface name");

struct pep_context *pep_ctx = NULL;
EXPORT_SYMBOL(pep_ctx);

static void pep_mem_tune_init(struct pep_context *ctx);
static void pep_mem_tune_update(struct pep_context *ctx);

/*
 * 功能/Main: 后台处理垃圾回收/清理（Work task garbage collection/cleanup）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；ACK pacing 调度（ACK pacing scheduling）；定时器/工作队列上下文（timer/workqueue context）；并发同步（spinlock/atomic/rcu）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: work
 * 影响/Effects: 清理过期状态，影响资源占用（clear expired state, affects resource usage）
 * 重要程度/Importance: 中/Medium
 */
static void pep_gc_work_handler(struct work_struct *work)
{
    struct pep_context *ctx = container_of(work, struct pep_context, gc_work.work);
    struct pep_flow *flow;
    struct hlist_node *tmp;
    ktime_t now = ktime_get();
    ktime_t timeout_ns;
    ktime_t closing_timeout_ns;
    int bkt;
    unsigned long flags;
    LIST_HEAD(dead_list);

    if (!ctx || !atomic_read(&ctx->running))
        return;

    pep_mem_tune_update(ctx);

    timeout_ns = ms_to_ktime(ctx->config.flow_timeout_ms);
    /*
     * v74: FIN_WAIT/CLOSING 状态流使用更短的超时
     *
     * 问题: 当 LAN 客户端发送 FIN 时，流进入 FIN_WAIT_2 状态，
     *       但由于 Split-TCP 未正确实现 WAN 侧 FIN 处理，
     *       这些流会卡住并持续产生 RTX 日志
     *
     * 解决: 对 closing 状态的流使用 10 秒超时，确保及时清理
     */
    closing_timeout_ns = ms_to_ktime(10000);

    raw_spin_lock_irqsave(&ctx->flow_table.lock, flags);

    hash_for_each_safe(ctx->flow_table.flows, bkt, tmp, flow, hnode) {
        ktime_t flow_timeout;
        s64 age_ms;
        bool should_clean = false;

        /*
         * v100 关键修复: 清理已标记 DEAD 的流
         *
         * 问题: 之前 GC 跳过 DEAD 流，但 RST 处理只设置 DEAD_BIT
         *       不从哈希表移除，导致流累积永不清理
         *
         * 解决: GC 应该清理所有 DEAD 流，不只是超时流
         */
        if (pep_flow_is_dead(flow)) {
            should_clean = true;
            pr_info_ratelimited("pep: GC cleaning DEAD flow: port=%u state=%d\n",
                    ntohs(flow->tuple.src_port), flow->state);
        } else {
            /* v74: 根据流状态选择超时时间 */
            if (flow->state >= PEP_TCP_FIN_WAIT_1 &&
                flow->state <= PEP_TCP_TIME_WAIT) {
                flow_timeout = closing_timeout_ns;
            } else {
                flow_timeout = timeout_ns;
            }

            age_ms = ktime_ms_delta(now, flow->last_activity);

            /*
             * v98 诊断: 输出 GC 检查详情
             */
            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                pr_info_ratelimited("pep: v98 GC check: port=%u state=%d wan_state=%d age_ms=%lld timeout_ms=%lld\n",
                        ntohs(flow->tuple.src_port), flow->state, flow->wan_state,
                        age_ms, ktime_to_ms(flow_timeout));
            }

            if (ktime_after(now, ktime_add(flow->last_activity, flow_timeout))) {
                pr_info_ratelimited("pep: GC cleaning timeout flow: port=%u state=%d age_ms=%lld\n",
                        ntohs(flow->tuple.src_port), flow->state, age_ms);
                pep_flow_mark_dead(flow);
                should_clean = true;
            }
        }

        if (should_clean) {
            hash_del_rcu(&flow->hnode);
            atomic_dec(&ctx->flow_table.count);
            list_add(&flow->list, &dead_list);
        }
    }

    raw_spin_unlock_irqrestore(&ctx->flow_table.lock, flags);

    if (!list_empty(&dead_list)) {
        synchronize_rcu();

        while (!list_empty(&dead_list)) {
            flow = list_first_entry(&dead_list, struct pep_flow, list);
            list_del(&flow->list);

            pep_pacing_cleanup(flow);
            pep_tlp_cleanup(flow);
            pep_ack_pacer_cleanup(flow);
            cancel_work_sync(&flow->wan_tx_work);
            cancel_work_sync(&flow->lan_tx_work);

            pep_flow_put(flow);
        }
    }

    if (atomic_read(&ctx->running)) {
        /* v109: faster GC cycle — max(2s, timeout/50) instead of timeout/10
         * Helps clean up dead flows promptly under high churn */
        u32 gc_interval = max_t(u32, 2000, ctx->config.flow_timeout_ms / 50);
        queue_delayed_work(ctx->wq, &ctx->gc_work,
                           msecs_to_jiffies(gc_interval));
    }
}

/*
 * 功能/Main: 后台处理工作队列任务（Work task workqueue task）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；定时器/工作队列上下文（timer/workqueue context）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: work
 * 影响/Effects: 后台维护/调度，影响吞吐与时延（background maintenance/scheduling, affects throughput/latency）
 * 重要程度/Importance: 中/Medium
 */
static void pep_rtx_work_handler(struct work_struct *work)
{
    struct pep_context *ctx = container_of(work, struct pep_context, rtx_work.work);
    struct pep_flow *flow;
    int bkt;
    u32 min_timeout_ms = UINT_MAX;
    u32 next_timeout;
    int total_retrans = 0;

    if (!ctx || !atomic_read(&ctx->running))
        return;

    if (!ctx->config.tcp_spoofing)
        return;

    rcu_read_lock();
    hash_for_each_rcu(ctx->flow_table.flows, bkt, flow, hnode) {

        if (pep_flow_is_dead(flow))
            continue;

        if (!test_bit(PEP_FLOW_F_SPOOFED_BIT, &flow->flags))
            continue;

        if (flow->state != PEP_TCP_ESTABLISHED)
            continue;

        if (!refcount_inc_not_zero(&flow->refcnt))
            continue;

        rcu_read_unlock();

        total_retrans += pep_retrans_check_timeouts(flow);

        next_timeout = pep_retrans_get_next_timeout(flow);
        if (next_timeout > 0 && next_timeout < min_timeout_ms) {
            min_timeout_ms = next_timeout;
        }

        pep_flow_put(flow);

        rcu_read_lock();
    }
    rcu_read_unlock();

    if (total_retrans > 0) {
        pep_dbg("RTX check: retransmitted %d packets\n", total_retrans);
    }

    if (atomic_read(&ctx->running)) {
        u32 delay_ms = (min_timeout_ms < UINT_MAX) ? min_timeout_ms : 10;
        delay_ms = max(1U, min(delay_ms, 100U));

        queue_delayed_work(ctx->wq, &ctx->rtx_work,
                           msecs_to_jiffies(delay_ms));
    }
}

/*
 * 功能/Main: RTT 探测/估计（Probe RTT probing/estimation）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；RTT/RTO 估计（RTT/RTO estimation）；定时器/工作队列上下文（timer/workqueue context）；并发同步（spinlock/atomic/rcu）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: work
 * 影响/Effects: 后台维护/调度，影响吞吐与时延（background maintenance/scheduling, affects throughput/latency）
 * 重要程度/Importance: 中/Medium
 */
static void pep_rtt_probe_work_handler(struct work_struct *work)
{
    struct pep_context *ctx = container_of(work, struct pep_context, rtt_probe_work.work);
    struct pep_flow *flow;
    int bkt;
    u32 delay_ms;

    if (!ctx || !atomic_read(&ctx->running))
        return;

    if (!ctx->config.rtt_probe_enabled || ctx->config.rtt_probe_interval_ms == 0)
        return;

    rcu_read_lock();
    hash_for_each_rcu(ctx->flow_table.flows, bkt, flow, hnode) {
        if (pep_flow_is_dead(flow))
            continue;
        pep_rtt_probe_maybe_send(flow);
    }
    rcu_read_unlock();

    delay_ms = ctx->config.rtt_probe_interval_ms;
    delay_ms = max(100U, min(delay_ms, 5000U));
    queue_delayed_work(ctx->wq, &ctx->rtt_probe_work,
                       msecs_to_jiffies(delay_ms));
}

/*
 * 功能/Main: 处理pep_parse_cidr相关逻辑（Handle pep_parse_cidr logic）
 * 细节/Details: RTT/RTO 估计（RTT/RTO estimation）
 * 输入/Inputs: 参数/Inputs: cidr, addr, mask, prefix
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static bool pep_parse_cidr(const char *cidr, __be32 *addr, __be32 *mask, u32 *prefix)
{
    char buf[64];
    char *slash;
    u32 pref = 32;
    u8 ip[4];

    if (!cidr || !addr || !mask || !prefix)
        return false;

    if (strscpy(buf, cidr, sizeof(buf)) <= 0)
        return false;

    slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        pref = simple_strtoul(slash + 1, NULL, 10);
        if (pref > 32)
            return false;
    }

    if (!in4_pton(buf, -1, ip, -1, NULL))
        return false;

    memcpy(addr, ip, sizeof(*addr));

    if (pref == 0)
        *mask = 0;
    else
        *mask = htonl(0xFFFFFFFFu << (32 - pref));

    *prefix = pref;
    return true;
}

/*
 * 功能/Main: 计算带宽整形/调度（Compute traffic shaping/scheduling）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: rate_bps, burst_ms, min_bytes, tolerance
 * 影响/Effects: 计算派生值，影响策略决策（compute derived values, affects policy decisions）
 * 重要程度/Importance: 中/Medium
 */
static u64 pep_calc_shaper_burst(u64 rate_bps, u32 burst_ms,
                                 u32 min_bytes, u32 tolerance)
{
    u64 burst = 0;

    if (rate_bps > 0 && burst_ms > 0) {
        burst = div64_u64((rate_bps / 8) * (u64)burst_ms, 1000);
    }

    if (burst < min_bytes)
        burst = min_bytes;

    burst += tolerance;

    return burst;
}

/*
 * 功能/Main: 初始化pep_init_config相关逻辑（Initialize pep_init_config logic）
 * 细节/Details: 分片重组/重排处理（fragment reassembly）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；ACK pacing 调度（ACK pacing scheduling）；带宽整形/速率限制（shaping/rate limit）；FEC 编码/映射/恢复（FEC encode/map/recover）；RTT/RTO 估计（RTT/RTO estimation）
 * 输入/Inputs: 参数/Inputs: config
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
static void pep_init_config(struct pep_config *config)
{
    memset(config, 0, sizeof(*config));

    config->enabled = enabled;
    config->max_flows = max_flows;
    config->flow_timeout_ms = flow_timeout;

    config->lan_wan_queue_min = lan_wan_queue_min;
    config->lan_wan_queue_max = lan_wan_queue_max;
    config->wan_lan_queue_min = wan_lan_queue_min;
    config->wan_lan_queue_max = wan_lan_queue_max;

    config->queue_bdp_enabled = queue_bdp_enabled;
    config->queue_bdp_multiplier = queue_bdp_multiplier;
    config->queue_max_absolute = queue_max_absolute;
    config->wan_rtt_ms = wan_rtt_ms;

    config->max_retrans = PEP_DEFAULT_MAX_RETRANS;
    config->rto_min_ms = rto_min;
    config->rto_max_ms = rto_max;
    config->rto_init_ms = rto_init;
    config->wan_syn_fail_open_ms = wan_syn_fail_open_ms;
    config->wan_syn_max_retries = wan_syn_max_retries ?
                                  wan_syn_max_retries : PEP_WAN_SYN_MAX_RETRIES;
    config->wan_syn_init_rto_ms = wan_syn_init_rto_ms ?
                                  wan_syn_init_rto_ms : PEP_WAN_SYN_INIT_RTO_MS;
    config->wan_syn_max_rto_ms = wan_syn_max_rto_ms ?
                                 wan_syn_max_rto_ms : PEP_WAN_SYN_MAX_RTO_MS;
    if (config->wan_syn_max_rto_ms < config->wan_syn_init_rto_ms)
        config->wan_syn_max_rto_ms = config->wan_syn_init_rto_ms;

    config->init_cwnd = init_cwnd;
    config->max_cwnd = PEP_DEFAULT_MAX_CWND;
    config->cc_cong_reduction_pct = cc_cong_reduction_pct;
    if (config->cc_cong_reduction_pct == 0 || config->cc_cong_reduction_pct > 100)
        config->cc_cong_reduction_pct = PEP_DEFAULT_CC_CONG_REDUCTION_PCT;
    config->cc_ber_reduction_pct = cc_ber_reduction_pct;
    if (config->cc_ber_reduction_pct == 0 || config->cc_ber_reduction_pct > 100)
        config->cc_ber_reduction_pct = PEP_DEFAULT_CC_BER_REDUCTION_PCT;
    config->cc_rtt_inflation_pct = cc_rtt_inflation_pct;
    if (config->cc_rtt_inflation_pct == 0 || config->cc_rtt_inflation_pct > 100)
        config->cc_rtt_inflation_pct = PEP_DEFAULT_CC_RTT_INFLATION_PCT;
    config->ecn_ce_reduction_pct = ecn_ce_reduction_pct;
    if (config->ecn_ce_reduction_pct == 0 || config->ecn_ce_reduction_pct > 100)
        config->ecn_ce_reduction_pct = PEP_DEFAULT_ECN_CE_REDUCTION_PCT;
    config->ecn_enabled = ecn_enabled ? 1 : 0;

    {
        u32 derived_kbps = bandwidth_mbps * 1000;
        u32 wan_kbps_eff = wan_kbps ? wan_kbps : derived_kbps;
        u32 wan_in_kbps_eff = wan_in_kbps ? wan_in_kbps : derived_kbps;
        u64 max_bps = (u64)max(wan_kbps_eff, wan_in_kbps_eff) * 1000ULL;

        config->shaper_enabled = shaper_enabled ? 1 : 0;
        config->wan_kbps = wan_kbps_eff;
        config->wan_in_kbps = wan_in_kbps_eff;
        config->sm_burst_ms = sm_burst_ms;
        config->sm_burst_min = sm_burst_min;
        config->sm_burst_tolerance = sm_burst_tolerance;
        config->bypass_overflows = bypass_overflows ? 1 : 0;
        config->max_acc_flow_tx_kbps = max_acc_flow_tx_kbps;
        config->subnet_acc = subnet_acc ? 1 : 0;
        config->lan_segment_prefix = 0;
        config->lan_segment_addr = 0;
        config->lan_segment_mask = 0;
        config->lan_segment_str[0] = '\0';

        if (lan_segment && *lan_segment) {
            if (pep_parse_cidr(lan_segment, &config->lan_segment_addr,
                               &config->lan_segment_mask,
                               &config->lan_segment_prefix)) {
                strscpy(config->lan_segment_str, lan_segment,
                        sizeof(config->lan_segment_str));
            } else {
                pr_warn("pep: invalid lan_segment '%s', disabling subnet filter\n",
                        lan_segment);
                config->subnet_acc = 0;
            }
        }

        config->bandwidth_bps = max_bps;
        config->burst_size = pep_calc_shaper_burst(max_bps, sm_burst_ms,
                                                  sm_burst_min, sm_burst_tolerance);
    }

    config->tcp_spoofing = tcp_spoofing;
    {
        u32 fake_ack_effective = fake_ack;

        if (advinacc >= 0)
            fake_ack_effective = advinacc ? 1 : 0;
        config->fake_ack = fake_ack_effective;
    }

    if (config->fake_ack && !local_retrans) {
        pr_warn("pep: WARNING: fake_ack=1 requires local_retrans=1 for data safety!\n");
        pr_warn("pep: Auto-enabling local_retrans to prevent data loss.\n");
        config->local_retrans = 1;
    } else {
        config->local_retrans = local_retrans;
    }
    config->local_retrans_max_pkts = local_retrans_max_pkts;
    config->local_retrans_max_bytes = local_retrans_max_bytes;
    if (config->local_retrans &&
        (config->local_retrans_max_pkts == 0 || config->local_retrans_max_bytes == 0)) {
        pr_warn("pep: local_retrans cache size invalid, using defaults\n");
        config->local_retrans_max_pkts = PEP_DEFAULT_LOCAL_RETRANS_MAX_PKTS;
        config->local_retrans_max_bytes = PEP_DEFAULT_LOCAL_RETRANS_MAX_BYTES;
    }
    config->aggressive_ack = tcp_spoofing ? 1 : 0;
    if (advacc >= 0)
        config->aggressive_ack = advacc ? 1 : 0;
    if (!config->tcp_spoofing)
        config->aggressive_ack = 0;
    config->gso_enabled = gso_enabled;
    config->gro_enabled = gro_enabled;
    config->rsc_enabled = rsc_enabled;
    config->rsc_max_size = rsc_max_size ? rsc_max_size : PEP_DEFAULT_RSC_MAX_SIZE;
    config->rsc_timeout_us = rsc_timeout_us ? rsc_timeout_us : PEP_DEFAULT_RSC_TIMEOUT_US;
    config->tx_csum_enabled = tx_csum_enabled ? 1 : 0;
    config->rx_csum_enabled = rx_csum_enabled ? 1 : 0;
    config->fastpath_enabled = fastpath_enabled;
    config->fastpath_threshold = fastpath_threshold;
    config->learning_enabled = learning_enabled;
    config->debug_level = debug_level;

    config->byte_cache_enabled = byte_cache_enabled ? 1 : 0;
    config->byte_cache_mem_mb = byte_cache_memory_mb;
    config->byte_cache_disk_mb = byte_cache_disk_mb;
    if (byte_cache_disk_path && *byte_cache_disk_path) {
        strscpy(config->byte_cache_disk_path, byte_cache_disk_path,
                sizeof(config->byte_cache_disk_path));
    } else {
        strscpy(config->byte_cache_disk_path, PEP_DEFAULT_BYTE_CACHE_DISK_PATH,
                sizeof(config->byte_cache_disk_path));
    }
    config->mem_tune_enabled = mem_tune_enabled ? 1 : 0;
    config->mem_tune_low_mb = mem_tune_low_mb;
    config->mem_tune_high_mb = mem_tune_high_mb;
    config->mem_tune_min_pct = mem_tune_min_pct;
    if (config->mem_tune_min_pct == 0 || config->mem_tune_min_pct > 100)
        config->mem_tune_min_pct = PEP_DEFAULT_MEM_TUNE_MIN_PCT;
    if (config->mem_tune_low_mb > 0 && config->mem_tune_high_mb > 0 &&
        config->mem_tune_low_mb >= config->mem_tune_high_mb) {
        config->mem_tune_enabled = 0;
    }
    config->mempool_max_cache_bytes = mempool_max_cache_bytes;

    config->ack_pacing_enabled = ack_pacing;
    config->ack_delay_us = ack_delay_us;
    config->ack_bytes_threshold = ack_bytes_threshold;
    config->pacing_gain_pct = pacing_gain_pct ? pacing_gain_pct : PEP_PACING_GAIN_PERCENT;
    if (config->pacing_gain_pct > 200)
        config->pacing_gain_pct = PEP_PACING_GAIN_PERCENT;
    config->pacing_min_interval_us =
        pacing_min_interval_us ? pacing_min_interval_us : PEP_PACING_MIN_INTERVAL_US;
    config->pacing_max_interval_us =
        pacing_max_interval_us ? pacing_max_interval_us : PEP_PACING_MAX_INTERVAL_US;
    if (config->pacing_min_interval_us > config->pacing_max_interval_us)
        config->pacing_max_interval_us = config->pacing_min_interval_us;
    config->pacing_min_rate_pct = pacing_min_rate_pct;
    if (config->pacing_min_rate_pct == 0 || config->pacing_min_rate_pct > 100)
        config->pacing_min_rate_pct = PEP_PACING_MIN_RATE_PERCENT;

    config->reseq_enabled = reseq_enabled;
    config->reseq_max_packets = reseq_max_packets;
    if (config->reseq_max_packets == 0) {
        config->reseq_enabled = 0;
    }

    config->sched_enabled = sched_enabled;
    config->classify_small_flow_bytes = classify_small_flow_bytes;
    config->engine_num = engine_num;
    config->task_sched_delay_wan_ms = task_sched_delay_wan_ms;
    config->task_sched_delay_lan_ms = task_sched_delay_lan_ms;

    config->rtt_probe_enabled = rtt_probe_enabled;
    config->rtt_probe_interval_ms = rtt_probe_interval_ms;
    config->rtt_probe_idle_ms = rtt_probe_idle_ms;

    config->ip_reassembly_enabled = ip_reassembly_enabled;
    config->split_dl_enabled = split_dl_enabled;
    config->downlink_reorder_enabled = downlink_reorder_enabled;
    config->downlink_reorder_max = downlink_reorder_max;
    config->downlink_reorder_timeout_ms = downlink_reorder_timeout_ms;
    if (config->downlink_reorder_max == 0)
        config->downlink_reorder_enabled = 0;

    config->region_learning_enabled = region_learning;
    config->region_max_entries = region_max;
    config->region_prefix_len = (u8)region_prefix;

    config->fec_enabled = fec_enabled;
    config->fec_k = fec_k;
    config->fec_n = fec_n;

    config->pmtu_enabled = pmtu_enabled;
    config->pmtu_timeout_ms = pmtu_timeout_ms;
    config->pmtu_default = pmtu_default;

    if (wan_if && strlen(wan_if) > 0)
        strscpy(config->wan_ifname, wan_if, IFNAMSIZ);
    if (lan_if && strlen(lan_if) > 0)
        strscpy(config->lan_ifname, lan_if, IFNAMSIZ);
}

/*
 * 功能/Main: 初始化pep_stats_init相关逻辑（Initialize pep_stats_init logic）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: stats
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
static int pep_stats_init(struct pep_stats *stats)
{
    stats->percpu = alloc_percpu(struct pep_percpu_stats);
    if (!stats->percpu)
        return -ENOMEM;

    atomic64_set(&stats->active_flows, 0);
    atomic64_set(&stats->flow_creates, 0);
    atomic64_set(&stats->flow_destroys, 0);
    atomic64_set(&stats->wan_syn_sent, 0);
    atomic64_set(&stats->wan_syn_synack, 0);
    atomic64_set(&stats->wan_syn_retries, 0);
    atomic64_set(&stats->wan_syn_retransmit_sent, 0);
    atomic64_set(&stats->wan_syn_timeouts, 0);
    atomic64_set(&stats->wan_syn_fail_open, 0);
    atomic64_set(&stats->wan_syn_max_retries, 0);
    atomic64_set(&stats->wan_syn_send_fail, 0);
    atomic64_set(&stats->wan_syn_bypass, 0);
    atomic64_set(&stats->wan_syn_rst, 0);

    return 0;
}

/*
 * 功能/Main: 清理pep_stats_exit相关逻辑（Cleanup pep_stats_exit logic）
 * 细节/Details: 统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: stats
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
static void pep_stats_exit(struct pep_stats *stats)
{
    if (stats->percpu) {
        free_percpu(stats->percpu);
        stats->percpu = NULL;
    }
}

/*
 * 功能/Main: 处理pep_stats_aggregate相关逻辑（Handle pep_stats_aggregate logic）
 * 细节/Details: 重传/缓存处理（retransmission/cache）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: stats, total
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_stats_aggregate(struct pep_stats *stats, struct pep_percpu_stats *total)
{
    int cpu;

    memset(total, 0, sizeof(*total));

    if (!stats->percpu)
        return;

    for_each_possible_cpu(cpu) {
        struct pep_percpu_stats *pcpu = per_cpu_ptr(stats->percpu, cpu);
        total->rx_packets += READ_ONCE(pcpu->rx_packets);
        total->rx_bytes += READ_ONCE(pcpu->rx_bytes);
        total->tx_packets += READ_ONCE(pcpu->tx_packets);
        total->tx_bytes += READ_ONCE(pcpu->tx_bytes);
        total->fake_acks += READ_ONCE(pcpu->fake_acks);
        total->acks_filtered += READ_ONCE(pcpu->acks_filtered);
        total->retrans += READ_ONCE(pcpu->retrans);
        total->dropped += READ_ONCE(pcpu->dropped);
        total->errors += READ_ONCE(pcpu->errors);
        total->fastpath_packets += READ_ONCE(pcpu->fastpath_packets);
        total->adv_acks += READ_ONCE(pcpu->adv_acks);
    }
}

/*
 * 功能/Main: 查找pep_find_dev相关逻辑（Find pep_find_dev logic）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: name
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static struct net_device *pep_find_dev(const char *name)
{
    struct net_device *dev;

    if (!name || strlen(name) == 0)
        return NULL;

    dev = dev_get_by_name(&init_net, name);
    return dev;
}

/*
 * 功能/Main: 处理pep_mem_tune_avail_mb相关逻辑（Handle pep_mem_tune_avail_mb logic）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 无（void）/none
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static u32 pep_mem_tune_avail_mb(void)
{
    struct sysinfo info;
    u64 avail_pages;
    u64 avail_mb;

    si_meminfo(&info);
    avail_pages = (u64)info.freeram + (u64)info.bufferram;
    avail_mb = (avail_pages << PAGE_SHIFT) >> 20;

    return (u32)avail_mb;
}

/*
 * 功能/Main: 初始化pep_mem_tune_init相关逻辑（Initialize pep_mem_tune_init logic）
 * 细节/Details: 队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；字节缓存读写（byte cache access）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: ctx
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
static void pep_mem_tune_init(struct pep_context *ctx)
{
    if (!ctx)
        return;

    ctx->mem_tune.base_queue_absolute = ctx->config.queue_max_absolute;
    ctx->mem_tune.base_lan_rtx_max_pkts = ctx->config.local_retrans_max_pkts;
    ctx->mem_tune.base_lan_rtx_max_bytes = ctx->config.local_retrans_max_bytes;
    ctx->mem_tune.base_byte_cache_max_bytes = ctx->byte_cache_max_bytes;
    ctx->mem_tune.scale_pct = 100;
}

/*
 * 功能/Main: 处理pep_mem_tune_apply相关逻辑（Handle pep_mem_tune_apply logic）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；字节缓存读写（byte cache access）；并发同步（spinlock/atomic/rcu）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: ctx, scale_pct
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static void pep_mem_tune_apply(struct pep_context *ctx, u32 scale_pct)
{
    struct pep_flow *flow;
    int bkt;
    u32 queue_abs;
    u32 rtx_pkts;
    u32 rtx_bytes;
    u64 byte_cache_max;

    if (!ctx)
        return;

    queue_abs = (u32)(((u64)ctx->mem_tune.base_queue_absolute * scale_pct) / 100);
    rtx_pkts = (u32)(((u64)ctx->mem_tune.base_lan_rtx_max_pkts * scale_pct) / 100);
    rtx_bytes = (u32)(((u64)ctx->mem_tune.base_lan_rtx_max_bytes * scale_pct) / 100);
    byte_cache_max = (ctx->mem_tune.base_byte_cache_max_bytes * scale_pct) / 100;

    if (ctx->mem_tune.base_queue_absolute > 0 && queue_abs == 0)
        queue_abs = ctx->mem_tune.base_queue_absolute;

    if (!ctx->config.local_retrans) {
        rtx_pkts = 0;
        rtx_bytes = 0;
    } else {
        if (ctx->mem_tune.base_lan_rtx_max_pkts > 0 && rtx_pkts == 0)
            rtx_pkts = 1;
        if (ctx->mem_tune.base_lan_rtx_max_bytes > 0 && rtx_bytes == 0)
            rtx_bytes = 1;
    }

    ctx->config.queue_max_absolute = queue_abs;
    ctx->config.local_retrans_max_pkts = rtx_pkts;
    ctx->config.local_retrans_max_bytes = rtx_bytes;
    ctx->byte_cache_max_bytes = byte_cache_max;

    if (ctx->config.byte_cache_enabled)
        pep_byte_cache_trim(ctx);

    rcu_read_lock();
    hash_for_each_rcu(ctx->flow_table.flows, bkt, flow, hnode) {
        if (pep_flow_is_dead(flow))
            continue;

        WRITE_ONCE(flow->lan_to_wan.absolute_max, queue_abs);
        WRITE_ONCE(flow->wan_to_lan.absolute_max, queue_abs);
        WRITE_ONCE(flow->lan_rtx_max_pkts, rtx_pkts);
        WRITE_ONCE(flow->lan_rtx_max_bytes, rtx_bytes);
    }
    rcu_read_unlock();

    ctx->mem_tune.scale_pct = scale_pct;
}

/*
 * 功能/Main: 更新pep_mem_tune_update相关逻辑（Update pep_mem_tune_update logic）
 * 细节/Details: 配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: ctx
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 中/Medium
 */
static void pep_mem_tune_update(struct pep_context *ctx)
{
    u32 avail_mb;
    u32 scale_pct;
    u32 low_mb;
    u32 high_mb;
    u32 min_pct;

    if (!ctx || !ctx->config.mem_tune_enabled)
        return;

    low_mb = ctx->config.mem_tune_low_mb;
    high_mb = ctx->config.mem_tune_high_mb;
    min_pct = ctx->config.mem_tune_min_pct;

    if (min_pct == 0 || min_pct > 100)
        min_pct = PEP_DEFAULT_MEM_TUNE_MIN_PCT;

    if (low_mb == 0 || high_mb == 0 || low_mb >= high_mb)
        return;

    avail_mb = pep_mem_tune_avail_mb();

    if (avail_mb <= low_mb) {
        scale_pct = min_pct;
    } else if (avail_mb >= high_mb) {
        scale_pct = 100;
    } else {
        scale_pct = min_pct +
            ((avail_mb - low_mb) * (100 - min_pct)) / (high_mb - low_mb);
    }

    if (scale_pct < min_pct)
        scale_pct = min_pct;
    if (scale_pct > 100)
        scale_pct = 100;

    if (scale_pct == ctx->mem_tune.scale_pct)
        return;

    pep_mem_tune_apply(ctx, scale_pct);
}

/*
 * 功能/Main: 初始化pep_module_init相关逻辑（Initialize pep_module_init logic）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；带宽整形/速率限制（shaping/rate limit）；RTT/RTO 估计（RTT/RTO estimation）；PMTU/MSS 更新（PMTU/MSS update）；学习控制/区域统计（learning/regional stats）；字节缓存读写（byte cache access）
 * 输入/Inputs: 无（void）/none
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
static int __init pep_module_init(void)
{
    int ret;
    const char *mode_str;

    pep_info("Initializing RFC 3135 PEP TCP Accelerator v%s\n", PEP_VERSION);

    pep_ctx = kzalloc(sizeof(struct pep_context), GFP_KERNEL);
    if (!pep_ctx) {
        pep_err("Failed to allocate context\n");
        return -ENOMEM;
    }

    pep_init_config(&pep_ctx->config);

    mode_str = pep_ctx->config.tcp_spoofing ? "Spoofing" : "Monitor";

    pep_ctx->wq = alloc_workqueue("pep_wq",
                                   WQ_HIGHPRI | WQ_MEM_RECLAIM | WQ_UNBOUND,
                                   num_online_cpus());
    if (!pep_ctx->wq) {
        pep_err("Failed to create workqueue\n");
        ret = -ENOMEM;
        goto err_wq;
    }

    ret = pep_engine_init(pep_ctx);
    if (ret < 0) {
        pep_err("Failed to init engine scheduler: %d\n", ret);
        goto err_engine;
    }

    ret = pep_stats_init(&pep_ctx->stats);
    if (ret < 0) {
        pep_err("Failed to init stats: %d\n", ret);
        goto err_stats;
    }

    ret = pep_mempool_init(&pep_ctx->mempool);
    if (ret < 0) {
        pep_err("Failed to init mempool: %d\n", ret);
        goto err_mempool;
    }
    pep_ctx->mempool.max_cache_bytes = pep_ctx->config.mempool_max_cache_bytes;

    ret = pep_flow_table_init(&pep_ctx->flow_table,
                               pep_ctx->config.max_flows,
                               pep_ctx->config.flow_timeout_ms);
    if (ret < 0) {
        pep_err("Failed to init flow table: %d\n", ret);
        goto err_flow_table;
    }

    ret = pep_byte_cache_init(pep_ctx);
    if (ret < 0) {
        pep_err("Failed to init byte cache: %d\n", ret);
        goto err_byte_cache;
    }

    pep_mem_tune_init(pep_ctx);
    if (pep_ctx->config.mem_tune_enabled)
        pep_mem_tune_update(pep_ctx);

    if (pep_ctx->config.learning_enabled) {
        ret = pep_learning_init(&pep_ctx->learning);
        if (ret < 0) {
            pep_err("Failed to init learning module: %d\n", ret);
            goto err_learning;
        }
        pep_learning_set_epsilon(&pep_ctx->learning,
                                 (PEP_FIXED_ONE * learning_epsilon_pct) / 100);
        pep_info("Self-Learning CC enabled\n");
    }

    if (pep_ctx->config.region_learning_enabled) {
        ret = pep_region_table_init(&pep_ctx->region_table,
                                     pep_ctx->config.region_max_entries,
                                     pep_ctx->config.region_prefix_len);
        if (ret < 0) {
            pep_err("Failed to init region table: %d\n", ret);
            goto err_region;
        }
        pep_info("Regional Learning enabled: max=%u, prefix=/%u\n",
                 pep_ctx->config.region_max_entries,
                 pep_ctx->config.region_prefix_len);
    }

    if (pep_ctx->config.pmtu_enabled) {
        ret = pep_pmtu_init();
        if (ret < 0) {
            pep_err("Failed to init PMTU module: %d\n", ret);
            goto err_pmtu;
        }
        pep_info("PMTU Discovery enabled\n");
    }

    {
        u64 lan_wan_rate_bps = (u64)pep_ctx->config.wan_kbps * 1000ULL;
        u64 wan_lan_rate_bps = (u64)pep_ctx->config.wan_in_kbps * 1000ULL;
        u64 lan_wan_burst = pep_calc_shaper_burst(lan_wan_rate_bps,
                                                  pep_ctx->config.sm_burst_ms,
                                                  pep_ctx->config.sm_burst_min,
                                                  pep_ctx->config.sm_burst_tolerance);

        if (!pep_ctx->config.shaper_enabled) {
            lan_wan_rate_bps = 0;
            wan_lan_rate_bps = 0;
        }

        ret = pep_shaper_init(&pep_ctx->shaper_lan_wan,
                              lan_wan_rate_bps, lan_wan_burst);
    }
    if (ret < 0) {
        pep_err("Failed to init LAN->WAN shaper: %d\n", ret);
        goto err_shaper1;
    }

    {
        u64 wan_lan_rate_bps = (u64)pep_ctx->config.wan_in_kbps * 1000ULL;
        u64 wan_lan_burst = pep_calc_shaper_burst(wan_lan_rate_bps,
                                                  pep_ctx->config.sm_burst_ms,
                                                  pep_ctx->config.sm_burst_min,
                                                  pep_ctx->config.sm_burst_tolerance);

        if (!pep_ctx->config.shaper_enabled)
            wan_lan_rate_bps = 0;

        ret = pep_shaper_init(&pep_ctx->shaper_wan_lan,
                              wan_lan_rate_bps, wan_lan_burst);
    }
    if (ret < 0) {
        pep_err("Failed to init WAN->LAN shaper: %d\n", ret);
        goto err_shaper2;
    }

    ret = pep_proc_init(pep_ctx);
    if (ret < 0) {
        pep_err("Failed to init procfs: %d\n", ret);
        goto err_proc;
    }

    if (strlen(pep_ctx->config.wan_ifname) > 0) {
        pep_ctx->wan_dev = pep_find_dev(pep_ctx->config.wan_ifname);
        if (pep_ctx->wan_dev)
            pep_info("WAN device: %s\n", pep_ctx->config.wan_ifname);
    }
    if (strlen(pep_ctx->config.lan_ifname) > 0) {
        pep_ctx->lan_dev = pep_find_dev(pep_ctx->config.lan_ifname);
        if (pep_ctx->lan_dev)
            pep_info("LAN device: %s\n", pep_ctx->config.lan_ifname);
    }
    if (pep_ctx->wan_dev && pep_ctx->lan_dev &&
        pep_ctx->wan_dev == pep_ctx->lan_dev) {
        pep_info("Single-interface mode: %s\n", pep_ctx->wan_dev->name);
    }
    if (!pep_ctx->wan_dev || !pep_ctx->lan_dev) {
        pep_warn("LAN/WAN interface binding required (wan_if=%s lan_if=%s). "
                 "PEP will only process traffic when both are bound.\n",
                 pep_ctx->config.wan_ifname, pep_ctx->config.lan_ifname);
    }

    atomic_set(&pep_ctx->initialized, 1);
    atomic_set(&pep_ctx->running, 1);

    INIT_DELAYED_WORK(&pep_ctx->gc_work, pep_gc_work_handler);
    queue_delayed_work(pep_ctx->wq, &pep_ctx->gc_work,
                       msecs_to_jiffies(pep_ctx->config.flow_timeout_ms / 10));

    INIT_DELAYED_WORK(&pep_ctx->rtx_work, pep_rtx_work_handler);
    if (pep_ctx->config.tcp_spoofing) {
        queue_delayed_work(pep_ctx->wq, &pep_ctx->rtx_work,
                           msecs_to_jiffies(10));
    }

    INIT_DELAYED_WORK(&pep_ctx->rtt_probe_work, pep_rtt_probe_work_handler);
    if (pep_ctx->config.rtt_probe_enabled &&
        pep_ctx->config.rtt_probe_interval_ms > 0) {
        queue_delayed_work(pep_ctx->wq, &pep_ctx->rtt_probe_work,
                           msecs_to_jiffies(pep_ctx->config.rtt_probe_interval_ms));
    }

    ret = pep_netfilter_init(pep_ctx);
    if (ret < 0) {
        pep_err("Failed to init netfilter: %d\n", ret);
        goto err_netfilter;
    }

    pep_info("PEP Accelerator started (%s Mode)\n", mode_str);
    pep_info("  Max flows: %u\n", pep_ctx->config.max_flows);
    pep_info("  Flow timeout: %u ms\n", pep_ctx->config.flow_timeout_ms);
    pep_info("  RTO: %u-%u ms\n", pep_ctx->config.rto_min_ms, pep_ctx->config.rto_max_ms);
    pep_info("  WAN SYN fail-open: %u ms\n", pep_ctx->config.wan_syn_fail_open_ms);
    pep_info("  WAN SYN retries: %u, RTO: %u-%u ms\n",
             pep_ctx->config.wan_syn_max_retries,
             pep_ctx->config.wan_syn_init_rto_ms,
             pep_ctx->config.wan_syn_max_rto_ms);
    pep_info("  CWND: init=%u max=%u\n", pep_ctx->config.init_cwnd, pep_ctx->config.max_cwnd);
    pep_info("  ECN: %s (ce_reduction=%u%%)\n",
             pep_ctx->config.ecn_enabled ? "enabled" : "disabled",
             pep_ctx->config.ecn_ce_reduction_pct);
    pep_info("  Bandwidth: %llu Mbps\n", pep_ctx->config.bandwidth_bps / 1000000);
    pep_info("  Shaper: %s (wan=%u kbps, wan_in=%u kbps)\n",
             pep_ctx->config.shaper_enabled ? "enabled" : "disabled",
             pep_ctx->config.wan_kbps, pep_ctx->config.wan_in_kbps);
    pep_info("  Flow cap: %u kbps, bypass_overflows=%u\n",
             pep_ctx->config.max_acc_flow_tx_kbps,
             pep_ctx->config.bypass_overflows);
    if (pep_ctx->config.subnet_acc && pep_ctx->config.lan_segment_str[0]) {
        pep_info("  LAN segment: %s\n", pep_ctx->config.lan_segment_str);
    } else {
        pep_info("  LAN segment: disabled\n");
    }
    pep_info("  Byte cache: %s (mem=%u MB disk=%u MB)\n",
             pep_ctx->config.byte_cache_enabled ? "enabled" : "disabled",
             pep_ctx->config.byte_cache_mem_mb,
             pep_ctx->config.byte_cache_disk_mb);
    pep_info("  GSO: %s, GRO: %s\n",
             pep_ctx->config.gso_enabled ? "enabled" : "disabled",
             pep_ctx->config.gro_enabled ? "enabled" : "disabled");
    pep_info("  Fast Path: %s (threshold=%u pkts)\n",
             pep_ctx->config.fastpath_enabled ? "enabled" : "disabled",
             pep_ctx->config.fastpath_threshold);
    pep_info("  Learning CC: %s\n",
             pep_ctx->config.learning_enabled ? "enabled" : "disabled");
    pep_info("  Queue LAN->WAN: %u-%u, WAN->LAN: %u-%u\n",
             pep_ctx->config.lan_wan_queue_min, pep_ctx->config.lan_wan_queue_max,
             pep_ctx->config.wan_lan_queue_min, pep_ctx->config.wan_lan_queue_max);
    pep_info("  Status: /proc/%s/stats\n", PEP_PROC_ROOT);

    return 0;

err_netfilter:
    atomic_set(&pep_ctx->running, 0);
    cancel_delayed_work_sync(&pep_ctx->rtx_work);
    cancel_delayed_work_sync(&pep_ctx->gc_work);
    pep_proc_exit(pep_ctx);
err_proc:
    pep_shaper_exit(&pep_ctx->shaper_wan_lan);
err_shaper2:
    pep_shaper_exit(&pep_ctx->shaper_lan_wan);
err_shaper1:
    if (pep_ctx->config.pmtu_enabled)
        pep_pmtu_exit();
err_pmtu:
    if (pep_ctx->config.region_learning_enabled)
        pep_region_table_exit(&pep_ctx->region_table);
err_region:
    if (pep_ctx->config.learning_enabled)
        pep_learning_exit(&pep_ctx->learning);
err_learning:
    pep_byte_cache_exit(pep_ctx);
err_byte_cache:
    pep_flow_table_exit(&pep_ctx->flow_table);
err_flow_table:
    pep_mempool_exit(&pep_ctx->mempool);
err_mempool:
    pep_stats_exit(&pep_ctx->stats);
err_stats:
    pep_engine_exit(pep_ctx);
err_engine:
    destroy_workqueue(pep_ctx->wq);
err_wq:
    kfree(pep_ctx);
    pep_ctx = NULL;
    return ret;
}

/*
 * 功能/Main: 清理pep_module_exit相关逻辑（Cleanup pep_module_exit logic）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；带宽整形/速率限制（shaping/rate limit）；RTT/RTO 估计（RTT/RTO estimation）；PMTU/MSS 更新（PMTU/MSS update）；学习控制/区域统计（learning/regional stats）；字节缓存读写（byte cache access）
 * 输入/Inputs: 无（void）/none
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
static void __exit pep_module_exit(void)
{
    struct pep_context *ctx = pep_ctx;

    pr_info("pep: [EXIT] === Module unload START ===\n");

    if (!ctx)
        return;

    pr_info("pep: [EXIT] Step 1: Setting running=0\n");
    atomic_set(&ctx->running, 0);

    pr_info("pep: [EXIT] Step 2a: cancel rtx_work...\n");
    cancel_delayed_work_sync(&ctx->rtx_work);
    pr_info("pep: [EXIT] Step 2b: cancel gc_work...\n");
    cancel_delayed_work_sync(&ctx->gc_work);
    pr_info("pep: [EXIT] Step 2c: cancel rtt_probe_work...\n");
    cancel_delayed_work_sync(&ctx->rtt_probe_work);
    pr_info("pep: [EXIT] Step 2d: cancel scheduler work...\n");
    pep_engine_exit(ctx);
    pr_info("pep: [EXIT] Step 2: Done\n");

    pr_info("pep: [EXIT] Step 3: Cancel all flow timers (v10 fix)...\n");
    pep_flow_table_cancel_all_timers(&ctx->flow_table);
    pr_info("pep: [EXIT] Step 3: Done\n");

    pr_info("pep: [EXIT] Step 4: Unregistering netfilter...\n");
    pep_netfilter_exit(ctx);
    pr_info("pep: [EXIT] Step 4: Done\n");

    pr_info("pep: [EXIT] Step 5: synchronize_rcu...\n");
    synchronize_rcu();
    pr_info("pep: [EXIT] Step 5: Done\n");

    pr_info("pep: [EXIT] Step 6: Releasing device refs...\n");
    if (ctx->wan_dev) {
        dev_put(ctx->wan_dev);
        ctx->wan_dev = NULL;
    }
    if (ctx->lan_dev) {
        dev_put(ctx->lan_dev);
        ctx->lan_dev = NULL;
    }
    pr_info("pep: [EXIT] Step 6: Done\n");

    pr_info("pep: [EXIT] Step 7: Byte cache exit...\n");
    pep_byte_cache_exit(ctx);
    pr_info("pep: [EXIT] Step 7: Done\n");

    pr_info("pep: [EXIT] Step 8: Flow table exit...\n");
    pep_flow_table_exit(&ctx->flow_table);
    pr_info("pep: [EXIT] Step 8: Done\n");

    synchronize_rcu();

    pep_shaper_exit(&ctx->shaper_wan_lan);
    pep_shaper_exit(&ctx->shaper_lan_wan);

    if (ctx->config.learning_enabled)
        pep_learning_exit(&ctx->learning);

    if (ctx->config.region_learning_enabled)
        pep_region_table_exit(&ctx->region_table);

    if (ctx->config.pmtu_enabled)
        pep_pmtu_exit();

    pep_proc_exit(ctx);
    pep_stats_exit(&ctx->stats);

    if (ctx->wq)
        destroy_workqueue(ctx->wq);

    pep_mempool_exit(&ctx->mempool);

    WRITE_ONCE(pep_ctx, NULL);

    kfree(ctx);

    pep_info("PEP Accelerator unloaded\n");
}

module_init(pep_module_init);
module_exit(pep_module_exit);
