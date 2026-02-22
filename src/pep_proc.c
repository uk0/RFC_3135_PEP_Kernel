/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"
#include <linux/inet.h>

extern struct pep_context *pep_ctx;

/*
 * 功能/Main: 处理proc 控制接口（Handle proc control interface）
 * 细节/Details: RTT/RTO 估计（RTT/RTO estimation）
 * 输入/Inputs: 参数/Inputs: cidr, addr, mask, prefix
 * 影响/Effects: 提供 /proc 控制接口，影响运行时配置（provide /proc control interface, affects runtime config）
 * 重要程度/Importance: 低/Low
 */
static bool pep_proc_parse_cidr(const char *cidr, __be32 *addr, __be32 *mask, u32 *prefix)
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
 * 功能/Main: 计算proc 控制接口（Compute proc control interface）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: rate_bps, burst_ms, min_bytes, tolerance
 * 影响/Effects: 计算派生值，影响策略决策（compute derived values, affects policy decisions）
 * 重要程度/Importance: 低/Low
 */
static u64 pep_proc_calc_burst(u64 rate_bps, u32 burst_ms,
                               u32 min_bytes, u32 tolerance)
{
    u64 burst = 0;

    if (rate_bps > 0 && burst_ms > 0)
        burst = div64_u64((rate_bps / 8) * (u64)burst_ms, 1000);

    if (burst < min_bytes)
        burst = min_bytes;

    burst += tolerance;

    return burst;
}

/*
 * 功能/Main: 更新带宽整形/调度（Update traffic shaping/scheduling）
 * 细节/Details: 带宽整形/速率限制（shaping/rate limit）；proc 接口读写（/proc IO）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: ctx
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 中/Medium
 */
static void pep_proc_update_shaper(struct pep_context *ctx)
{
    u64 lan_wan_rate_bps;
    u64 wan_lan_rate_bps;
    u64 lan_wan_burst;
    u64 wan_lan_burst;

    if (!ctx)
        return;

    lan_wan_rate_bps = (u64)ctx->config.wan_kbps * 1000ULL;
    wan_lan_rate_bps = (u64)ctx->config.wan_in_kbps * 1000ULL;

    lan_wan_burst = pep_proc_calc_burst(lan_wan_rate_bps,
                                        ctx->config.sm_burst_ms,
                                        ctx->config.sm_burst_min,
                                        ctx->config.sm_burst_tolerance);
    wan_lan_burst = pep_proc_calc_burst(wan_lan_rate_bps,
                                        ctx->config.sm_burst_ms,
                                        ctx->config.sm_burst_min,
                                        ctx->config.sm_burst_tolerance);

    if (!ctx->config.shaper_enabled) {
        lan_wan_rate_bps = 0;
        wan_lan_rate_bps = 0;
    }

    pep_shaper_update(&ctx->shaper_lan_wan, lan_wan_rate_bps, lan_wan_burst);
    pep_shaper_update(&ctx->shaper_wan_lan, wan_lan_rate_bps, wan_lan_burst);
}

/*
 * 功能/Main: 处理proc 控制接口（Handle proc control interface）
 * 细节/Details: 分片重组/重排处理（fragment reassembly）；流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；ACK pacing 调度（ACK pacing scheduling）；带宽整形/速率限制（shaping/rate limit）；FEC 编码/映射/恢复（FEC encode/map/recover）
 * 输入/Inputs: 参数/Inputs: m, v
 * 影响/Effects: 提供 /proc 控制接口，影响运行时配置（provide /proc control interface, affects runtime config）
 * 重要程度/Importance: 低/Low
 */
static int pep_proc_stats_show(struct seq_file *m, void *v)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);
    struct pep_percpu_stats total;
    const char *mode_str;

    if (!ctx) {
        seq_puts(m, "PEP context not initialized\n");
        return 0;
    }

    pep_stats_aggregate(&ctx->stats, &total);

    mode_str = ctx->config.tcp_spoofing ? "Spoofing" : "Monitor";

    seq_printf(m, "=== PEP Accelerator Statistics ===\n");
    seq_printf(m, "Version: %s (%s Mode)\n\n", PEP_VERSION, mode_str);

    seq_printf(m, "Status: %s\n",
               atomic_read(&ctx->running) ? "Running" : "Stopped");
    seq_printf(m, "Enabled: %s\n\n",
               ctx->config.enabled ? "Yes" : "No");

    seq_printf(m, "--- Packet Statistics ---\n");
    seq_printf(m, "RX packets:      %llu\n", total.rx_packets);
    seq_printf(m, "RX bytes:        %llu\n", total.rx_bytes);
    seq_printf(m, "TX packets:      %llu\n", total.tx_packets);
    seq_printf(m, "TX bytes:        %llu\n", total.tx_bytes);
    seq_printf(m, "Dropped:         %llu\n", total.dropped);
    seq_printf(m, "Errors:          %llu\n\n", total.errors);

    seq_printf(m, "--- Flow Statistics ---\n");
    seq_printf(m, "Active flows:    %d\n",
               atomic_read(&ctx->flow_table.count));
    seq_printf(m, "Flow creates:    %llu\n",
               atomic64_read(&ctx->stats.flow_creates));
    seq_printf(m, "Flow destroys:   %llu\n\n",
               atomic64_read(&ctx->stats.flow_destroys));

    seq_printf(m, "--- WAN SYN Statistics ---\n");
    seq_printf(m, "SYN sent:        %llu\n",
               atomic64_read(&ctx->stats.wan_syn_sent));
    seq_printf(m, "SYN-ACK recv:    %llu\n",
               atomic64_read(&ctx->stats.wan_syn_synack));
    seq_printf(m, "Timeouts:        %llu\n",
               atomic64_read(&ctx->stats.wan_syn_timeouts));
    seq_printf(m, "Retries queued:  %llu\n",
               atomic64_read(&ctx->stats.wan_syn_retries));
    seq_printf(m, "Retries sent:    %llu\n",
               atomic64_read(&ctx->stats.wan_syn_retransmit_sent));
    seq_printf(m, "Send failures:   %llu\n",
               atomic64_read(&ctx->stats.wan_syn_send_fail));
    seq_printf(m, "Max retries:     %llu\n",
               atomic64_read(&ctx->stats.wan_syn_max_retries));
    seq_printf(m, "Fail-open:       %llu\n",
               atomic64_read(&ctx->stats.wan_syn_fail_open));
    seq_printf(m, "Bypass SYN:      %llu\n",
               atomic64_read(&ctx->stats.wan_syn_bypass));
    seq_printf(m, "RST sent:        %llu\n",
               atomic64_read(&ctx->stats.wan_syn_rst));
    if (ctx->config.wan_syn_fail_open_ms > 0) {
        u64 now_ns = ktime_get_ns();
        u64 until_ns = READ_ONCE(ctx->syn_fail_open_until_ns);
        u64 remain_ms = (until_ns > now_ns) ?
                        (until_ns - now_ns) / NSEC_PER_MSEC : 0;

        seq_printf(m, "Fail-open active:%s (%llu ms)\n",
                   remain_ms ? "yes" : "no", remain_ms);
    }
    seq_puts(m, "\n");

    seq_printf(m, "--- Acceleration Statistics ---\n");
    seq_printf(m, "Fake ACKs:       %llu\n", total.fake_acks);
    seq_printf(m, "Advance ACKs:    %llu\n", total.adv_acks);
    seq_printf(m, "ACKs filtered:   %llu\n", total.acks_filtered);
    seq_printf(m, "Retransmits:     %llu\n", total.retrans);
    seq_printf(m, "Fast Path pkts:  %llu\n\n", total.fastpath_packets);

    seq_printf(m, "--- Configuration ---\n");
    seq_printf(m, "Max flows:       %u\n", ctx->config.max_flows);
    seq_printf(m, "Flow timeout:    %u ms\n", ctx->config.flow_timeout_ms);
    seq_printf(m, "RTO range:       %u-%u ms\n",
               ctx->config.rto_min_ms, ctx->config.rto_max_ms);
    seq_printf(m, "WAN SYN:         fail_open=%u ms retries=%u rto=%u-%u ms\n",
               ctx->config.wan_syn_fail_open_ms,
               ctx->config.wan_syn_max_retries,
               ctx->config.wan_syn_init_rto_ms,
               ctx->config.wan_syn_max_rto_ms);
    seq_printf(m, "CWND:            init=%u max=%u\n",
               ctx->config.init_cwnd, ctx->config.max_cwnd);
    seq_printf(m, "CC tuning:       cong=%u%% ber=%u%% rtt_infl=%u%% ecn=%u%%\n",
               ctx->config.cc_cong_reduction_pct,
               ctx->config.cc_ber_reduction_pct,
               ctx->config.cc_rtt_inflation_pct,
               ctx->config.ecn_ce_reduction_pct);
    seq_printf(m, "ECN:             enabled=%u\n", ctx->config.ecn_enabled);
    seq_printf(m, "Bandwidth:       %llu Mbps\n",
               ctx->config.bandwidth_bps / 1000000);
    seq_printf(m, "Shaper:          %s (wan=%u kbps wan_in=%u kbps)\n",
               ctx->config.shaper_enabled ? "enabled" : "disabled",
               ctx->config.wan_kbps, ctx->config.wan_in_kbps);
    seq_printf(m, "Flow cap:        %u kbps, bypass_overflows=%u\n",
               ctx->config.max_acc_flow_tx_kbps,
               ctx->config.bypass_overflows);
    if (ctx->config.subnet_acc && ctx->config.lan_segment_str[0]) {
        seq_printf(m, "LAN segment:     %s\n", ctx->config.lan_segment_str);
    } else {
        seq_puts(m, "LAN segment:     disabled\n");
    }
    seq_printf(m, "Queue LAN->WAN:  %u-%u packets\n",
               ctx->config.lan_wan_queue_min, ctx->config.lan_wan_queue_max);
    seq_printf(m, "Queue WAN->LAN:  %u-%u packets\n",
               ctx->config.wan_lan_queue_min, ctx->config.wan_lan_queue_max);
    seq_printf(m, "GSO: %s, GRO: %s, RSC: %s\n",
               ctx->config.gso_enabled ? "enabled" : "disabled",
               ctx->config.gro_enabled ? "enabled" : "disabled",
               ctx->config.rsc_enabled ? "enabled" : "disabled");
    seq_printf(m, "Checksum: tx=%s rx=%s\n",
               ctx->config.tx_csum_enabled ? "enabled" : "disabled",
               ctx->config.rx_csum_enabled ? "enabled" : "disabled");
    seq_printf(m, "Fast Path: %s (threshold=%u pkts)\n",
               ctx->config.fastpath_enabled ? "enabled" : "disabled",
               ctx->config.fastpath_threshold);
    seq_printf(m, "FEC: %s (K=%u, N=%u)\n",
               ctx->config.fec_enabled ? "enabled" : "disabled",
               PEP_FEC_DEFAULT_K, PEP_FEC_DEFAULT_N);
    seq_printf(m, "PMTU Discovery: %s\n",
               ctx->config.pmtu_enabled ? "enabled" : "disabled");
    seq_printf(m, "Scheduler: %s (small_flow=%u bytes)\n",
               ctx->config.sched_enabled ? "enabled" : "disabled",
               ctx->config.classify_small_flow_bytes);
    seq_printf(m, "Engine sched: engines=%u (delay wan=%u ms lan=%u ms)\n",
               ctx->engine_num,
               ctx->config.task_sched_delay_wan_ms,
               ctx->config.task_sched_delay_lan_ms);
    seq_printf(m, "RTT Probe: %s (interval=%u ms idle=%u ms)\n",
               ctx->config.rtt_probe_enabled ? "enabled" : "disabled",
               ctx->config.rtt_probe_interval_ms,
               ctx->config.rtt_probe_idle_ms);
    seq_printf(m, "IP Reassembly: %s\n",
               ctx->config.ip_reassembly_enabled ? "enabled" : "disabled");
    seq_printf(m, "Downlink Reorder: %s (max=%u timeout=%u ms)\n",
               ctx->config.downlink_reorder_enabled ? "enabled" : "disabled",
               ctx->config.downlink_reorder_max,
               ctx->config.downlink_reorder_timeout_ms);
    seq_printf(m, "Local retrans: %s (cache pkts=%u bytes=%u)\n",
               ctx->config.local_retrans ? "enabled" : "disabled",
               ctx->config.local_retrans_max_pkts,
               ctx->config.local_retrans_max_bytes);
    seq_printf(m, "Byte cache: %s (mem=%u MB disk=%u MB)\n",
               ctx->config.byte_cache_enabled ? "enabled" : "disabled",
               ctx->config.byte_cache_mem_mb,
               ctx->config.byte_cache_disk_mb);
    seq_printf(m, "Mem tune: %s (low=%u MB high=%u MB min=%u%% cap=%u bytes)\n",
               ctx->config.mem_tune_enabled ? "enabled" : "disabled",
               ctx->config.mem_tune_low_mb,
               ctx->config.mem_tune_high_mb,
               ctx->config.mem_tune_min_pct,
               ctx->config.mempool_max_cache_bytes);

    if (ctx->config.learning_enabled) {
        seq_printf(m, "\n--- Self-Learning CC ---\n");
        seq_printf(m, "Learning: %s\n",
                   atomic_read(&ctx->learning.learning_enabled) ? "active" : "frozen");
        seq_printf(m, "Active states: %d\n",
                   atomic_read(&ctx->learning.state_count));
        seq_printf(m, "Total decisions: %lld\n",
                   atomic64_read(&ctx->learning.total_decisions));
        seq_printf(m, "Explorations: %lld\n",
                   atomic64_read(&ctx->learning.total_explorations));
        seq_printf(m, "Total rewards: %lld\n",
                   atomic64_read(&ctx->learning.total_rewards));
        seq_printf(m, "Alpha (learning rate): %u/%u\n",
                   ctx->learning.alpha, PEP_FIXED_ONE);
        seq_printf(m, "Epsilon (exploration): %u/%u\n",
                   ctx->learning.epsilon, PEP_FIXED_ONE);
    }

    seq_printf(m, "\n--- ACK Pacing ---\n");
    seq_printf(m, "Enabled: %s\n",
               ctx->config.ack_pacing_enabled ? "yes" : "no");
    seq_printf(m, "Delay: %u us\n", ctx->config.ack_delay_us);
    seq_printf(m, "Bytes threshold: %u\n", ctx->config.ack_bytes_threshold);
    seq_printf(m, "Pacing: gain=%u%% min=%u us max=%u us min_rate=%u%%\n",
               ctx->config.pacing_gain_pct,
               ctx->config.pacing_min_interval_us,
               ctx->config.pacing_max_interval_us,
               ctx->config.pacing_min_rate_pct);

    if (ctx->config.region_learning_enabled) {
        seq_printf(m, "\n--- Regional Learning ---\n");
        seq_printf(m, "Enabled: yes\n");
        seq_printf(m, "Active regions: %d\n",
                   atomic_read(&ctx->region_table.count));
        seq_printf(m, "Max regions: %u\n", ctx->region_table.max_regions);
        seq_printf(m, "Prefix length: /%u\n", ctx->region_table.default_prefix_len);
    }

    seq_printf(m, "\n--- BDP-aware Queue ---\n");
    seq_printf(m, "Enabled: %s\n",
               ctx->config.queue_bdp_enabled ? "yes" : "no");
    if (ctx->config.queue_bdp_enabled) {
        seq_printf(m, "BDP multiplier: %u\n", ctx->config.queue_bdp_multiplier);
        seq_printf(m, "Absolute max: %u bytes (%u MB)\n",
                   ctx->config.queue_max_absolute,
                   ctx->config.queue_max_absolute / 1048576);
        seq_printf(m, "Backpressure thresholds: Level1=%u%%, Level2=%u%%\n",
                   PEP_QUEUE_BACKPRESSURE_LEVEL1, PEP_QUEUE_BACKPRESSURE_LEVEL2);
    }

    return 0;
}

/*
 * 功能/Main: 处理proc 控制接口（Handle proc control interface）
 * 细节/Details: proc 接口读写（/proc IO）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: inode, file
 * 影响/Effects: 提供 /proc 控制接口，影响运行时配置（provide /proc control interface, affects runtime config）
 * 重要程度/Importance: 低/Low
 */
static int pep_proc_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, pep_proc_stats_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops pep_proc_stats_ops = {
    .proc_open    = pep_proc_stats_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations pep_proc_stats_ops = {
    .owner   = THIS_MODULE,
    .open    = pep_proc_stats_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};
#endif

/*
 * 功能/Main: 处理proc 控制接口（Handle proc control interface）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；ACK pacing 调度（ACK pacing scheduling）；RTT/RTO 估计（RTT/RTO estimation）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: m, v
 * 影响/Effects: 提供 /proc 控制接口，影响运行时配置（provide /proc control interface, affects runtime config）
 * 重要程度/Importance: 低/Low
 */
static int pep_proc_flows_show(struct seq_file *m, void *v)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);
    struct pep_flow *flow;
    int bkt;
    int count = 0;

    if (!ctx) {
        seq_puts(m, "PEP context not initialized\n");
        return 0;
    }

    seq_printf(m, "=== Active TCP Flows ===\n\n");

    rcu_read_lock();
    hash_for_each_rcu(ctx->flow_table.flows, bkt, flow, hnode) {

        if (pep_flow_is_dead(flow))
            continue;

        seq_printf(m, "--- Flow %d: %pI4:%u -> %pI4:%u ---\n",
                   count + 1,
                   &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
                   &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));

        seq_printf(m, "  State: %s, Flags: 0x%lx\n",
                   pep_flow_state_str(flow->state), flow->flags);

        seq_printf(m, "  Packets: RX=%llu TX=%llu, Bytes: RX=%llu TX=%llu\n",
                   flow->rx_packets, flow->tx_packets,
                   flow->rx_bytes, flow->tx_bytes);

        seq_printf(m, "  CC: cwnd=%u ssthresh=%u in_flight=%u\n",
                   flow->cc.cwnd, flow->cc.ssthresh, flow->cc.bytes_in_flight);

        seq_printf(m, "  RTT: srtt=%u us, rto=%u ms, min=%u us\n",
                   flow->rtt.srtt >> 3, flow->rtt.rto, flow->rtt.min_rtt);

        seq_printf(m, "  Split-TCP: seq_offset=%d, fake_acks=%llu, retrans=%llu, adv_acks=%llu\n",
                   flow->seq_offset, flow->fake_acks_sent, flow->retrans_packets,
                   flow->adv_ack_sent_count);

        seq_printf(m, "  Queues: lan_wan=%u pkts, wan_lan=%u pkts, rtx=%u pkts\n",
                   pep_queue_len(&flow->lan_to_wan),
                   pep_queue_len(&flow->wan_to_lan),
                   skb_queue_len(&flow->rtx_queue));

        seq_printf(m, "  RACK: lost=%u, reord_wnd=%u us, min_rtt=%u us\n",
                   flow->rack.lost, flow->rack.reord_wnd_us, flow->rack.min_rtt_us);

        seq_printf(m, "  TLP: probes=%u, total_sent=%llu, recoveries=%llu\n",
                   flow->tlp.probes_sent, flow->tlp.total_tlp_sent,
                   flow->tlp.total_tlp_recoveries);

        seq_printf(m, "  Pacing: rate=%llu bps, interval=%u us, paced=%llu burst=%llu\n",
                   flow->pacing.pacing_rate_bps, flow->pacing.inter_packet_us,
                   flow->pacing.packets_paced, flow->pacing.packets_burst);

        seq_printf(m, "  ACK Pacer: sent=%llu, batched=%llu, interval=%u us\n",
                   flow->ack_pacer.acks_sent, flow->ack_pacer.acks_batched,
                   flow->ack_pacer.ack_interval_us);

        seq_printf(m, "\n");
        count++;

        if (count >= 50) {
            seq_printf(m, "... (showing first 50 flows)\n");
            break;
        }
    }
    rcu_read_unlock();

    seq_printf(m, "Total: %d flows\n", atomic_read(&ctx->flow_table.count));

    return 0;
}

/*
 * 功能/Main: 处理proc 控制接口（Handle proc control interface）
 * 细节/Details: proc 接口读写（/proc IO）
 * 输入/Inputs: 参数/Inputs: inode, file
 * 影响/Effects: 提供 /proc 控制接口，影响运行时配置（provide /proc control interface, affects runtime config）
 * 重要程度/Importance: 低/Low
 */
static int pep_proc_flows_open(struct inode *inode, struct file *file)
{
    return single_open(file, pep_proc_flows_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops pep_proc_flows_ops = {
    .proc_open    = pep_proc_flows_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations pep_proc_flows_ops = {
    .owner   = THIS_MODULE,
    .open    = pep_proc_flows_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};
#endif

/*
 * 功能/Main: 处理proc 控制接口（Handle proc control interface）
 * 细节/Details: 分片重组/重排处理（fragment reassembly）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；ACK pacing 调度（ACK pacing scheduling）；带宽整形/速率限制（shaping/rate limit）；FEC 编码/映射/恢复（FEC encode/map/recover）；RTT/RTO 估计（RTT/RTO estimation）
 * 输入/Inputs: 参数/Inputs: m, v
 * 影响/Effects: 提供 /proc 控制接口，影响运行时配置（provide /proc control interface, affects runtime config）
 * 重要程度/Importance: 低/Low
 */
static int pep_proc_config_show(struct seq_file *m, void *v)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);

    if (!ctx) {
        seq_puts(m, "PEP context not initialized\n");
        return 0;
    }

    seq_printf(m, "=== PEP Configuration ===\n");
    seq_printf(m, "enabled=%u\n", ctx->config.enabled);
    seq_printf(m, "max_flows=%u\n", ctx->config.max_flows);
    seq_printf(m, "flow_timeout_ms=%u\n", ctx->config.flow_timeout_ms);
    seq_printf(m, "lan_wan_queue_min=%u\n", ctx->config.lan_wan_queue_min);
    seq_printf(m, "lan_wan_queue_max=%u\n", ctx->config.lan_wan_queue_max);
    seq_printf(m, "wan_lan_queue_min=%u\n", ctx->config.wan_lan_queue_min);
    seq_printf(m, "wan_lan_queue_max=%u\n", ctx->config.wan_lan_queue_max);
    seq_printf(m, "max_retrans=%u\n", ctx->config.max_retrans);
    seq_printf(m, "rto_min_ms=%u\n", ctx->config.rto_min_ms);
    seq_printf(m, "rto_max_ms=%u\n", ctx->config.rto_max_ms);
    seq_printf(m, "wan_syn_fail_open_ms=%u\n", ctx->config.wan_syn_fail_open_ms);
    seq_printf(m, "wan_syn_max_retries=%u\n", ctx->config.wan_syn_max_retries);
    seq_printf(m, "wan_syn_init_rto_ms=%u\n", ctx->config.wan_syn_init_rto_ms);
    seq_printf(m, "wan_syn_max_rto_ms=%u\n", ctx->config.wan_syn_max_rto_ms);
    seq_printf(m, "init_cwnd=%u\n", ctx->config.init_cwnd);
    seq_printf(m, "max_cwnd=%u\n", ctx->config.max_cwnd);
    seq_printf(m, "cc_cong_reduction_pct=%u\n", ctx->config.cc_cong_reduction_pct);
    seq_printf(m, "cc_ber_reduction_pct=%u\n", ctx->config.cc_ber_reduction_pct);
    seq_printf(m, "cc_rtt_inflation_pct=%u\n", ctx->config.cc_rtt_inflation_pct);
    seq_printf(m, "ecn_ce_reduction_pct=%u\n", ctx->config.ecn_ce_reduction_pct);
    seq_printf(m, "ecn_enabled=%u\n", ctx->config.ecn_enabled);
    seq_printf(m, "bandwidth_bps=%llu\n", ctx->config.bandwidth_bps);
    seq_printf(m, "burst_size=%llu\n", ctx->config.burst_size);
    seq_printf(m, "shaper_enabled=%u\n", ctx->config.shaper_enabled);
    seq_printf(m, "wan_kbps=%u\n", ctx->config.wan_kbps);
    seq_printf(m, "wan_in_kbps=%u\n", ctx->config.wan_in_kbps);
    seq_printf(m, "sm_burst_ms=%u\n", ctx->config.sm_burst_ms);
    seq_printf(m, "sm_burst_min=%u\n", ctx->config.sm_burst_min);
    seq_printf(m, "sm_burst_tolerance=%u\n", ctx->config.sm_burst_tolerance);
    seq_printf(m, "bypass_overflows=%u\n", ctx->config.bypass_overflows);
    seq_printf(m, "max_acc_flow_tx_kbps=%u\n", ctx->config.max_acc_flow_tx_kbps);
    seq_printf(m, "subnet_acc=%u\n", ctx->config.subnet_acc);
    seq_printf(m, "lan_segment=%s\n", ctx->config.lan_segment_str);
    seq_printf(m, "tcp_spoofing=%u\n", ctx->config.tcp_spoofing);
    seq_printf(m, "advacc=%u\n", ctx->config.aggressive_ack);
    seq_printf(m, "advinacc=%u\n", ctx->config.fake_ack);
    seq_printf(m, "fake_ack=%u\n", ctx->config.fake_ack);
    seq_printf(m, "local_retrans=%u\n", ctx->config.local_retrans);
    seq_printf(m, "local_retrans_max_pkts=%u\n", ctx->config.local_retrans_max_pkts);
    seq_printf(m, "local_retrans_max_bytes=%u\n", ctx->config.local_retrans_max_bytes);
    seq_printf(m, "byte_cache_enabled=%u\n", ctx->config.byte_cache_enabled);
    seq_printf(m, "byte_cache_mem_mb=%u\n", ctx->config.byte_cache_mem_mb);
    seq_printf(m, "byte_cache_disk_mb=%u\n", ctx->config.byte_cache_disk_mb);
    seq_printf(m, "byte_cache_disk_path=%s\n", ctx->config.byte_cache_disk_path);
    seq_printf(m, "mem_tune_enabled=%u\n", ctx->config.mem_tune_enabled);
    seq_printf(m, "mem_tune_low_mb=%u\n", ctx->config.mem_tune_low_mb);
    seq_printf(m, "mem_tune_high_mb=%u\n", ctx->config.mem_tune_high_mb);
    seq_printf(m, "mem_tune_min_pct=%u\n", ctx->config.mem_tune_min_pct);
    seq_printf(m, "mempool_max_cache_bytes=%u\n", ctx->config.mempool_max_cache_bytes);
    seq_printf(m, "gso_enabled=%u\n", ctx->config.gso_enabled);
    seq_printf(m, "gro_enabled=%u\n", ctx->config.gro_enabled);
    seq_printf(m, "rsc_enabled=%u\n", ctx->config.rsc_enabled);
    seq_printf(m, "rsc_max_size=%u\n", ctx->config.rsc_max_size);
    seq_printf(m, "rsc_timeout_us=%u\n", ctx->config.rsc_timeout_us);
    seq_printf(m, "tx_csum_enabled=%u\n", ctx->config.tx_csum_enabled);
    seq_printf(m, "rx_csum_enabled=%u\n", ctx->config.rx_csum_enabled);
    seq_printf(m, "fastpath_enabled=%u\n", ctx->config.fastpath_enabled);
    seq_printf(m, "fastpath_threshold=%u\n", ctx->config.fastpath_threshold);
    seq_printf(m, "fec_enabled=%u\n", ctx->config.fec_enabled);
    seq_printf(m, "pmtu_enabled=%u\n", ctx->config.pmtu_enabled);
    seq_printf(m, "pmtu_timeout_ms=%u\n", ctx->config.pmtu_timeout_ms);
    seq_printf(m, "pmtu_default=%u\n", ctx->config.pmtu_default);
    seq_printf(m, "ack_pacing=%u\n", ctx->config.ack_pacing_enabled);
    seq_printf(m, "ack_delay_us=%u\n", ctx->config.ack_delay_us);
    seq_printf(m, "ack_bytes_threshold=%u\n", ctx->config.ack_bytes_threshold);
    seq_printf(m, "pacing_gain_pct=%u\n", ctx->config.pacing_gain_pct);
    seq_printf(m, "pacing_min_interval_us=%u\n", ctx->config.pacing_min_interval_us);
    seq_printf(m, "pacing_max_interval_us=%u\n", ctx->config.pacing_max_interval_us);
    seq_printf(m, "pacing_min_rate_pct=%u\n", ctx->config.pacing_min_rate_pct);
    seq_printf(m, "reseq_enabled=%u\n", ctx->config.reseq_enabled);
    seq_printf(m, "reseq_max_packets=%u\n", ctx->config.reseq_max_packets);
    seq_printf(m, "sched_enabled=%u\n", ctx->config.sched_enabled);
    seq_printf(m, "classify_small_flow_bytes=%u\n", ctx->config.classify_small_flow_bytes);
    seq_printf(m, "engine_num=%u\n", ctx->config.engine_num);
    seq_printf(m, "task_sched_delay_wan_ms=%u\n", ctx->config.task_sched_delay_wan_ms);
    seq_printf(m, "task_sched_delay_lan_ms=%u\n", ctx->config.task_sched_delay_lan_ms);
    seq_printf(m, "rtt_probe_enabled=%u\n", ctx->config.rtt_probe_enabled);
    seq_printf(m, "rtt_probe_interval_ms=%u\n", ctx->config.rtt_probe_interval_ms);
    seq_printf(m, "rtt_probe_idle_ms=%u\n", ctx->config.rtt_probe_idle_ms);
    seq_printf(m, "ip_reassembly_enabled=%u\n", ctx->config.ip_reassembly_enabled);
    seq_printf(m, "downlink_reorder_enabled=%u\n", ctx->config.downlink_reorder_enabled);
    seq_printf(m, "downlink_reorder_max=%u\n", ctx->config.downlink_reorder_max);
    seq_printf(m, "downlink_reorder_timeout_ms=%u\n", ctx->config.downlink_reorder_timeout_ms);
    seq_printf(m, "debug_level=%u\n", ctx->config.debug_level);
    seq_printf(m, "wan_ifname=%s\n", ctx->config.wan_ifname);
    seq_printf(m, "lan_ifname=%s\n", ctx->config.lan_ifname);

    seq_printf(m, "queue_bdp_enabled=%u\n", ctx->config.queue_bdp_enabled);
    seq_printf(m, "queue_bdp_multiplier=%u\n", ctx->config.queue_bdp_multiplier);
    seq_printf(m, "queue_max_absolute=%u\n", ctx->config.queue_max_absolute);

    return 0;
}

/*
 * 功能/Main: 处理proc 控制接口（Handle proc control interface）
 * 细节/Details: 分片重组/重排处理（fragment reassembly）；流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；ACK pacing 调度（ACK pacing scheduling）；带宽整形/速率限制（shaping/rate limit）；FEC 编码/映射/恢复（FEC encode/map/recover）
 * 输入/Inputs: 参数/Inputs: file, buf, count, ppos
 * 影响/Effects: 提供 /proc 控制接口，影响运行时配置（provide /proc control interface, affects runtime config）
 * 重要程度/Importance: 低/Low
 */
static ssize_t pep_proc_config_write(struct file *file, const char __user *buf,
                                     size_t count, loff_t *ppos)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);
    char kbuf[256];
    char *line, *key, *val;
    size_t len;

    if (!ctx)
        return -ENODEV;

    len = min(count, sizeof(kbuf) - 1);
    if (copy_from_user(kbuf, buf, len))
        return -EFAULT;

    kbuf[len] = '\0';

    line = strim(kbuf);
    key = strsep(&line, "=");
    val = line;

    if (!key || !val)
        return -EINVAL;

    key = strim(key);
    val = strim(val);

    if (strcmp(key, "enabled") == 0) {
        ctx->config.enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: enabled=%u\n", ctx->config.enabled);
    } else if (strcmp(key, "max_flows") == 0) {
        ctx->config.max_flows = simple_strtoul(val, NULL, 10);
        ctx->flow_table.max_flows = ctx->config.max_flows;
    } else if (strcmp(key, "bandwidth_bps") == 0) {
        u64 bps = simple_strtoull(val, NULL, 10);
        u32 kbps = (u32)(bps / 1000ULL);
        ctx->config.bandwidth_bps = bps;
        ctx->config.wan_kbps = kbps;
        ctx->config.wan_in_kbps = kbps;
        ctx->config.burst_size = pep_proc_calc_burst(bps,
                                                     ctx->config.sm_burst_ms,
                                                     ctx->config.sm_burst_min,
                                                     ctx->config.sm_burst_tolerance);
        pep_proc_update_shaper(ctx);
    } else if (strcmp(key, "shaper_enabled") == 0) {
        ctx->config.shaper_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_proc_update_shaper(ctx);
        pep_info("Config: shaper_enabled=%u\n", ctx->config.shaper_enabled);
    } else if (strcmp(key, "wan_kbps") == 0) {
        ctx->config.wan_kbps = simple_strtoul(val, NULL, 10);
        ctx->config.bandwidth_bps = (u64)max(ctx->config.wan_kbps,
                                             ctx->config.wan_in_kbps) * 1000ULL;
        ctx->config.burst_size = pep_proc_calc_burst(ctx->config.bandwidth_bps,
                                                     ctx->config.sm_burst_ms,
                                                     ctx->config.sm_burst_min,
                                                     ctx->config.sm_burst_tolerance);
        pep_proc_update_shaper(ctx);
        pep_info("Config: wan_kbps=%u\n", ctx->config.wan_kbps);
    } else if (strcmp(key, "wan_in_kbps") == 0) {
        ctx->config.wan_in_kbps = simple_strtoul(val, NULL, 10);
        ctx->config.bandwidth_bps = (u64)max(ctx->config.wan_kbps,
                                             ctx->config.wan_in_kbps) * 1000ULL;
        ctx->config.burst_size = pep_proc_calc_burst(ctx->config.bandwidth_bps,
                                                     ctx->config.sm_burst_ms,
                                                     ctx->config.sm_burst_min,
                                                     ctx->config.sm_burst_tolerance);
        pep_proc_update_shaper(ctx);
        pep_info("Config: wan_in_kbps=%u\n", ctx->config.wan_in_kbps);
    } else if (strcmp(key, "sm_burst_ms") == 0) {
        ctx->config.sm_burst_ms = simple_strtoul(val, NULL, 10);
        ctx->config.burst_size = pep_proc_calc_burst(ctx->config.bandwidth_bps,
                                                     ctx->config.sm_burst_ms,
                                                     ctx->config.sm_burst_min,
                                                     ctx->config.sm_burst_tolerance);
        pep_proc_update_shaper(ctx);
        pep_info("Config: sm_burst_ms=%u\n", ctx->config.sm_burst_ms);
    } else if (strcmp(key, "sm_burst_min") == 0) {
        ctx->config.sm_burst_min = simple_strtoul(val, NULL, 10);
        ctx->config.burst_size = pep_proc_calc_burst(ctx->config.bandwidth_bps,
                                                     ctx->config.sm_burst_ms,
                                                     ctx->config.sm_burst_min,
                                                     ctx->config.sm_burst_tolerance);
        pep_proc_update_shaper(ctx);
        pep_info("Config: sm_burst_min=%u\n", ctx->config.sm_burst_min);
    } else if (strcmp(key, "sm_burst_tolerance") == 0) {
        ctx->config.sm_burst_tolerance = simple_strtoul(val, NULL, 10);
        ctx->config.burst_size = pep_proc_calc_burst(ctx->config.bandwidth_bps,
                                                     ctx->config.sm_burst_ms,
                                                     ctx->config.sm_burst_min,
                                                     ctx->config.sm_burst_tolerance);
        pep_proc_update_shaper(ctx);
        pep_info("Config: sm_burst_tolerance=%u\n", ctx->config.sm_burst_tolerance);
    } else if (strcmp(key, "bypass_overflows") == 0) {
        ctx->config.bypass_overflows = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: bypass_overflows=%u\n", ctx->config.bypass_overflows);
    } else if (strcmp(key, "max_acc_flow_tx_kbps") == 0) {
        ctx->config.max_acc_flow_tx_kbps = simple_strtoul(val, NULL, 10);
        pep_info("Config: max_acc_flow_tx_kbps=%u\n",
                 ctx->config.max_acc_flow_tx_kbps);
    } else if (strcmp(key, "subnet_acc") == 0) {
        ctx->config.subnet_acc = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: subnet_acc=%u\n", ctx->config.subnet_acc);
    } else if (strcmp(key, "lan_segment") == 0) {
        if (val[0] == '\0') {
            ctx->config.subnet_acc = 0;
            ctx->config.lan_segment_prefix = 0;
            ctx->config.lan_segment_addr = 0;
            ctx->config.lan_segment_mask = 0;
            ctx->config.lan_segment_str[0] = '\0';
            pep_info("Config: lan_segment cleared\n");
        } else if (pep_proc_parse_cidr(val, &ctx->config.lan_segment_addr,
                                       &ctx->config.lan_segment_mask,
                                       &ctx->config.lan_segment_prefix)) {
            ctx->config.subnet_acc = 1;
            strscpy(ctx->config.lan_segment_str, val,
                    sizeof(ctx->config.lan_segment_str));
            pep_info("Config: lan_segment=%s\n", ctx->config.lan_segment_str);
        } else {
            pep_warn("Invalid lan_segment: %s\n", val);
            return -EINVAL;
        }
    } else if (strcmp(key, "debug_level") == 0) {
        ctx->config.debug_level = simple_strtoul(val, NULL, 10);
    } else if (strcmp(key, "tcp_spoofing") == 0) {
        ctx->config.tcp_spoofing = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: tcp_spoofing=%u\n", ctx->config.tcp_spoofing);
    } else if (strcmp(key, "advacc") == 0 || strcmp(key, "aggressive_ack") == 0) {
        ctx->config.aggressive_ack = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: advacc=%u\n", ctx->config.aggressive_ack);
    } else if (strcmp(key, "advinacc") == 0) {
        ctx->config.fake_ack = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: advinacc=%u\n", ctx->config.fake_ack);
    } else if (strcmp(key, "fake_ack") == 0) {
        ctx->config.fake_ack = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: fake_ack=%u\n", ctx->config.fake_ack);
    } else if (strcmp(key, "init_cwnd") == 0) {
        ctx->config.init_cwnd = simple_strtoul(val, NULL, 10);
        pep_info("Config: init_cwnd=%u\n", ctx->config.init_cwnd);
    } else if (strcmp(key, "wan_syn_fail_open_ms") == 0) {
        ctx->config.wan_syn_fail_open_ms = simple_strtoul(val, NULL, 10);
        pep_info("Config: wan_syn_fail_open_ms=%u\n", ctx->config.wan_syn_fail_open_ms);
    } else if (strcmp(key, "wan_syn_max_retries") == 0) {
        ctx->config.wan_syn_max_retries = simple_strtoul(val, NULL, 10);
        pep_info("Config: wan_syn_max_retries=%u\n", ctx->config.wan_syn_max_retries);
    } else if (strcmp(key, "wan_syn_init_rto_ms") == 0) {
        ctx->config.wan_syn_init_rto_ms = simple_strtoul(val, NULL, 10);
        pep_info("Config: wan_syn_init_rto_ms=%u\n", ctx->config.wan_syn_init_rto_ms);
    } else if (strcmp(key, "wan_syn_max_rto_ms") == 0) {
        ctx->config.wan_syn_max_rto_ms = simple_strtoul(val, NULL, 10);
        pep_info("Config: wan_syn_max_rto_ms=%u\n", ctx->config.wan_syn_max_rto_ms);
    } else if (strcmp(key, "cc_cong_reduction_pct") == 0) {
        ctx->config.cc_cong_reduction_pct = simple_strtoul(val, NULL, 10);
        pep_info("Config: cc_cong_reduction_pct=%u\n", ctx->config.cc_cong_reduction_pct);
    } else if (strcmp(key, "cc_ber_reduction_pct") == 0) {
        ctx->config.cc_ber_reduction_pct = simple_strtoul(val, NULL, 10);
        pep_info("Config: cc_ber_reduction_pct=%u\n", ctx->config.cc_ber_reduction_pct);
    } else if (strcmp(key, "cc_rtt_inflation_pct") == 0) {
        ctx->config.cc_rtt_inflation_pct = simple_strtoul(val, NULL, 10);
        pep_info("Config: cc_rtt_inflation_pct=%u\n", ctx->config.cc_rtt_inflation_pct);
    } else if (strcmp(key, "ecn_ce_reduction_pct") == 0) {
        ctx->config.ecn_ce_reduction_pct = simple_strtoul(val, NULL, 10);
        pep_info("Config: ecn_ce_reduction_pct=%u\n", ctx->config.ecn_ce_reduction_pct);
    } else if (strcmp(key, "ecn_enabled") == 0) {
        ctx->config.ecn_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: ecn_enabled=%u\n", ctx->config.ecn_enabled);
    } else if (strcmp(key, "local_retrans") == 0) {
        ctx->config.local_retrans = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: local_retrans=%u\n", ctx->config.local_retrans);
    } else if (strcmp(key, "local_retrans_max_pkts") == 0) {
        ctx->config.local_retrans_max_pkts = simple_strtoul(val, NULL, 10);
        pep_info("Config: local_retrans_max_pkts=%u (new flows)\n",
                 ctx->config.local_retrans_max_pkts);
    } else if (strcmp(key, "local_retrans_max_bytes") == 0) {
        ctx->config.local_retrans_max_bytes = simple_strtoul(val, NULL, 10);
        pep_info("Config: local_retrans_max_bytes=%u (new flows)\n",
                 ctx->config.local_retrans_max_bytes);
    } else if (strcmp(key, "byte_cache_enabled") == 0) {
        ctx->config.byte_cache_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_byte_cache_init(ctx);
        pep_info("Config: byte_cache_enabled=%u\n", ctx->config.byte_cache_enabled);
    } else if (strcmp(key, "byte_cache_mem_mb") == 0) {
        ctx->config.byte_cache_mem_mb = simple_strtoul(val, NULL, 10);
        pep_byte_cache_init(ctx);
        pep_info("Config: byte_cache_mem_mb=%u\n", ctx->config.byte_cache_mem_mb);
    } else if (strcmp(key, "byte_cache_disk_mb") == 0) {
        ctx->config.byte_cache_disk_mb = simple_strtoul(val, NULL, 10);
        pep_byte_cache_init(ctx);
        pep_info("Config: byte_cache_disk_mb=%u\n", ctx->config.byte_cache_disk_mb);
    } else if (strcmp(key, "byte_cache_disk_path") == 0) {
        if (val[0] == '\0') {
            pep_warn("byte_cache_disk_path cannot be empty\n");
            return -EINVAL;
        }
        strscpy(ctx->config.byte_cache_disk_path, val,
                sizeof(ctx->config.byte_cache_disk_path));
        pep_byte_cache_init(ctx);
        pep_info("Config: byte_cache_disk_path=%s\n",
                 ctx->config.byte_cache_disk_path);
    } else if (strcmp(key, "mem_tune_enabled") == 0) {
        ctx->config.mem_tune_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: mem_tune_enabled=%u\n", ctx->config.mem_tune_enabled);
    } else if (strcmp(key, "mem_tune_low_mb") == 0) {
        ctx->config.mem_tune_low_mb = simple_strtoul(val, NULL, 10);
        pep_info("Config: mem_tune_low_mb=%u\n", ctx->config.mem_tune_low_mb);
    } else if (strcmp(key, "mem_tune_high_mb") == 0) {
        ctx->config.mem_tune_high_mb = simple_strtoul(val, NULL, 10);
        pep_info("Config: mem_tune_high_mb=%u\n", ctx->config.mem_tune_high_mb);
    } else if (strcmp(key, "mem_tune_min_pct") == 0) {
        ctx->config.mem_tune_min_pct = simple_strtoul(val, NULL, 10);
        pep_info("Config: mem_tune_min_pct=%u\n", ctx->config.mem_tune_min_pct);
    } else if (strcmp(key, "mempool_max_cache_bytes") == 0) {
        ctx->config.mempool_max_cache_bytes = simple_strtoul(val, NULL, 10);
        ctx->mempool.max_cache_bytes = ctx->config.mempool_max_cache_bytes;
        pep_info("Config: mempool_max_cache_bytes=%u\n",
                 ctx->config.mempool_max_cache_bytes);
    } else if (strcmp(key, "gso_enabled") == 0) {
        ctx->config.gso_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: gso_enabled=%u\n", ctx->config.gso_enabled);
    } else if (strcmp(key, "gro_enabled") == 0) {
        ctx->config.gro_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: gro_enabled=%u\n", ctx->config.gro_enabled);
    } else if (strcmp(key, "rsc_enabled") == 0) {
        ctx->config.rsc_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: rsc_enabled=%u (new flows)\n", ctx->config.rsc_enabled);
    } else if (strcmp(key, "rsc_max_size") == 0) {
        ctx->config.rsc_max_size = simple_strtoul(val, NULL, 10);
        pep_info("Config: rsc_max_size=%u (new flows)\n", ctx->config.rsc_max_size);
    } else if (strcmp(key, "rsc_timeout_us") == 0) {
        ctx->config.rsc_timeout_us = simple_strtoul(val, NULL, 10);
        pep_info("Config: rsc_timeout_us=%u\n", ctx->config.rsc_timeout_us);
    } else if (strcmp(key, "tx_csum_enabled") == 0) {
        ctx->config.tx_csum_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: tx_csum_enabled=%u\n", ctx->config.tx_csum_enabled);
    } else if (strcmp(key, "rx_csum_enabled") == 0) {
        ctx->config.rx_csum_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: rx_csum_enabled=%u\n", ctx->config.rx_csum_enabled);
    } else if (strcmp(key, "ack_pacing") == 0) {
        ctx->config.ack_pacing_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: ack_pacing=%u\n", ctx->config.ack_pacing_enabled);
    } else if (strcmp(key, "ack_delay_us") == 0) {
        ctx->config.ack_delay_us = simple_strtoul(val, NULL, 10);
        pep_info("Config: ack_delay_us=%u\n", ctx->config.ack_delay_us);
    } else if (strcmp(key, "ack_bytes_threshold") == 0) {
        ctx->config.ack_bytes_threshold = simple_strtoul(val, NULL, 10);
        pep_info("Config: ack_bytes_threshold=%u\n", ctx->config.ack_bytes_threshold);
    } else if (strcmp(key, "pacing_gain_pct") == 0) {
        ctx->config.pacing_gain_pct = simple_strtoul(val, NULL, 10);
        pep_info("Config: pacing_gain_pct=%u\n", ctx->config.pacing_gain_pct);
    } else if (strcmp(key, "pacing_min_interval_us") == 0) {
        ctx->config.pacing_min_interval_us = simple_strtoul(val, NULL, 10);
        pep_info("Config: pacing_min_interval_us=%u\n", ctx->config.pacing_min_interval_us);
    } else if (strcmp(key, "pacing_max_interval_us") == 0) {
        ctx->config.pacing_max_interval_us = simple_strtoul(val, NULL, 10);
        pep_info("Config: pacing_max_interval_us=%u\n", ctx->config.pacing_max_interval_us);
    } else if (strcmp(key, "pacing_min_rate_pct") == 0) {
        ctx->config.pacing_min_rate_pct = simple_strtoul(val, NULL, 10);
        pep_info("Config: pacing_min_rate_pct=%u\n", ctx->config.pacing_min_rate_pct);
    } else if (strcmp(key, "learning_enabled") == 0) {
        ctx->config.learning_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: learning_enabled=%u\n", ctx->config.learning_enabled);
    } else if (strcmp(key, "region_learning") == 0) {
        ctx->config.region_learning_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: region_learning=%u\n", ctx->config.region_learning_enabled);
    } else if (strcmp(key, "fec_enabled") == 0) {
        ctx->config.fec_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: fec_enabled=%u\n", ctx->config.fec_enabled);
    } else if (strcmp(key, "pmtu_enabled") == 0) {
        ctx->config.pmtu_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: pmtu_enabled=%u\n", ctx->config.pmtu_enabled);
    } else if (strcmp(key, "pmtu_timeout_ms") == 0) {
        ctx->config.pmtu_timeout_ms = simple_strtoul(val, NULL, 10);
        pep_pmtu_set_defaults(ctx->config.pmtu_default, ctx->config.pmtu_timeout_ms);
        pep_info("Config: pmtu_timeout_ms=%u\n", ctx->config.pmtu_timeout_ms);
    } else if (strcmp(key, "pmtu_default") == 0) {
        ctx->config.pmtu_default = simple_strtoul(val, NULL, 10);
        pep_pmtu_set_defaults(ctx->config.pmtu_default, ctx->config.pmtu_timeout_ms);
        pep_info("Config: pmtu_default=%u\n", ctx->config.pmtu_default);
    } else if (strcmp(key, "reseq_enabled") == 0) {
        ctx->config.reseq_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: reseq_enabled=%u (new flows)\n", ctx->config.reseq_enabled);
    } else if (strcmp(key, "reseq_max_packets") == 0 ||
               strcmp(key, "reseqPacketCnt") == 0) {
        u32 max_pkts = simple_strtoul(val, NULL, 10);
        if (max_pkts > 4096) {
            pep_warn("Invalid reseq_max_packets: %u (valid: 0-4096)\n", max_pkts);
            return -EINVAL;
        }
        ctx->config.reseq_max_packets = max_pkts;
        if (max_pkts == 0)
            ctx->config.reseq_enabled = 0;
        pep_info("Config: reseq_max_packets=%u (new flows)\n", max_pkts);
    } else if (strcmp(key, "sched_enabled") == 0) {
        ctx->config.sched_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: sched_enabled=%u\n", ctx->config.sched_enabled);
    } else if (strcmp(key, "classify_small_flow_bytes") == 0) {
        ctx->config.classify_small_flow_bytes = simple_strtoul(val, NULL, 10);
        pep_info("Config: classify_small_flow_bytes=%u\n",
                 ctx->config.classify_small_flow_bytes);
    } else if (strcmp(key, "engine_num") == 0) {
        pep_warn("Config: engine_num is static, reload required\n");
    } else if (strcmp(key, "task_sched_delay_wan_ms") == 0) {
        u32 delay = simple_strtoul(val, NULL, 10);
        u32 i;
        ctx->config.task_sched_delay_wan_ms = delay;
        if (ctx->sched_wan) {
            for (i = 0; i < ctx->engine_num; i++)
                ctx->sched_wan[i].delay_ms = delay;
        }
        pep_info("Config: task_sched_delay_wan_ms=%u\n", delay);
    } else if (strcmp(key, "task_sched_delay_lan_ms") == 0) {
        u32 delay = simple_strtoul(val, NULL, 10);
        u32 i;
        ctx->config.task_sched_delay_lan_ms = delay;
        if (ctx->sched_lan) {
            for (i = 0; i < ctx->engine_num; i++)
                ctx->sched_lan[i].delay_ms = delay;
        }
        pep_info("Config: task_sched_delay_lan_ms=%u\n", delay);
    } else if (strcmp(key, "rtt_probe_enabled") == 0) {
        ctx->config.rtt_probe_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: rtt_probe_enabled=%u\n", ctx->config.rtt_probe_enabled);
        if (ctx->config.rtt_probe_enabled && ctx->config.rtt_probe_interval_ms > 0) {
            queue_delayed_work(ctx->wq, &ctx->rtt_probe_work,
                               msecs_to_jiffies(ctx->config.rtt_probe_interval_ms));
        } else {
            cancel_delayed_work_sync(&ctx->rtt_probe_work);
        }
    } else if (strcmp(key, "rtt_probe_interval_ms") == 0) {
        ctx->config.rtt_probe_interval_ms = simple_strtoul(val, NULL, 10);
        pep_info("Config: rtt_probe_interval_ms=%u\n",
                 ctx->config.rtt_probe_interval_ms);
        if (ctx->config.rtt_probe_enabled && ctx->config.rtt_probe_interval_ms > 0) {
            queue_delayed_work(ctx->wq, &ctx->rtt_probe_work,
                               msecs_to_jiffies(ctx->config.rtt_probe_interval_ms));
        }
    } else if (strcmp(key, "rtt_probe_idle_ms") == 0) {
        ctx->config.rtt_probe_idle_ms = simple_strtoul(val, NULL, 10);
        pep_info("Config: rtt_probe_idle_ms=%u\n", ctx->config.rtt_probe_idle_ms);
    } else if (strcmp(key, "ip_reassembly_enabled") == 0) {
        ctx->config.ip_reassembly_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: ip_reassembly_enabled=%u\n",
                 ctx->config.ip_reassembly_enabled);
    } else if (strcmp(key, "downlink_reorder_enabled") == 0) {
        ctx->config.downlink_reorder_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: downlink_reorder_enabled=%u\n",
                 ctx->config.downlink_reorder_enabled);
    } else if (strcmp(key, "downlink_reorder_max") == 0) {
        u32 max_pkts = simple_strtoul(val, NULL, 10);
        if (max_pkts > 8192) {
            pep_warn("Invalid downlink_reorder_max: %u (valid: 0-8192)\n", max_pkts);
            return -EINVAL;
        }
        ctx->config.downlink_reorder_max = max_pkts;
        if (max_pkts == 0)
            ctx->config.downlink_reorder_enabled = 0;
        pep_info("Config: downlink_reorder_max=%u (new flows)\n", max_pkts);
    } else if (strcmp(key, "downlink_reorder_timeout_ms") == 0) {
        ctx->config.downlink_reorder_timeout_ms = simple_strtoul(val, NULL, 10);
        pep_info("Config: downlink_reorder_timeout_ms=%u\n",
                 ctx->config.downlink_reorder_timeout_ms);
    } else if (strcmp(key, "fastpath_enabled") == 0) {
        ctx->config.fastpath_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: fastpath_enabled=%u\n", ctx->config.fastpath_enabled);
    } else if (strcmp(key, "fastpath_threshold") == 0) {
        ctx->config.fastpath_threshold = simple_strtoul(val, NULL, 10);
        pep_info("Config: fastpath_threshold=%u\n", ctx->config.fastpath_threshold);
    } else if (strcmp(key, "queue_bdp_enabled") == 0) {
        ctx->config.queue_bdp_enabled = simple_strtoul(val, NULL, 10) ? 1 : 0;
        pep_info("Config: queue_bdp_enabled=%u\n", ctx->config.queue_bdp_enabled);
    } else if (strcmp(key, "queue_bdp_multiplier") == 0) {
        u32 mult = simple_strtoul(val, NULL, 10);
        if (mult >= 1 && mult <= 10) {
            ctx->config.queue_bdp_multiplier = mult;
            pep_info("Config: queue_bdp_multiplier=%u\n", ctx->config.queue_bdp_multiplier);
        } else {
            pep_warn("Invalid queue_bdp_multiplier: %u (valid: 1-10)\n", mult);
            return -EINVAL;
        }
    } else if (strcmp(key, "queue_max_absolute") == 0) {
        u32 max_bytes = simple_strtoul(val, NULL, 10);
        if (max_bytes >= 1048576 && max_bytes <= 67108864) {
            ctx->config.queue_max_absolute = max_bytes;
            pep_info("Config: queue_max_absolute=%u (%u MB)\n",
                     max_bytes, max_bytes / 1048576);
        } else {
            pep_warn("Invalid queue_max_absolute: %u (valid: 1MB-64MB)\n", max_bytes);
            return -EINVAL;
        }
    } else {
        pep_warn("Unknown config key: %s\n", key);
        return -EINVAL;
    }

    return count;
}

/*
 * 功能/Main: 处理proc 控制接口（Handle proc control interface）
 * 细节/Details: proc 接口读写（/proc IO）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: inode, file
 * 影响/Effects: 提供 /proc 控制接口，影响运行时配置（provide /proc control interface, affects runtime config）
 * 重要程度/Importance: 低/Low
 */
static int pep_proc_config_open(struct inode *inode, struct file *file)
{
    return single_open(file, pep_proc_config_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops pep_proc_config_ops = {
    .proc_open    = pep_proc_config_open,
    .proc_read    = seq_read,
    .proc_write   = pep_proc_config_write,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations pep_proc_config_ops = {
    .owner   = THIS_MODULE,
    .open    = pep_proc_config_open,
    .read    = seq_read,
    .write   = pep_proc_config_write,
    .llseek  = seq_lseek,
    .release = single_release,
};
#endif

/*
 * 功能/Main: 处理proc 控制接口（Handle proc control interface）
 * 细节/Details: 学习控制/区域统计（learning/regional stats）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: m, v
 * 影响/Effects: 提供 /proc 控制接口，影响运行时配置（provide /proc control interface, affects runtime config）
 * 重要程度/Importance: 低/Low
 */
static int pep_proc_learning_show(struct seq_file *m, void *v)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);

    if (!ctx) {
        seq_puts(m, "PEP context not initialized\n");
        return 0;
    }

    if (!ctx->config.learning_enabled) {
        seq_puts(m, "Self-Learning CC is disabled\n");
        return 0;
    }

    pep_learning_export_stats(&ctx->learning, m);

    pep_learning_export_q_table(&ctx->learning, m);

    return 0;
}

/*
 * 功能/Main: 处理proc 控制接口（Handle proc control interface）
 * 细节/Details: 学习控制/区域统计（learning/regional stats）；proc 接口读写（/proc IO）
 * 输入/Inputs: 参数/Inputs: inode, file
 * 影响/Effects: 提供 /proc 控制接口，影响运行时配置（provide /proc control interface, affects runtime config）
 * 重要程度/Importance: 低/Low
 */
static int pep_proc_learning_open(struct inode *inode, struct file *file)
{
    return single_open(file, pep_proc_learning_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops pep_proc_learning_ops = {
    .proc_open    = pep_proc_learning_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations pep_proc_learning_ops = {
    .owner   = THIS_MODULE,
    .open    = pep_proc_learning_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};
#endif

/*
 * 功能/Main: PMTU/MSS 处理（Handle PMTU/MSS handling）
 * 细节/Details: frag/分片结构处理（frag list handling）；PMTU/MSS 更新（PMTU/MSS update）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: m, v
 * 影响/Effects: 提供 /proc 控制接口，影响运行时配置（provide /proc control interface, affects runtime config）
 * 重要程度/Importance: 中/Medium
 */
static int pep_proc_pmtu_show(struct seq_file *m, void *v)
{
    u64 lookups, hits, updates, icmp_sent, icmp_received;
    u64 hit_rate;
    struct pep_context *ctx = READ_ONCE(pep_ctx);

    pep_pmtu_get_stats(&lookups, &hits, &updates, &icmp_sent, &icmp_received);

    seq_puts(m, "======== PMTU Statistics ========\n");
    seq_printf(m, "Cache lookups:      %llu\n", lookups);
    seq_printf(m, "Cache hits:         %llu\n", hits);
    if (lookups > 0) {
        hit_rate = (hits * 100) / lookups;
        seq_printf(m, "Hit rate:           %llu%%\n", hit_rate);
    } else {
        seq_puts(m, "Hit rate:           N/A\n");
    }
    seq_printf(m, "Cache updates:      %llu\n", updates);
    seq_printf(m, "ICMP sent:          %llu (Frag Needed)\n", icmp_sent);
    seq_printf(m, "ICMP received:      %llu (Frag Needed)\n", icmp_received);
    if (ctx) {
        seq_printf(m, "Default PMTU:       %u\n", ctx->config.pmtu_default);
        seq_printf(m, "Timeout (ms):       %u\n", ctx->config.pmtu_timeout_ms);
    }

    return 0;
}

/*
 * 功能/Main: PMTU/MSS 处理（Handle PMTU/MSS handling）
 * 细节/Details: PMTU/MSS 更新（PMTU/MSS update）；proc 接口读写（/proc IO）
 * 输入/Inputs: 参数/Inputs: inode, file
 * 影响/Effects: 提供 /proc 控制接口，影响运行时配置（provide /proc control interface, affects runtime config）
 * 重要程度/Importance: 中/Medium
 */
static int pep_proc_pmtu_open(struct inode *inode, struct file *file)
{
    return single_open(file, pep_proc_pmtu_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops pep_proc_pmtu_ops = {
    .proc_open    = pep_proc_pmtu_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations pep_proc_pmtu_ops = {
    .owner   = THIS_MODULE,
    .open    = pep_proc_pmtu_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};
#endif

/*
 * 功能/Main: 初始化proc 控制接口（Initialize proc control interface）
 * 细节/Details: PMTU/MSS 更新（PMTU/MSS update）；学习控制/区域统计（learning/regional stats）；proc 接口读写（/proc IO）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: ctx
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
int pep_proc_init(struct pep_context *ctx)
{
    struct proc_dir_entry *entry;

    if (!ctx)
        return -EINVAL;

    ctx->proc_root = proc_mkdir(PEP_PROC_ROOT, NULL);
    if (!ctx->proc_root) {
        pep_err("Failed to create /proc/%s\n", PEP_PROC_ROOT);
        return -ENOMEM;
    }

    entry = proc_create("stats", 0444, ctx->proc_root, &pep_proc_stats_ops);
    if (!entry) {
        pep_err("Failed to create /proc/%s/stats\n", PEP_PROC_ROOT);
        goto err_stats;
    }

    entry = proc_create("flows", 0444, ctx->proc_root, &pep_proc_flows_ops);
    if (!entry) {
        pep_err("Failed to create /proc/%s/flows\n", PEP_PROC_ROOT);
        goto err_flows;
    }

    entry = proc_create("config", 0644, ctx->proc_root, &pep_proc_config_ops);
    if (!entry) {
        pep_err("Failed to create /proc/%s/config\n", PEP_PROC_ROOT);
        goto err_config;
    }

    if (ctx->config.learning_enabled) {
        entry = proc_create("learning", 0444, ctx->proc_root, &pep_proc_learning_ops);
        if (!entry) {
            pep_err("Failed to create /proc/%s/learning\n", PEP_PROC_ROOT);
            goto err_learning;
        }
    }

    if (ctx->config.pmtu_enabled) {
        entry = proc_create("pmtu", 0444, ctx->proc_root, &pep_proc_pmtu_ops);
        if (!entry) {
            pep_err("Failed to create /proc/%s/pmtu\n", PEP_PROC_ROOT);
            goto err_pmtu;
        }
    }

    pep_info("procfs interface initialized at /proc/%s\n", PEP_PROC_ROOT);

    return 0;

err_pmtu:
    if (ctx->config.learning_enabled)
        remove_proc_entry("learning", ctx->proc_root);
err_learning:
    remove_proc_entry("config", ctx->proc_root);
err_config:
    remove_proc_entry("flows", ctx->proc_root);
err_flows:
    remove_proc_entry("stats", ctx->proc_root);
err_stats:
    proc_remove(ctx->proc_root);
    ctx->proc_root = NULL;
    return -ENOMEM;
}

/*
 * 功能/Main: 清理proc 控制接口（Cleanup proc control interface）
 * 细节/Details: PMTU/MSS 更新（PMTU/MSS update）；学习控制/区域统计（learning/regional stats）；proc 接口读写（/proc IO）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: ctx
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_proc_exit(struct pep_context *ctx)
{
    if (!ctx || !ctx->proc_root)
        return;

    if (ctx->config.pmtu_enabled)
        remove_proc_entry("pmtu", ctx->proc_root);
    if (ctx->config.learning_enabled)
        remove_proc_entry("learning", ctx->proc_root);
    remove_proc_entry("config", ctx->proc_root);
    remove_proc_entry("flows", ctx->proc_root);
    remove_proc_entry("stats", ctx->proc_root);
    proc_remove(ctx->proc_root);
    ctx->proc_root = NULL;

    pep_info("procfs interface removed\n");
}
