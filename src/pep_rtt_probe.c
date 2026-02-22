/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"

extern struct pep_context *pep_ctx;

/*
 * 功能/Main: 探测pep_create_wan_keepalive_probe相关逻辑（Probe pep_create_wan_keepalive_probe logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；frag/分片结构处理（frag list handling）；访问/维护流状态（flow state access/maintenance）；并发同步（spinlock/atomic/rcu）；校验和处理（checksum adjust）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, seq
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 中/Medium
 */
static struct sk_buff *pep_create_wan_keepalive_probe(struct pep_flow *flow, u32 seq)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len = sizeof(struct iphdr);
    unsigned int tcp_hdr_len = sizeof(struct tcphdr);
    unsigned int total_len;
    unsigned int headroom;
    u8 probe_byte = 0;

    if (!flow)
        return NULL;

    headroom = LL_MAX_HEADER + ip_hdr_len;
    total_len = ip_hdr_len + tcp_hdr_len + 1;

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
    tcph->window = htons(65535);

    skb_put_data(skb, &probe_byte, 1);

    pep_update_ip_checksum(iph);
    {
        bool hw_offload = pep_ctx && pep_ctx->config.tx_csum_enabled;

        pep_fast_tcp_checksum(skb, iph, tcph, hw_offload);
    }

    skb->protocol = htons(ETH_P_IP);
    skb->mark = PEP_SKB_MARK;
    skb->priority = 0;

    return skb;
}

/*
 * 功能/Main: RTT 探测/估计（Probe RTT probing/estimation）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；RTT/RTO 估计（RTT/RTO estimation）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, ack_seq
 * 影响/Effects: 更新 RTT 策略，影响超时与 pacing（update RTT policy, affects timeout/pacing）
 * 重要程度/Importance: 中/Medium
 */
void pep_rtt_probe_on_ack(struct pep_flow *flow, u32 ack_seq)
{
    ktime_t now;
    s64 rtt_us;

    if (!flow || !flow->rtt_probe_pending)
        return;

    if (ack_seq != flow->rtt_probe_ack_seq)
        return;

    now = ktime_get();
    rtt_us = ktime_to_us(ktime_sub(now, flow->rtt_probe_sent_time));
    if (rtt_us > 0 && rtt_us < 30000000LL) {
        pep_rtt_update(&flow->rtt, (u32)rtt_us);
        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
            pr_info("pep: RTT probe sample=%lld us (ack=%u)\n",
                    rtt_us, ack_seq);
        }
    }

    flow->rtt_probe_pending = 0;
}

/*
 * 功能/Main: 发送RTT 探测/估计（Send RTT probing/estimation）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；带宽整形/速率限制（shaping/rate limit）；RTT/RTO 估计（RTT/RTO estimation）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 向网络栈/设备发送数据，影响链路时延与吞吐（send into stack/device, affects latency/throughput）
 * 重要程度/Importance: 高/High
 */
void pep_rtt_probe_maybe_send(struct pep_flow *flow)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);
    ktime_t now;
    s64 idle_ms;
    s64 since_sample_ms;
    s64 since_probe_ms;
    struct sk_buff *skb;
    u32 probe_seq;

    if (!flow || !ctx)
        return;

    if (!ctx->config.rtt_probe_enabled || !flow->rtt_probe_enabled)
        return;

    if (flow->wan_state != PEP_WAN_ESTABLISHED)
        return;

    if (flow->rtt_probe_pending) {
        now = ktime_get();
        since_probe_ms = ktime_to_ms(ktime_sub(now, flow->rtt_probe_sent_time));
        if (since_probe_ms > (s64)ctx->config.rtt_probe_interval_ms * 2)
            flow->rtt_probe_pending = 0;
        return;
    }

    now = ktime_get();
    idle_ms = ktime_to_ms(ktime_sub(now, flow->last_activity));
    if (ctx->config.rtt_probe_idle_ms > 0 &&
        idle_ms < (s64)ctx->config.rtt_probe_idle_ms)
        return;

    since_sample_ms = ktime_to_ms(ktime_sub(now, flow->rtt.last_sample));
    if (flow->rtt.samples > 0 &&
        since_sample_ms < (s64)ctx->config.rtt_probe_interval_ms)
        return;

    if (ktime_to_ns(flow->rtt_probe_last_time) != 0) {
        since_probe_ms = ktime_to_ms(ktime_sub(now, flow->rtt_probe_last_time));
        if (since_probe_ms < (s64)ctx->config.rtt_probe_interval_ms)
            return;
    }

    if (flow->cc.bytes_in_flight > 0)
        return;

    if (flow->wan_snd_nxt == 0)
        return;

    probe_seq = flow->wan_snd_nxt - 1;
    skb = pep_create_wan_keepalive_probe(flow, probe_seq);
    if (!skb)
        return;

    if (pep_shaper_allow(&ctx->shaper_lan_wan, skb->len)) {
        if (pep_send_wan_skb(skb) == 0) {
            pep_shaper_consume(&ctx->shaper_lan_wan, skb->len);
            flow->rtt_probe_pending = 1;
            flow->rtt_probe_ack_seq = flow->wan_snd_nxt;
            flow->rtt_probe_sent_time = now;
            flow->rtt_probe_last_time = now;
        }
    } else {
        kfree_skb(skb);
    }
}
