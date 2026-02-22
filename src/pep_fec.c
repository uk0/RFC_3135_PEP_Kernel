    /* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"

extern struct pep_context *pep_ctx;

/*
 * 功能/Main: 分配FEC 编码/恢复（Allocate FEC encode/recovery）
 * 细节/Details: FEC 编码/映射/恢复（FEC encode/map/recover）
 * 输入/Inputs: 参数/Inputs: encoder
 * 影响/Effects: 更新 FEC 策略，影响丢包恢复（update FEC policy, affects loss recovery）
 * 重要程度/Importance: 中/Medium
 */
static int pep_fec_encoder_alloc(struct pep_fec_encoder *encoder)
{
    if (!encoder)
        return -EINVAL;

    encoder->fec_buffer = kzalloc(PEP_FEC_MAX_BLOCK_SIZE, GFP_ATOMIC);
    if (!encoder->fec_buffer)
        return -ENOMEM;

    encoder->fec_buffer_len = PEP_FEC_MAX_BLOCK_SIZE;
    return 0;
}

/*
 * 功能/Main: 释放FEC 编码/恢复（Free FEC encode/recovery）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；FEC 编码/映射/恢复（FEC encode/map/recover）
 * 输入/Inputs: 参数/Inputs: encoder
 * 影响/Effects: 更新 FEC 策略，影响丢包恢复（update FEC policy, affects loss recovery）
 * 重要程度/Importance: 中/Medium
 */
static void pep_fec_encoder_free(struct pep_fec_encoder *encoder)
{
    int i;

    if (!encoder)
        return;

    kfree(encoder->fec_buffer);
    encoder->fec_buffer = NULL;

    for (i = 0; i < PEP_FEC_MAX_K; i++) {
        if (encoder->data_pkts[i]) {
            kfree_skb(encoder->data_pkts[i]);
            encoder->data_pkts[i] = NULL;
        }
    }
}

/*
 * 功能/Main: 分配FEC 编码/恢复（Allocate FEC encode/recovery）
 * 细节/Details: FEC 编码/映射/恢复（FEC encode/map/recover）
 * 输入/Inputs: 参数/Inputs: decoder
 * 影响/Effects: 更新 FEC 策略，影响丢包恢复（update FEC policy, affects loss recovery）
 * 重要程度/Importance: 中/Medium
 */
static int pep_fec_decoder_alloc(struct pep_fec_decoder *decoder)
{
    if (!decoder)
        return -EINVAL;

    decoder->recover_buffer = kzalloc(PEP_FEC_MAX_BLOCK_SIZE, GFP_ATOMIC);
    if (!decoder->recover_buffer)
        return -ENOMEM;

    return 0;
}

/*
 * 功能/Main: 释放FEC 编码/恢复（Free FEC encode/recovery）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；FEC 编码/映射/恢复（FEC encode/map/recover）
 * 输入/Inputs: 参数/Inputs: decoder
 * 影响/Effects: 更新 FEC 策略，影响丢包恢复（update FEC policy, affects loss recovery）
 * 重要程度/Importance: 中/Medium
 */
static void pep_fec_decoder_free(struct pep_fec_decoder *decoder)
{
    int i;

    if (!decoder)
        return;

    kfree(decoder->recover_buffer);
    decoder->recover_buffer = NULL;

    for (i = 0; i < PEP_FEC_MAX_K + 1; i++) {
        if (decoder->received_pkts[i]) {
            kfree_skb(decoder->received_pkts[i]);
            decoder->received_pkts[i] = NULL;
        }
    }
}

/*
 * 功能/Main: 初始化FEC 编码/恢复（Initialize FEC encode/recovery）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；FEC 编码/映射/恢复（FEC encode/map/recover）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
int pep_fec_init(struct pep_flow *flow)
{
    struct pep_fec_state *fec;
    int ret;

    if (!flow)
        return -EINVAL;

    fec = &flow->fec;
    memset(fec, 0, sizeof(*fec));

    if (!pep_ctx || !pep_ctx->config.fec_enabled) {
        fec->enabled = false;
        return 0;
    }

    {
        u32 cfg_k = pep_ctx->config.fec_k;
        u32 cfg_n = pep_ctx->config.fec_n;

        if (cfg_k == 0 || cfg_k > PEP_FEC_MAX_K)
            cfg_k = PEP_FEC_DEFAULT_K;
        if (cfg_n == 0 || cfg_n < cfg_k + 1)
            cfg_n = cfg_k + 1;
        if (cfg_n > PEP_FEC_MAX_K + 1)
            cfg_n = PEP_FEC_MAX_K + 1;

        fec->encoder.k = cfg_k;
        fec->encoder.n = cfg_n;
        fec->decoder.k = cfg_k;
        fec->decoder.n = cfg_n;
    }
    fec->encoder.block_id = 0;
    fec->encoder.pkt_count = 0;

    ret = pep_fec_encoder_alloc(&fec->encoder);
    if (ret < 0) {
        pep_warn("FEC: Failed to allocate encoder buffer\n");
        return ret;
    }

    fec->decoder.block_id = 0;
    fec->decoder.received_count = 0;
    fec->decoder.received_mask = 0;
    fec->decoder.fec_payload_len = 0;
    fec->decoder.has_fec = false;

    ret = pep_fec_decoder_alloc(&fec->decoder);
    if (ret < 0) {
        pep_warn("FEC: Failed to allocate decoder buffer\n");
        pep_fec_encoder_free(&fec->encoder);
        return ret;
    }

    fec->loss_rate_ppm = 0;
    fec->target_recovery_rate = 99;
    fec->last_adjust_time = ktime_get();

    fec->enabled = true;

    set_bit(PEP_FLOW_F_FEC_ENABLED_BIT, &flow->flags);

    pep_dbg("FEC: Initialized for flow, K=%u N=%u\n",
            fec->encoder.k, fec->encoder.n);

    return 0;
}

/*
 * 功能/Main: 清理FEC 编码/恢复（Cleanup FEC encode/recovery）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；FEC 编码/映射/恢复（FEC encode/map/recover）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_fec_cleanup(struct pep_flow *flow)
{
    struct pep_fec_state *fec;

    if (!flow)
        return;

    fec = &flow->fec;

    if (!fec->enabled)
        return;

    pep_fec_encoder_free(&fec->encoder);
    pep_fec_decoder_free(&fec->decoder);

    fec->enabled = false;

    clear_bit(PEP_FLOW_F_FEC_ENABLED_BIT, &flow->flags);

    pep_dbg("FEC: Cleaned up for flow, encoded=%llu recovered=%llu\n",
            fec->encoder.blocks_encoded, fec->decoder.pkts_recovered);
}

/*
 * 功能/Main: 处理FEC 编码/恢复（Handle FEC encode/recovery）
 * 细节/Details: FEC 编码/映射/恢复（FEC encode/map/recover）
 * 输入/Inputs: 参数/Inputs: encoder, data, len
 * 影响/Effects: 更新 FEC 策略，影响丢包恢复（update FEC policy, affects loss recovery）
 * 重要程度/Importance: 中/Medium
 */
static void pep_fec_xor_into_buffer(struct pep_fec_encoder *encoder,
                                     const void *data, u32 len)
{
    u32 i;
    u8 *fec_buf = encoder->fec_buffer;
    const u8 *src = data;

    if (len > encoder->fec_buffer_len) {

        encoder->fec_buffer_len = min_t(u32, len, PEP_FEC_MAX_BLOCK_SIZE);
    }

    for (i = 0; i < len && i < PEP_FEC_MAX_BLOCK_SIZE; i++) {
        fec_buf[i] ^= src[i];
    }
}

static bool pep_fec_header_valid(const struct pep_fec_header *fec_hdr, u32 payload_len)
{
    u32 original_len;

    if (!fec_hdr)
        return false;

    if (payload_len < PEP_FEC_HEADER_SIZE)
        return false;

    if (ntohl(fec_hdr->magic) != PEP_FEC_MAGIC)
        return false;

    if (fec_hdr->version != PEP_FEC_VERSION)
        return false;

    if (fec_hdr->type != PEP_FEC_PKT_FEC)
        return false;

    if (fec_hdr->k == 0 || fec_hdr->k > PEP_FEC_MAX_K)
        return false;

    if (fec_hdr->n < fec_hdr->k + 1 || fec_hdr->n > PEP_FEC_MAX_K + 1)
        return false;

    if (fec_hdr->pkt_idx != fec_hdr->k)
        return false;

    original_len = ntohl(fec_hdr->original_len);
    if (original_len == 0 || original_len > PEP_FEC_MAX_BLOCK_SIZE)
        return false;

    if (original_len > payload_len - PEP_FEC_HEADER_SIZE)
        return false;

    return true;
}

/*
 * 功能/Main: 处理FEC 编码/恢复（Handle FEC encode/recovery）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；访问/维护流状态（flow state access/maintenance）；FEC 编码/映射/恢复（FEC encode/map/recover）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow, skb, seq, len
 * 影响/Effects: 更新 FEC 策略，影响丢包恢复（update FEC policy, affects loss recovery）
 * 重要程度/Importance: 中/Medium
 */
int pep_fec_encoder_add_packet(struct pep_flow *flow, struct sk_buff *skb,
                                u32 seq, u32 len)
{
    struct pep_fec_state *fec;
    struct pep_fec_encoder *enc;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len, tcp_hdr_len;
    unsigned char *payload;
    u32 payload_len;

    if (!flow || !skb)
        return -EINVAL;

    fec = &flow->fec;
    if (!fec->enabled)
        return 0;

    enc = &fec->encoder;

    if (skb_linearize(skb))
        return -ENOMEM;

    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
    tcp_hdr_len = tcph->doff * 4;
    payload = (unsigned char *)tcph + tcp_hdr_len;
    if (ntohs(iph->tot_len) < ip_hdr_len + tcp_hdr_len)
        return 0;

    payload_len = ntohs(iph->tot_len) - ip_hdr_len - tcp_hdr_len;

    if (tcph->syn || tcph->fin || tcph->rst)
        return 0;

    if (payload_len == 0)
        return 0;

    if (payload_len > PEP_FEC_MAX_BLOCK_SIZE)
        payload_len = PEP_FEC_MAX_BLOCK_SIZE;

    if (enc->pkt_count == 0) {
        enc->block_seq_base = seq;
        memset(enc->fec_buffer, 0, PEP_FEC_MAX_BLOCK_SIZE);
        enc->fec_buffer_len = 0;
    }

    if (enc->pkt_count < PEP_FEC_MAX_K) {
        /*
         * v63 关键修复: 检查 skb_clone() 返回值
         *
         * 问题: skb_clone() 可能因内存不足返回 NULL
         *       但 data_lens 仍被设置，导致 pep_fec_encoder_generate()
         *       访问 NULL 指针崩溃
         *
         * 解决: 只有克隆成功时才设置 data_lens
         */
        struct sk_buff *cloned = skb_clone(skb, GFP_ATOMIC);
        if (cloned) {
            enc->data_pkts[enc->pkt_count] = cloned;
            enc->data_lens[enc->pkt_count] = payload_len;
        } else {
            /* 克隆失败，标记此槽位为空 */
            enc->data_pkts[enc->pkt_count] = NULL;
            enc->data_lens[enc->pkt_count] = 0;
            pep_warn("FEC: skb_clone failed for packet %u in block %u\n",
                     enc->pkt_count, enc->block_id);
        }
    }

    pep_fec_xor_into_buffer(enc, payload, payload_len);

    enc->pkt_count++;

    if (enc->pkt_count >= enc->k) {
        return 1;
    }

    return 0;
}

/*
 * 功能/Main: 处理FEC 编码/恢复（Handle FEC encode/recovery）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；frag/分片结构处理（frag list handling）；访问/维护流状态（flow state access/maintenance）；FEC 编码/映射/恢复（FEC encode/map/recover）；并发同步（spinlock/atomic/rcu）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新 FEC 策略，影响丢包恢复（update FEC policy, affects loss recovery）
 * 重要程度/Importance: 中/Medium
 */
struct sk_buff *pep_fec_encoder_generate(struct pep_flow *flow)
{
    struct pep_fec_state *fec;
    struct pep_fec_encoder *enc;
    struct sk_buff *fec_skb;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct pep_fec_header *fec_hdr;
    unsigned int ip_hdr_len = sizeof(struct iphdr);
    unsigned int tcp_hdr_len = sizeof(struct tcphdr);
    unsigned int fec_hdr_len = sizeof(struct pep_fec_header);
    unsigned int total_len;
    unsigned int headroom;
    u32 max_payload_len = 0;
    int i;

    if (!flow)
        return NULL;

    fec = &flow->fec;
    if (!fec->enabled)
        return NULL;

    enc = &fec->encoder;

    if (enc->pkt_count < enc->k)
        return NULL;

    for (i = 0; i < enc->k && i < PEP_FEC_MAX_K; i++) {
        if (enc->data_lens[i] > max_payload_len)
            max_payload_len = enc->data_lens[i];
    }

    if (max_payload_len == 0)
        return NULL;

    if (max_payload_len > PEP_FEC_MAX_BLOCK_SIZE)
        max_payload_len = PEP_FEC_MAX_BLOCK_SIZE;

    /*
     * v73: 确保 FEC 包不超过 MTU
     *
     * FEC 包结构: IP(20) + TCP(20) + FEC_header(16) + payload
     * 必须确保总大小 <= MTU (通常 1500)
     *
     * max_payload = MTU - ip_hdr_len - tcp_hdr_len - fec_hdr_len
     *             = 1500 - 20 - 20 - 16 = 1444 字节
     */
    {
        unsigned int mtu = 1500;
        unsigned int max_fec_payload;

        if (pep_ctx && pep_ctx->wan_dev)
            mtu = pep_ctx->wan_dev->mtu;

        max_fec_payload = mtu - ip_hdr_len - tcp_hdr_len - fec_hdr_len;
        if (max_payload_len > max_fec_payload)
            max_payload_len = max_fec_payload;
    }

    headroom = LL_MAX_HEADER + ip_hdr_len;
    total_len = ip_hdr_len + tcp_hdr_len + fec_hdr_len + max_payload_len;

    fec_skb = alloc_skb(headroom + total_len, GFP_ATOMIC);
    if (!fec_skb)
        return NULL;

    skb_reserve(fec_skb, headroom);
    skb_reset_network_header(fec_skb);

    iph = skb_put(fec_skb, ip_hdr_len);
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

    skb_set_transport_header(fec_skb, ip_hdr_len);
    tcph = skb_put(fec_skb, tcp_hdr_len);
    memset(tcph, 0, tcp_hdr_len);
    tcph->source = flow->tuple.src_port;
    tcph->dest = flow->tuple.dst_port;
    tcph->seq = htonl(enc->block_seq_base);
    tcph->ack_seq = htonl(flow->wan.seq_next);
    tcph->doff = tcp_hdr_len / 4;
    tcph->ack = 1;
    tcph->window = htons(65535);

    if (pep_ctx && pep_ctx->config.ecn_enabled &&
        test_bit(PEP_FLOW_F_ECN_BIT, &flow->flags) &&
        flow->cc.ecn_enabled) {
        iph->tos = (iph->tos & ~PEP_ECN_MASK) | PEP_ECN_ECT0;
        if (flow->cc.ecn_state == PEP_ECN_STATE_CWR)
            tcph->cwr = 1;
    }

    fec_hdr = skb_put(fec_skb, fec_hdr_len);
    fec_hdr->magic = htonl(PEP_FEC_MAGIC);
    fec_hdr->version = PEP_FEC_VERSION;
    fec_hdr->type = PEP_FEC_PKT_FEC;
    fec_hdr->block_id = enc->block_id;
    fec_hdr->pkt_idx = enc->k;
    fec_hdr->k = enc->k;
    fec_hdr->n = enc->n;
    fec_hdr->original_len = htonl(max_payload_len);

    skb_put_data(fec_skb, enc->fec_buffer, max_payload_len);

    pep_update_ip_checksum(iph);
    {
        bool hw_offload = pep_ctx && pep_ctx->config.tx_csum_enabled;

        pep_fast_tcp_checksum(fec_skb, iph, tcph, hw_offload);
    }

    fec_skb->protocol = htons(ETH_P_IP);
    fec_skb->mark = PEP_SKB_MARK;
    fec_skb->priority = 0;

    enc->blocks_encoded++;
    enc->fec_pkts_sent++;

    for (i = 0; i < PEP_FEC_MAX_K; i++) {
        if (enc->data_pkts[i]) {
            kfree_skb(enc->data_pkts[i]);
            enc->data_pkts[i] = NULL;
        }
        enc->data_lens[i] = 0;
    }
    enc->block_id++;
    enc->pkt_count = 0;
    memset(enc->fec_buffer, 0, PEP_FEC_MAX_BLOCK_SIZE);

    pep_dbg("FEC: Generated FEC packet for block %u (K=%u, payload=%u)\n",
            enc->block_id - 1, enc->k, max_payload_len);

    return fec_skb;
}

/*
 * 功能/Main: 处理FEC 编码/恢复（Handle FEC encode/recovery）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；FEC 编码/映射/恢复（FEC encode/map/recover）；PMTU/MSS 更新（PMTU/MSS update）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, seq, len, out_block_id, out_pkt_idx
 * 影响/Effects: 更新 FEC 策略，影响丢包恢复（update FEC policy, affects loss recovery）
 * 重要程度/Importance: 中/Medium
 */
static int pep_fec_map_seq_to_block(struct pep_flow *flow, u32 seq, u32 len,
                                     u8 *out_block_id, u8 *out_pkt_idx)
{
    struct pep_fec_decoder *dec;
    u32 relative_seq;
    u32 block_size;
    u32 block_offset;
    u8 block_id;
    u8 pkt_idx;

    if (!flow || !out_block_id || !out_pkt_idx)
        return -EINVAL;

    dec = &flow->fec.decoder;

    u32 mss = flow->mss ? flow->mss : 1460;

    block_size = dec->k * mss;

    if (dec->block_seq_base == 0) {

        dec->block_seq_base = seq;
        dec->block_id = 0;
        relative_seq = 0;
    } else {

        relative_seq = seq - dec->block_seq_base;
    }

    block_id = relative_seq / block_size;

    block_offset = relative_seq % block_size;

    pkt_idx = block_offset / mss;

    if (pkt_idx >= dec->k) {
        if (pep_ctx && pep_ctx->config.debug_level >= 3) {
            pr_info_ratelimited("pep: FEC seq_map: invalid pkt_idx=%u (>= k=%u) for seq=%u\n",
                                pkt_idx, dec->k, seq);
        }
        return -EINVAL;
    }

    if (block_id != dec->block_id && block_id == dec->block_id + 1) {

        dec->block_id = block_id;
        dec->received_count = 0;
        dec->received_mask = 0;
        dec->has_fec = false;
        dec->block_seq_base += block_size;

        int i;
        for (i = 0; i < PEP_FEC_MAX_K + 1; i++) {
            if (dec->received_pkts[i]) {
                kfree_skb(dec->received_pkts[i]);
                dec->received_pkts[i] = NULL;
            }
        }
    }

    *out_block_id = block_id & 0xFF;
    *out_pkt_idx = pkt_idx;

    if (pep_ctx && pep_ctx->config.debug_level >= 3) {
        pr_info_ratelimited("pep: FEC seq_map: seq=%u -> block=%u, pkt=%u (base=%u, mss=%u)\n",
                            seq, block_id, pkt_idx, dec->block_seq_base, mss);
    }

    return 0;
}

/*
 * 功能/Main: 处理FEC 编码/恢复（Process FEC encode/recovery）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；访问/维护流状态（flow state access/maintenance）；FEC 编码/映射/恢复（FEC encode/map/recover）
 * 输入/Inputs: 参数/Inputs: flow, skb, seq
 * 影响/Effects: 更新 FEC 策略，影响丢包恢复（update FEC policy, affects loss recovery）
 * 重要程度/Importance: 高/High
 */
int pep_fec_process_data_packet(struct pep_flow *flow, struct sk_buff *skb, u32 seq)
{
    u8 block_id, pkt_idx;
    int ret;

    if (!flow || !skb)
        return -EINVAL;

    if (!flow->fec.enabled)
        return 0;

    ret = pep_fec_map_seq_to_block(flow, seq, skb->len, &block_id, &pkt_idx);
    if (ret < 0)
        return ret;

    return pep_fec_decoder_add_packet(flow, skb, block_id, pkt_idx, false);
}

/*
 * 功能/Main: 处理FEC 编码/恢复（Handle FEC encode/recovery）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；FEC 编码/映射/恢复（FEC encode/map/recover）
 * 输入/Inputs: 参数/Inputs: skb
 * 影响/Effects: 更新 FEC 策略，影响丢包恢复（update FEC policy, affects loss recovery）
 * 重要程度/Importance: 中/Medium
 */
bool pep_fec_is_fec_packet(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct pep_fec_header *fec_hdr;
    unsigned int ip_hdr_len, tcp_hdr_len;
    unsigned int payload_len;

    if (!skb)
        return false;

    if (skb_linearize(skb))
        return false;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return false;
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
    tcp_hdr_len = tcph->doff * 4;
    payload_len = ntohs(iph->tot_len) - ip_hdr_len - tcp_hdr_len;

    if (payload_len < PEP_FEC_HEADER_SIZE)
        return false;

    fec_hdr = (struct pep_fec_header *)((unsigned char *)tcph + tcp_hdr_len);

    return pep_fec_header_valid(fec_hdr, payload_len);
}

/*
 * 功能/Main: 处理FEC 编码/恢复（Handle FEC encode/recovery）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；访问/维护流状态（flow state access/maintenance）；FEC 编码/映射/恢复（FEC encode/map/recover）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow, skb, block_id, pkt_idx, is_fec
 * 影响/Effects: 更新 FEC 策略，影响丢包恢复（update FEC policy, affects loss recovery）
 * 重要程度/Importance: 中/Medium
 */
int pep_fec_decoder_add_packet(struct pep_flow *flow, struct sk_buff *skb,
                                u8 block_id, u8 pkt_idx, bool is_fec)
{
    struct pep_fec_state *fec;
    struct pep_fec_decoder *dec;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct pep_fec_header *fec_hdr;
    unsigned int ip_hdr_len, tcp_hdr_len;
    u32 payload_len;
    bool had_fec;

    if (!flow || !skb)
        return -EINVAL;

    fec = &flow->fec;
    if (!fec->enabled)
        return 0;

    dec = &fec->decoder;

    if (block_id != dec->block_id) {

        int i;
        for (i = 0; i < PEP_FEC_MAX_K + 1; i++) {
            if (dec->received_pkts[i]) {
                kfree_skb(dec->received_pkts[i]);
                dec->received_pkts[i] = NULL;
            }
        }
        dec->block_id = block_id;
        dec->received_count = 0;
        dec->received_mask = 0;
        dec->fec_payload_len = 0;
        dec->has_fec = false;
    }

    if (is_fec) {
        if (skb_linearize(skb))
            return -ENOMEM;

        iph = ip_hdr(skb);
        ip_hdr_len = iph->ihl * 4;
        tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
        tcp_hdr_len = tcph->doff * 4;
        if (ntohs(iph->tot_len) < ip_hdr_len + tcp_hdr_len + PEP_FEC_HEADER_SIZE)
            return -EINVAL;

        payload_len = ntohs(iph->tot_len) - ip_hdr_len - tcp_hdr_len;

        fec_hdr = (struct pep_fec_header *)((unsigned char *)tcph + tcp_hdr_len);
        if (!pep_fec_header_valid(fec_hdr, payload_len))
            return -EINVAL;
        if (fec_hdr->k > 0 && fec_hdr->k <= PEP_FEC_MAX_K)
            dec->k = fec_hdr->k;
        if (fec_hdr->n >= dec->k + 1 && fec_hdr->n <= PEP_FEC_MAX_K + 1)
            dec->n = fec_hdr->n;

        payload_len -= PEP_FEC_HEADER_SIZE;
        if (payload_len > PEP_FEC_MAX_BLOCK_SIZE)
            payload_len = PEP_FEC_MAX_BLOCK_SIZE;
        dec->fec_payload_len = min_t(u32, ntohl(fec_hdr->original_len), payload_len);

        if (dec->block_seq_base == 0)
            dec->block_seq_base = ntohl(tcph->seq);
    }

    had_fec = dec->has_fec;

    if (pkt_idx < PEP_FEC_MAX_K + 1) {
        if (dec->received_pkts[pkt_idx]) {
            kfree_skb(dec->received_pkts[pkt_idx]);
        }
        dec->received_pkts[pkt_idx] = skb_clone(skb, GFP_ATOMIC);
        if (dec->received_pkts[pkt_idx]) {
            if (pkt_idx < 64) {
                u64 bit = 1ULL << pkt_idx;
                if (!(dec->received_mask & bit)) {
                    dec->received_count++;
                    dec->received_mask |= bit;
                }
            } else if (is_fec && !had_fec) {
                dec->received_count++;
            }
        }
    }

    if (is_fec) {
        dec->has_fec = true;
    }

    if (dec->has_fec && dec->received_count >= dec->k) {
        return 1;
    }

    return 0;
}

/*
 * 功能/Main: 处理FEC 编码/恢复（Handle FEC encode/recovery）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；访问/维护流状态（flow state access/maintenance）；FEC 编码/映射/恢复（FEC encode/map/recover）；PMTU/MSS 更新（PMTU/MSS update）；并发同步（spinlock/atomic/rcu）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新 FEC 策略，影响丢包恢复（update FEC policy, affects loss recovery）
 * 重要程度/Importance: 中/Medium
 */
struct sk_buff *pep_fec_decoder_try_recover(struct pep_flow *flow)
{
    struct pep_fec_state *fec;
    struct pep_fec_decoder *dec;
    struct sk_buff *recovered_skb = NULL;
    struct sk_buff *template_skb = NULL;
    struct iphdr *iph, *new_iph;
    struct tcphdr *tcph, *new_tcph;
    unsigned int ip_hdr_len, tcp_hdr_len;
    int missing_idx = -1;
    int i;
    u32 max_len = 0;
    u32 payload_len;
    u32 mss;
    u32 missing_seq;

    if (!flow)
        return NULL;

    fec = &flow->fec;
    if (!fec->enabled)
        return NULL;

    dec = &fec->decoder;

    if (!dec->has_fec)
        return NULL;

    for (i = 0; i < dec->k; i++) {
        if (!(dec->received_mask & (1ULL << i))) {
            if (missing_idx >= 0) {

                dec->unrecoverable++;
                return NULL;
            }
            missing_idx = i;
        }
    }

    if (missing_idx < 0) {

        return NULL;
    }

    memset(dec->recover_buffer, 0, PEP_FEC_MAX_BLOCK_SIZE);

    for (i = 0; i < dec->k + 1; i++) {
        if (dec->received_pkts[i] && i != missing_idx) {

            if (skb_linearize(dec->received_pkts[i]))
                return NULL;

            iph = ip_hdr(dec->received_pkts[i]);
            ip_hdr_len = iph->ihl * 4;
            tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
            tcp_hdr_len = tcph->doff * 4;
            unsigned char *payload;

            if (i == dec->k) {

                if (ntohs(iph->tot_len) < ip_hdr_len + tcp_hdr_len + PEP_FEC_HEADER_SIZE)
                    return NULL;
                payload = (unsigned char *)tcph + tcp_hdr_len + PEP_FEC_HEADER_SIZE;
                payload_len = ntohs(iph->tot_len) - ip_hdr_len - tcp_hdr_len - PEP_FEC_HEADER_SIZE;
            } else {
                if (ntohs(iph->tot_len) < ip_hdr_len + tcp_hdr_len)
                    return NULL;
                payload = (unsigned char *)tcph + tcp_hdr_len;
                payload_len = ntohs(iph->tot_len) - ip_hdr_len - tcp_hdr_len;
            }

            if (payload_len > PEP_FEC_MAX_BLOCK_SIZE)
                payload_len = PEP_FEC_MAX_BLOCK_SIZE;

            for (u32 j = 0; j < payload_len && j < PEP_FEC_MAX_BLOCK_SIZE; j++) {
                dec->recover_buffer[j] ^= payload[j];
            }

            if (payload_len > max_len)
                max_len = payload_len;

            if (!template_skb && i < dec->k)
                template_skb = dec->received_pkts[i];
        }
    }

    if (max_len == 0 || !template_skb)
        return NULL;

    payload_len = dec->fec_payload_len ? dec->fec_payload_len : max_len;
    if (payload_len > PEP_FEC_MAX_BLOCK_SIZE)
        payload_len = PEP_FEC_MAX_BLOCK_SIZE;
    if (payload_len == 0)
        return NULL;

    if (dec->block_seq_base == 0)
        return NULL;

    if (skb_linearize(template_skb))
        return NULL;

    iph = ip_hdr(template_skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
    tcp_hdr_len = tcph->doff * 4;

    mss = flow->mss ? flow->mss : 1460;
    missing_seq = dec->block_seq_base + (u32)missing_idx * mss;

    recovered_skb = alloc_skb(LL_MAX_HEADER + ip_hdr_len +
                               tcp_hdr_len + payload_len, GFP_ATOMIC);
    if (!recovered_skb)
        return NULL;

    skb_reserve(recovered_skb, LL_MAX_HEADER);
    skb_reset_network_header(recovered_skb);

    new_iph = (struct iphdr *)skb_put(recovered_skb, ip_hdr_len);
    memcpy(new_iph, iph, ip_hdr_len);

    skb_set_transport_header(recovered_skb, ip_hdr_len);
    new_tcph = (struct tcphdr *)skb_put(recovered_skb, tcp_hdr_len);
    memcpy(new_tcph, tcph, tcp_hdr_len);

    new_tcph->seq = htonl(missing_seq);
    new_tcph->syn = 0;
    new_tcph->fin = 0;
    new_tcph->rst = 0;

    skb_put_data(recovered_skb, dec->recover_buffer, payload_len);

    new_iph->tot_len = htons(ip_hdr_len + tcp_hdr_len + payload_len);
    pep_update_ip_checksum(new_iph);
    {
        bool hw_offload = pep_ctx && pep_ctx->config.tx_csum_enabled;

        pep_fast_tcp_checksum(recovered_skb, new_iph, new_tcph, hw_offload);
    }

    recovered_skb->protocol = htons(ETH_P_IP);
    recovered_skb->dev = template_skb->dev;
    if (!recovered_skb->dev && pep_ctx)
        recovered_skb->dev = pep_ctx->wan_dev;
    recovered_skb->ip_summed = CHECKSUM_NONE;

    if (missing_idx < 64) {
        u64 bit = 1ULL << missing_idx;
        if (!(dec->received_mask & bit)) {
            dec->received_mask |= bit;
            dec->received_count++;
        }
    }

    dec->blocks_decoded++;
    dec->pkts_recovered++;

    pep_info("FEC: Recovered packet at index %d in block %u\n",
             missing_idx, dec->block_id);

    return recovered_skb;
}

/*
 * 功能/Main: 处理FEC 编码/恢复（Handle FEC encode/recovery）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；FEC 编码/映射/恢复（FEC encode/map/recover）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, loss_rate_ppm
 * 影响/Effects: 更新 FEC 策略，影响丢包恢复（update FEC policy, affects loss recovery）
 * 重要程度/Importance: 中/Medium
 */
void pep_fec_adjust_params(struct pep_flow *flow, u32 loss_rate_ppm)
{
    struct pep_fec_state *fec;
    ktime_t now;
    s64 elapsed_ms;
    u8 new_k, new_n;

    if (!flow || !pep_ctx)
        return;

    fec = &flow->fec;
    if (!fec->enabled)
        return;

    now = ktime_get();
    elapsed_ms = ktime_ms_delta(now, fec->last_adjust_time);
    if (elapsed_ms < 5000)
        return;

    fec->last_adjust_time = now;
    fec->loss_rate_ppm = loss_rate_ppm;

    if (loss_rate_ppm < 10000) {

        new_k = 10;
        new_n = 11;
    } else if (loss_rate_ppm < 50000) {

        new_k = 8;
        new_n = 10;
    } else if (loss_rate_ppm < 100000) {

        new_k = 5;
        new_n = 7;
    } else {

        new_k = 3;
        new_n = 5;
    }

    if (new_k != fec->encoder.k || new_n != fec->encoder.n) {

        fec->encoder.pkt_count = 0;

        fec->encoder.k = new_k;
        fec->encoder.n = new_n;
        fec->decoder.k = new_k;
        fec->decoder.n = new_n;

        pep_info("FEC: Parameters adjusted to K=%u N=%u for loss_rate=%u ppm\n",
                 new_k, new_n, loss_rate_ppm);
    }
}

/*
 * 功能/Main: 调整 MSS 以保证 FEC 包不超过 MTU（Adjust MSS for FEC MTU safety）
 * 细节/Details: PMTU/MSS 更新（PMTU/MSS update）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 限制 MSS，避免 FEC 包超 MTU（cap MSS to keep FEC under MTU）
 * 重要程度/Importance: 中/Medium
 */
void pep_fec_adjust_mss(struct pep_flow *flow)
{
    u32 pmtu;
    u32 max_payload;
    u32 old_mss;

    if (!flow)
        return;

    if (!flow->fec.enabled)
        return;

    pmtu = pep_pmtu_get(flow->tuple.dst_addr);
    if (pmtu <= sizeof(struct iphdr) + sizeof(struct tcphdr) + PEP_FEC_HEADER_SIZE)
        return;

    max_payload = pmtu - sizeof(struct iphdr) - sizeof(struct tcphdr) - PEP_FEC_HEADER_SIZE;
    if (flow->mss != 0 && flow->mss <= max_payload)
        return;

    old_mss = flow->mss;
    flow->mss = max_payload;

    if (pep_ctx && pep_ctx->config.debug_level >= 2) {
        pep_info("FEC: Adjusted MSS for flow %pI4:%u -> %pI4:%u from %u to %u (PMTU=%u)\n",
                 &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
                 &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port),
                 old_mss, flow->mss, pmtu);
    }
}

/*
 * 功能/Main: 获取FEC 编码/恢复（Get FEC encode/recovery）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；FEC 编码/映射/恢复（FEC encode/map/recover）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow, blocks_encoded, fec_sent, pkts_recovered, unrecoverable
 * 影响/Effects: 更新 FEC 策略，影响丢包恢复（update FEC policy, affects loss recovery）
 * 重要程度/Importance: 中/Medium
 */
void pep_fec_get_stats(struct pep_flow *flow, u64 *blocks_encoded,
                        u64 *fec_sent, u64 *pkts_recovered, u64 *unrecoverable)
{
    struct pep_fec_state *fec;

    if (!flow) {
        *blocks_encoded = 0;
        *fec_sent = 0;
        *pkts_recovered = 0;
        *unrecoverable = 0;
        return;
    }

    fec = &flow->fec;

    *blocks_encoded = fec->encoder.blocks_encoded;
    *fec_sent = fec->encoder.fec_pkts_sent;
    *pkts_recovered = fec->decoder.pkts_recovered;
    *unrecoverable = fec->decoder.unrecoverable;
}
