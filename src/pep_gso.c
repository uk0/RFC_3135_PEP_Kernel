/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/tcp.h>

extern struct pep_context *pep_ctx;

/*
 * 功能/Main: 处理GSO/GRO 分段/合并（Handle GSO/GRO segmentation/aggregation）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；frag/分片结构处理（frag list handling）；访问/维护流状态（flow state access/maintenance）；PMTU/MSS 更新（PMTU/MSS update）；并发同步（spinlock/atomic/rcu）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: flow, skb, mss
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
struct sk_buff *pep_gso_segment(struct pep_flow *flow, struct sk_buff *skb, u32 mss)
{
    struct sk_buff *segs = NULL;
    struct sk_buff *seg, *next;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len, tcp_hdr_len;
    unsigned int payload_len, total_len;
    unsigned int offset = 0;
    u32 seq;

    if (!skb || !flow)
        return NULL;

    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
    tcp_hdr_len = tcph->doff * 4;

    if (skb->len < ip_hdr_len + tcp_hdr_len) {
        pep_warn("GSO: skb too small (len=%u, ip=%u, tcp=%u)\n",
                 skb->len, ip_hdr_len, tcp_hdr_len);
        return NULL;
    }

    total_len = skb->len;
    payload_len = total_len - ip_hdr_len - tcp_hdr_len;

    if (payload_len <= mss) {

        return skb;
    }

    seq = ntohl(tcph->seq);

    pep_dbg("GSO: Software segmentation, payload=%u, mss=%u, segments=%u\n",
            payload_len, mss, DIV_ROUND_UP(payload_len, mss));

    if (skb_linearize(skb)) {
        pep_warn("GSO: Failed to linearize skb\n");
        return NULL;
    }

    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

    while (offset < payload_len) {
        u32 seg_len = min_t(u32, mss, payload_len - offset);
        struct sk_buff *new_skb;
        struct iphdr *new_iph;
        struct tcphdr *new_tcph;
        unsigned char *payload_start;

        new_skb = alloc_skb(ip_hdr_len + tcp_hdr_len + seg_len + 16, GFP_ATOMIC);
        if (!new_skb) {
            pep_warn("GSO: Failed to allocate segment skb\n");
            goto error_free_segs;
        }

        skb_reserve(new_skb, 16);

        new_iph = (struct iphdr *)skb_put(new_skb, ip_hdr_len);
        memcpy(new_iph, iph, ip_hdr_len);

        new_tcph = (struct tcphdr *)skb_put(new_skb, tcp_hdr_len);
        memcpy(new_tcph, tcph, tcp_hdr_len);

        payload_start = (unsigned char *)tcph + tcp_hdr_len;
        skb_put_data(new_skb, payload_start + offset, seg_len);

        new_iph->tot_len = htons(ip_hdr_len + tcp_hdr_len + seg_len);
        new_iph->id = htons(ntohs(iph->id) + offset / mss);
        new_iph->frag_off = htons(IP_DF);

        new_tcph->seq = htonl(seq + offset);

        if (offset + seg_len < payload_len) {
            new_tcph->psh = 0;
            new_tcph->fin = 0;
        }

        skb_reset_network_header(new_skb);
        skb_set_transport_header(new_skb, ip_hdr_len);
        new_skb->protocol = htons(ETH_P_IP);
        new_skb->ip_summed = CHECKSUM_NONE;

        new_iph->check = 0;
        new_iph->check = ip_fast_csum((unsigned char *)new_iph, new_iph->ihl);

        new_tcph->check = 0;
        new_tcph->check = csum_tcpudp_magic(new_iph->saddr, new_iph->daddr,
                                           tcp_hdr_len + seg_len, IPPROTO_TCP,
                                           csum_partial(new_tcph, tcp_hdr_len + seg_len, 0));

        if (!segs) {
            segs = new_skb;
            seg = segs;
        } else {
            seg->next = new_skb;
            seg = new_skb;
        }
        seg->next = NULL;

        offset += seg_len;

        pep_dbg("GSO: Created segment seq=%u, len=%u\n",
                ntohl(new_tcph->seq), seg_len);
    }

    return segs;

error_free_segs:

    seg = segs;
    while (seg) {
        next = seg->next;
        kfree_skb(seg);
        seg = next;
    }
    return NULL;
}

bool pep_gso_prepare_tso(struct sk_buff *skb, u32 mss, u32 payload_len)
{
    if (!skb || !mss || payload_len <= mss)
        return false;

    skb_shinfo(skb)->gso_size = mss;
    skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
    skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(payload_len, mss);

    return true;
}

/*
 * 功能/Main: 处理GSO/GRO 分段/合并（Handle GSO/GRO segmentation/aggregation）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；并发同步（spinlock/atomic/rcu）；校验和处理（checksum adjust）；GSO/GRO 分段/合并（GSO/GRO seg/agg）
 * 输入/Inputs: 参数/Inputs: flow, skb, gro_queue, max_size
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
struct sk_buff *pep_gro_receive(struct pep_flow *flow, struct sk_buff *skb,
                                struct sk_buff_head *gro_queue, u32 max_size)
{
    struct sk_buff *gro_skb = NULL;
    struct iphdr *iph, *gro_iph;
    struct tcphdr *tcph, *gro_tcph;
    unsigned int ip_hdr_len, tcp_hdr_len;
    unsigned int payload_len;
    u32 seq;

    if (!flow || !skb || !gro_queue)
        return ERR_PTR(-EINVAL);

    if (skb->dev && skb->dev->features & NETIF_F_GRO) {

    }

    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
    tcp_hdr_len = tcph->doff * 4;
    payload_len = ntohs(iph->tot_len) - ip_hdr_len - tcp_hdr_len;
    seq = ntohl(tcph->seq);

    if (tcph->syn || tcph->fin || tcph->rst) {

        if (!skb_queue_empty(gro_queue)) {
            gro_skb = __skb_dequeue(gro_queue);

            skb->tstamp = ktime_get();
            __skb_queue_tail(gro_queue, skb);
            return gro_skb;
        }

        return skb;
    }

    if (payload_len == 0) {

        if (!skb_queue_empty(gro_queue)) {
            gro_skb = __skb_dequeue(gro_queue);
        }
        return gro_skb ? gro_skb : skb;
    }

    gro_skb = skb_peek(gro_queue);
    if (!gro_skb) {
        /*
         * v78 关键修复: 第一个包检查 PSH 标志
         *
         * 问题: 之前即使第一个包有 PSH 标志，也会入队等待 40ms 超时
         *       TLS Server Hello 等带 PSH 的数据包会被延迟 40ms，导致握手卡住
         *
         * 解决: 如果包有 PSH 标志（应用层数据边界），直接返回不聚合
         *       这确保 TLS 握手等交互式流量能立即投递
         */
        if (tcph->psh) {
            pep_dbg("GRO: First packet has PSH, not queuing, seq=%u, len=%u\n", seq, payload_len);
            return skb;
        }

        skb->tstamp = ktime_get();
        __skb_queue_tail(gro_queue, skb);
        pep_dbg("GRO: First packet queued, seq=%u, len=%u\n", seq, payload_len);
        return NULL;
    }

    /*
     * v63.9 关键修复: 先线性化 gro_skb 再访问其头部
     *
     * 问题: 在 skb_linearize 之前就通过 ip_hdr(gro_skb) 访问头部
     *       如果 gro_skb 是非线性的，可能导致访问无效内存
     *
     * 解决: 先线性化，再获取头部指针
     */
    if (skb_linearize(gro_skb)) {
        pep_warn("GRO: Failed to linearize gro_skb early\n");
        /* 无法线性化，刷新队列中的包并添加新包 */
        __skb_unlink(gro_skb, gro_queue);
        skb->tstamp = ktime_get();
        __skb_queue_tail(gro_queue, skb);
        return gro_skb;
    }

    gro_iph = ip_hdr(gro_skb);
    if (!gro_iph || ntohs(gro_iph->tot_len) < sizeof(struct iphdr)) {
        pep_warn("GRO: Invalid gro_skb IP header\n");
        __skb_unlink(gro_skb, gro_queue);
        skb->tstamp = ktime_get();
        __skb_queue_tail(gro_queue, skb);
        return gro_skb;
    }

    gro_tcph = (struct tcphdr *)((unsigned char *)gro_iph + gro_iph->ihl * 4);

    u32 gro_seq = ntohl(gro_tcph->seq);
    u32 gro_payload_len = ntohs(gro_iph->tot_len) - gro_iph->ihl * 4 - gro_tcph->doff * 4;
    u32 expected_seq = gro_seq + gro_payload_len;

    if (seq == expected_seq &&
        tcph->ack_seq == gro_tcph->ack_seq &&
        !tcph->psh &&
        (gro_payload_len + payload_len) <= max_size) {

        __skb_unlink(gro_skb, gro_queue);

        /* v63.9: gro_skb 已在上面线性化，只需线性化 incoming skb */
        if (skb_linearize(skb)) {
            pep_warn("GRO: Failed to linearize incoming skb\n");

            skb->tstamp = ktime_get();
            __skb_queue_tail(gro_queue, skb);
            return gro_skb;
        }

        /* 重新获取 incoming skb 的头部指针 */
        iph = ip_hdr(skb);
        ip_hdr_len = iph->ihl * 4;
        tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
        tcp_hdr_len = tcph->doff * 4;

        if (skb_tailroom(gro_skb) < payload_len) {

            if (pskb_expand_head(gro_skb, 0, payload_len, GFP_ATOMIC)) {
                pep_warn("GRO: Failed to expand gro_skb\n");

                skb->tstamp = ktime_get();
                __skb_queue_tail(gro_queue, skb);
                return gro_skb;
            }
            /*
             * v63.9: pskb_expand_head 可能重新分配数据缓冲区
             * 必须重新获取 gro_skb 的头部指针
             */
            gro_iph = ip_hdr(gro_skb);
            gro_tcph = (struct tcphdr *)((unsigned char *)gro_iph + gro_iph->ihl * 4);
        }

        /*
         * v63 关键修复: 确保头部可写
         *
         * 问题: 即使 tailroom 充足，skb 头部区域可能是共享/克隆的
         *       直接修改共享头部导致数据损坏或内核崩溃
         *
         * 解决: 使用 skb_cow_head() 确保头部区域可写
         *       如果头部是共享的，会复制一份私有副本
         */
        if (skb_cow_head(gro_skb, 0)) {
            pep_warn("GRO: Failed to make header writable\n");

            skb->tstamp = ktime_get();
            __skb_queue_tail(gro_queue, skb);
            return gro_skb;
        }

        unsigned char *src_payload = (unsigned char *)tcph + tcp_hdr_len;
        skb_put_data(gro_skb, src_payload, payload_len);

        /* 重新获取头部指针（skb_cow_head 可能重新分配了头部区域）*/
        gro_iph = ip_hdr(gro_skb);
        gro_tcph = (struct tcphdr *)((unsigned char *)gro_iph + gro_iph->ihl * 4);

        gro_iph->tot_len = htons(ntohs(gro_iph->tot_len) + payload_len);

        if (tcph->psh) {
            gro_tcph->psh = 1;
        }

        if (skb_shinfo(gro_skb)->gso_segs == 0) {
            skb_shinfo(gro_skb)->gso_segs = 1;
        }
        skb_shinfo(gro_skb)->gso_segs++;

        gro_iph->check = 0;
        gro_iph->check = ip_fast_csum((unsigned char *)gro_iph, gro_iph->ihl);

        gro_tcph->check = 0;
        gro_tcph->check = csum_tcpudp_magic(gro_iph->saddr, gro_iph->daddr,
                                           ntohs(gro_iph->tot_len) - gro_iph->ihl * 4,
                                           IPPROTO_TCP,
                                           csum_partial(gro_tcph,
                                                       ntohs(gro_iph->tot_len) - gro_iph->ihl * 4, 0));

        kfree_skb(skb);

        pep_dbg("GRO: Aggregated seq=%u+%u, total=%u bytes, %u segments\n",
                gro_seq, payload_len,
                ntohs(gro_iph->tot_len) - gro_iph->ihl * 4 - gro_tcph->doff * 4,
                skb_shinfo(gro_skb)->gso_segs);

        if (gro_tcph->psh ||
            (ntohs(gro_iph->tot_len) - gro_iph->ihl * 4 - gro_tcph->doff * 4) >= max_size) {

            return gro_skb;
        }

        __skb_queue_tail(gro_queue, gro_skb);
        return NULL;

    } else {

        __skb_unlink(gro_skb, gro_queue);
        skb->tstamp = ktime_get();
        __skb_queue_tail(gro_queue, skb);

        pep_dbg("GRO: Cannot aggregate, expected seq=%u, got=%u\n",
                expected_seq, seq);

        return gro_skb;
    }
}

/*
 * 功能/Main: 处理GSO/GRO 分段/合并（Handle GSO/GRO segmentation/aggregation）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；队列/链表维护（queue/list maintenance）；GSO/GRO 分段/合并（GSO/GRO seg/agg）
 * 输入/Inputs: 参数/Inputs: gro_queue, timeout_us
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
struct sk_buff *pep_gro_timeout_flush(struct sk_buff_head *gro_queue, u32 timeout_us)
{
    struct sk_buff *skb;
    ktime_t now;
    s64 age_us;

    if (!gro_queue || skb_queue_empty(gro_queue))
        return NULL;

    skb = skb_peek(gro_queue);
    if (!skb)
        return NULL;

    now = ktime_get();
    age_us = ktime_to_us(ktime_sub(now, skb->tstamp));

    if (age_us >= timeout_us) {

        __skb_unlink(skb, gro_queue);
        pep_dbg("GRO: Timeout flush, age=%lld us\n", age_us);
        return skb;
    }

    return NULL;
}

/*
 * 功能/Main: 处理GSO/GRO 分段/合并（Handle GSO/GRO segmentation/aggregation）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；PMTU/MSS 更新（PMTU/MSS update）；GSO/GRO 分段/合并（GSO/GRO seg/agg）
 * 输入/Inputs: 参数/Inputs: skb, mss
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
bool pep_gso_needed(struct sk_buff *skb, u32 mss)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int payload_len;

    if (!skb || !mss)
        return false;

    if (skb_is_gso(skb))
        return true;

    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((unsigned char *)iph + iph->ihl * 4);
    if (skb->len < iph->ihl * 4 + tcph->doff * 4)
        return false;
    payload_len = skb->len - iph->ihl * 4 - tcph->doff * 4;

    return payload_len > mss;
}

/*
 * 功能/Main: 处理GSO/GRO 分段/合并（Handle GSO/GRO segmentation/aggregation）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；PMTU/MSS 更新（PMTU/MSS update）；GSO/GRO 分段/合并（GSO/GRO seg/agg）
 * 输入/Inputs: 参数/Inputs: skb, mss
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
u32 pep_gso_segment_count(struct sk_buff *skb, u32 mss)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int payload_len;

    if (!skb || !mss)
        return 1;

    if (skb_is_gso(skb) && skb_shinfo(skb)->gso_segs)
        return skb_shinfo(skb)->gso_segs;

    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((unsigned char *)iph + iph->ihl * 4);
    if (skb->len < iph->ihl * 4 + tcph->doff * 4)
        return 1;
    payload_len = skb->len - iph->ihl * 4 - tcph->doff * 4;

    return DIV_ROUND_UP(payload_len, mss);
}

/*
 * 功能/Main: 初始化GSO/GRO 分段/合并（Initialize GSO/GRO segmentation/aggregation）
 * 细节/Details: GSO/GRO 分段/合并（GSO/GRO seg/agg）
 * 输入/Inputs: 无（void）/none
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
int pep_gso_init(void)
{
    pr_info("pep: GSO/GRO subsystem initialized\n");
    return 0;
}

/*
 * 功能/Main: 清理GSO/GRO 分段/合并（Cleanup GSO/GRO segmentation/aggregation）
 * 细节/Details: GSO/GRO 分段/合并（GSO/GRO seg/agg）
 * 输入/Inputs: 无（void）/none
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_gso_exit(void)
{
    pr_info("pep: GSO/GRO subsystem cleanup\n");
}
