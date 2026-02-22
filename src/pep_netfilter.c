/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/net_namespace.h>

extern struct pep_context *pep_ctx;

#ifndef IP_DEFRAG_LOCAL_DELIVER
#define IP_DEFRAG_LOCAL_DELIVER 0
#endif

#ifndef IP_DEFRAG_CONNTRACK_IN
#define IP_DEFRAG_CONNTRACK_IN IP_DEFRAG_LOCAL_DELIVER
#endif
#ifndef IP_DEFRAG_CONNTRACK_OUT
#define IP_DEFRAG_CONNTRACK_OUT IP_DEFRAG_LOCAL_DELIVER
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
extern int ip_defrag(struct net *net, struct sk_buff *skb, u32 user);
#else
extern struct sk_buff *ip_defrag(struct sk_buff *skb, u32 user);
#endif

/*
 * 功能/Main: 处理pep_ip_defrag_if_needed相关逻辑（Handle pep_ip_defrag_if_needed logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；分片重组/重排处理（fragment reassembly）；校验和处理（checksum adjust）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: ctx, skb, user
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static struct sk_buff *pep_ip_defrag_if_needed(struct pep_context *ctx, struct sk_buff *skb,
                                               u32 user)
{
    struct iphdr *iph;
    struct net *net;
    int ret;

    if (!ctx || !ctx->config.ip_reassembly_enabled)
        return skb;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return skb;

    iph = ip_hdr(skb);
    if (iph->version != 4)
        return skb;

    if (!(iph->frag_off & htons(IP_MF | IP_OFFSET)))
        return skb;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
    net = skb->dev ? dev_net(skb->dev) : &init_net;
    local_bh_disable();
    ret = ip_defrag(net, skb, user);
    local_bh_enable();

    if (ret != 0)
        return NULL;

    ip_send_check(ip_hdr(skb));
    return skb;
#else
    {
        struct sk_buff *defrag_skb;

        local_bh_disable();
        defrag_skb = ip_defrag(skb, user);
        local_bh_enable();

        if (!defrag_skb)
            return NULL;

        ip_send_check(ip_hdr(defrag_skb));
        return defrag_skb;
    }
#endif
}

/*
 * 功能/Main: 处理pep_iface_bound相关逻辑（Handle pep_iface_bound logic）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: ctx
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static inline bool pep_iface_bound(const struct pep_context *ctx)
{
    return ctx && ctx->wan_dev && ctx->lan_dev;
}

/*
 * 功能/Main: 处理pep_single_iface相关逻辑（Handle pep_single_iface logic）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: ctx
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static inline bool pep_single_iface(const struct pep_context *ctx)
{
    return pep_iface_bound(ctx) && ctx->wan_dev == ctx->lan_dev;
}

/*
 * 功能/Main: 处理pep_syn_fail_open_active相关逻辑（Handle pep_syn_fail_open_active logic）
 * 细节/Details: 配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: ctx
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static inline bool pep_syn_fail_open_active(const struct pep_context *ctx)
{
    u64 until;

    if (!ctx || ctx->config.wan_syn_fail_open_ms == 0)
        return false;

    until = READ_ONCE(ctx->syn_fail_open_until_ns);
    if (!until)
        return false;

    return ktime_get_ns() < until;
}

/*
 * 功能/Main: 处理pep_match_wan_in相关逻辑（Handle pep_match_wan_in logic）
 * 细节/Details: 统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: ctx, state
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static bool pep_match_wan_in(const struct pep_context *ctx, const struct nf_hook_state *state)
{
    if (!pep_iface_bound(ctx))
        return false;

    if (!state || !state->in)
        return false;

    return state->in == ctx->wan_dev;
}

/*
 * 功能/Main: 处理pep_match_wan_out相关逻辑（Handle pep_match_wan_out logic）
 * 细节/Details: 统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: ctx, state
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static bool pep_match_wan_out(const struct pep_context *ctx, const struct nf_hook_state *state)
{
    if (!pep_iface_bound(ctx))
        return false;

    if (!state || !state->out)
        return false;

    return state->out == ctx->wan_dev;
}

/*
 * 功能/Main: 处理pep_match_lan_in相关逻辑（Handle pep_match_lan_in logic）
 * 细节/Details: 统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: ctx, state
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static bool pep_match_lan_in(const struct pep_context *ctx, const struct nf_hook_state *state)
{
    if (!pep_iface_bound(ctx))
        return false;

    if (pep_single_iface(ctx)) {
        if (!state || !state->in)
            return true;
        return state->in == ctx->lan_dev;
    }

    if (!state || !state->in)
        return false;

    return state->in == ctx->lan_dev;
}

/*
 * 功能/Main: 设置pep_set_conntrack_liberal相关逻辑（Set pep_set_conntrack_liberal logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；Netfilter 钩子处理（netfilter hook）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: skb
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static inline void pep_set_conntrack_liberal(struct sk_buff *skb)
{
#ifdef CONFIG_NF_CONNTRACK
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct;

    ct = nf_ct_get(skb, &ctinfo);
    if (ct && nf_ct_protonum(ct) == IPPROTO_TCP) {
        nf_ct_set_tcp_be_liberal(ct);
    }
#endif
}

/*
 * 功能/Main: 处理pep_extract_tuple相关逻辑（Handle pep_extract_tuple logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）
 * 输入/Inputs: 参数/Inputs: skb, tuple
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static inline bool pep_extract_tuple(struct sk_buff *skb, struct pep_tuple *tuple)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return false;

    iph = ip_hdr(skb);

    if (iph->version != 4 || iph->protocol != IPPROTO_TCP)
        return false;

    ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return false;

    if (!pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr)))
        return false;

    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

    tuple->src_addr = iph->saddr;
    tuple->dst_addr = iph->daddr;
    tuple->src_port = tcph->source;
    tuple->dst_port = tcph->dest;
    tuple->protocol = IPPROTO_TCP;

    return true;
}

/*
 * 功能/Main: 处理pep_is_docker_ip相关逻辑（Handle pep_is_docker_ip logic）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: addr
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static inline bool pep_is_docker_ip(__be32 addr)
{

    u32 host_addr = ntohl(addr);

    return (host_addr >= 0xAC100000 && host_addr <= 0xAC1FFFFF);
}

/*
 * 功能/Main: 处理pep_should_process相关逻辑（Process pep_should_process logic）
 * 细节/Details: 配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: ctx, tuple
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
static inline bool pep_should_process(const struct pep_context *ctx,
                                      const struct pep_tuple *tuple)
{
    u16 src_port, dst_port;

    if (ipv4_is_loopback(tuple->src_addr) || ipv4_is_loopback(tuple->dst_addr))
        return false;

    if (ipv4_is_multicast(tuple->dst_addr))
        return false;

    if (pep_is_docker_ip(tuple->src_addr) || pep_is_docker_ip(tuple->dst_addr))
        return false;

    /*
     * v105 关键修复: 排除管理端口流量
     *
     * 问题: SSH/DNS 等管理流量被 PEP 代理处理
     *       在高负载下可能导致 SSH 断连
     *
     * 解决: 排除 SSH(22), DNS(53), DHCP(67,68) 等管理端口
     */
    src_port = ntohs(tuple->src_port);
    dst_port = ntohs(tuple->dst_port);

    /* 排除 SSH 端口 22 */
    if (src_port == 22 || dst_port == 22)
        return false;

    /* 排除 DNS 端口 53 */
    if (src_port == 53 || dst_port == 53)
        return false;

    /* 排除 DHCP 端口 67, 68 */
    if (src_port == 67 || dst_port == 67 ||
        src_port == 68 || dst_port == 68)
        return false;

    if (ctx && ctx->config.subnet_acc && ctx->config.lan_segment_mask != 0) {
        u32 mask = (__force u32)ctx->config.lan_segment_mask;
        u32 net = (__force u32)ctx->config.lan_segment_addr;
        u32 src = (__force u32)tuple->src_addr;
        u32 dst = (__force u32)tuple->dst_addr;
        bool src_in = (src & mask) == net;
        bool dst_in = (dst & mask) == net;

        if (pep_single_iface(ctx) && src_in && dst_in)
            return false;

        if (!src_in && !dst_in)
            return false;
    }

    return true;
}

/*
 * 功能/Main: 处理pep_handle_syn相关逻辑（Handle pep_handle_syn logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；流表查找/创建/状态更新（flow lookup/create/update）；PMTU/MSS 更新（PMTU/MSS update）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: ctx, skb, tuple
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
static struct pep_flow *pep_handle_syn(struct pep_context *ctx,
                                        struct sk_buff *skb,
                                        const struct pep_tuple *tuple)
{
    struct pep_flow *flow;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len;

    if (ctx->config.bypass_overflows &&
        atomic_read(&ctx->flow_table.count) >= ctx->flow_table.max_flows) {
        pep_warn("pep: bypass_overflows active, skipping new flow\n");
        return NULL;
    }

    flow = pep_flow_find(&ctx->flow_table, tuple);
    if (flow) {
        /*
         * v79/v104 关键修复: 处理 TIME_WAIT/CLOSING 状态的旧 flow
         *
         * 问题: 短连接关闭后进入 TIME_WAIT 状态，但不设置 DEAD_BIT
         *       新 SYN 到达时找到旧 flow，使用过时的 SEQ 号
         *       导致新连接无法正常工作 ("无法加载")
         *
         * 解决: 如果找到的 flow 处于 closing 状态（FIN_WAIT_1/2, CLOSING,
         *       TIME_WAIT, CLOSE_WAIT, LAST_ACK），标记为 dead 并创建新 flow
         *
         * 这符合 RFC 793: 新 SYN 可以重用 TIME_WAIT 状态的连接
         *
         * v104 关键修复: 必须立即从哈希表删除旧流！
         *
         * 问题: v79 只标记 DEAD_BIT 但不从哈希表删除
         *       v94 的 translation-aware lookup 会返回 DEAD 流
         *       当端口重用时，哈希表中存在两个相同 tuple 的流
         *       PRE_ROUTING 可能找到旧的 DEAD 流（state=0）而不是新流
         *       导致 NS_BINDING_ABORTED 错误
         *
         * 解决: 在标记 DEAD 的同时从哈希表删除，避免双流问题
         */
        if (flow->state >= PEP_TCP_FIN_WAIT_1 &&
            flow->state <= PEP_TCP_TIME_WAIT) {
            pr_info("pep: v104 SYN reuse: old flow (state=%d) removed from hash, port=%u\n",
                    flow->state, ntohs(tuple->src_port));
            set_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags);
            /* v104: 立即从哈希表删除，避免 translation-aware lookup 找到旧流 */
            hash_del_rcu(&flow->hnode);
            atomic_dec(&ctx->flow_table.count);
            pep_flow_put(flow);
            flow = NULL;
        } else {
            return flow;
        }
    }

    flow = pep_flow_create(&ctx->flow_table, tuple);
    if (!flow)
        return NULL;

    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

    flow->ecn_requested = (ctx->config.ecn_enabled &&
                           tcph->ece && tcph->cwr) ? 1 : 0;
    flow->isn_client = ntohl(tcph->seq);

    flow->lan.seq_next = ntohl(tcph->seq) + 1;
    flow->lan.seq_una = ntohl(tcph->seq);
    flow->lan.win = ntohs(tcph->window);
    flow->state = PEP_TCP_SYN_SENT;

    if (tcph->doff > 5) {
        unsigned int tcp_hdr_len_full = tcph->doff * 4;

        if (pskb_may_pull(skb, ip_hdr_len + tcp_hdr_len_full)) {
            struct pep_tcp_options opts;

            iph = ip_hdr(skb);
            tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

            memset(&opts, 0, sizeof(opts));
            pep_parse_tcp_options(tcph, &opts);

            if (opts.mss > 0)
                flow->mss = opts.mss;

            if (opts.wscale > 0)
                set_bit(PEP_FLOW_F_WSCALE_ENABLED_BIT, &flow->flags);

            if (opts.sack_ok)
                set_bit(PEP_FLOW_F_SACK_ENABLED_BIT, &flow->flags);

            if (opts.ts_val != 0)
                set_bit(PEP_FLOW_F_TIMESTAMP_BIT, &flow->flags);
        }
    }

    pep_fec_adjust_mss(flow);

    pep_dbg("New flow SYN: %pI4:%u -> %pI4:%u seq=%u\n",
            &tuple->src_addr, ntohs(tuple->src_port),
            &tuple->dst_addr, ntohs(tuple->dst_port),
            ntohl(tcph->seq));

    return flow;
}

/*
 * 功能/Main: 更新流表/会话状态（Update flow/session state）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow, tcph, dir
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 高/High
 */
static void pep_update_flow_state(struct pep_flow *flow, struct tcphdr *tcph,
                                   enum pep_direction dir)
{
    if (!flow)
        return;

    switch (flow->state) {
    case PEP_TCP_SYN_SENT:
        if (tcph->syn && tcph->ack) {
            flow->state = PEP_TCP_SYN_RECV;
            if (!test_bit(PEP_FLOW_F_SPOOFED_BIT, &flow->flags)) {
                flow->wan.seq_next = ntohl(tcph->seq) + 1;
                flow->wan.seq_una = ntohl(tcph->seq);
                flow->wan.ack_seq = ntohl(tcph->ack_seq);
                flow->wan.win = ntohs(tcph->window);
            }
        }
        break;

    case PEP_TCP_SYN_RECV:
        if (tcph->ack && !tcph->syn) {
            flow->state = PEP_TCP_ESTABLISHED;
            set_bit(PEP_FLOW_F_ACCELERATED_BIT, &flow->flags);
            set_bit(PEP_FLOW_F_ESTABLISHED_BIT, &flow->flags);
        }
        break;

    case PEP_TCP_ESTABLISHED:
        if (tcph->fin) {
            /*
             * v92 修复: 区分主动关闭和被动关闭
             *
             * Split-TCP 连接终止有两种情况：
             * 1. 客户端主动关闭 (LAN→WAN FIN): 进入 FIN_WAIT_1
             * 2. 服务器主动关闭 (WAN→LAN FIN): 进入 CLOSE_WAIT
             *
             * 之前的问题: 无论哪个方向的 FIN 都进入 FIN_WAIT_1
             *            导致服务器主动关闭时状态不正确
             *
             * NS_BINDING_ABORTED 可能原因:
             * - 服务器发送 FIN，但 PEP 状态错误，无法正确完成关闭
             */
            /* v109: FIN state transition — debug only */
            if (pep_ctx && pep_ctx->config.debug_level >= 3) {
                pr_info_ratelimited("pep: update_flow_state: FIN dir=%d old_state=%d\n",
                        dir, flow->state);
            }

            if (dir == PEP_DIR_LAN_TO_WAN) {
                /* 客户端主动关闭 */
                flow->state = PEP_TCP_FIN_WAIT_1;
                pep_dbg("v92: Client initiated close, state -> FIN_WAIT_1\n");
            } else {
                /* 服务器主动关闭 */
                flow->state = PEP_TCP_CLOSE_WAIT;
                pep_dbg("v92: Server initiated close, state -> CLOSE_WAIT\n");
            }
            set_bit(PEP_FLOW_F_CLOSING_BIT, &flow->flags);
        }
        if (tcph->rst) {
            flow->state = PEP_TCP_CLOSED;

            set_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags);
        }
        break;

    case PEP_TCP_FIN_WAIT_1:
        if (tcph->ack && tcph->fin) {
            flow->state = PEP_TCP_TIME_WAIT;
        } else if (tcph->ack) {
            flow->state = PEP_TCP_FIN_WAIT_2;
        } else if (tcph->fin) {
            flow->state = PEP_TCP_CLOSING;
        }
        break;

    case PEP_TCP_FIN_WAIT_2:
        if (tcph->fin) {
            flow->state = PEP_TCP_TIME_WAIT;
        }
        break;

    case PEP_TCP_CLOSING:
        if (tcph->ack) {
            flow->state = PEP_TCP_TIME_WAIT;
        }
        break;

    case PEP_TCP_CLOSE_WAIT:
        if (tcph->fin) {
            flow->state = PEP_TCP_LAST_ACK;
        }
        break;

    case PEP_TCP_LAST_ACK:
        if (tcph->ack) {
            /*
             * v103 关键修复: 仿照 pepsal，只有缓冲区为空时才标记 DEAD
             *
             * 问题: 之前收到 ACK 后立即设置 DEAD_BIT，
             *       但 wan_to_lan 队列中可能还有数据没发给客户端
             *       导致数据丢失，浏览器报告 NS_BINDING_ABORTED
             *
             * 解决: 检查缓冲区，只有为空时才进入 CLOSED + DEAD
             *       否则进入 TIME_WAIT，等待数据传输完成或超时清理
             *
             * pepsal 参考 (pep.c line 1000-1008):
             *   if ((iostat & PEP_IOEOF) && pepbuf_empty(&endp->buf))
             *       destroy_proxy(proxy);
             */
            if (pep_queue_len(&flow->wan_to_lan) == 0 &&
                pep_queue_len(&flow->lan_to_wan) == 0) {
                /* 缓冲区为空，可以安全关闭 */
                flow->state = PEP_TCP_CLOSED;
                set_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags);
                pr_info("pep: v103 LAST_ACK->CLOSED+DEAD (buffers empty) port=%u\n",
                        ntohs(flow->tuple.src_port));
            } else {
                /* 缓冲区还有数据，进入 TIME_WAIT 等待数据传输 */
                flow->state = PEP_TCP_TIME_WAIT;
                pr_info("pep: v103 LAST_ACK->TIME_WAIT (buffers not empty: w2l=%u, l2w=%u) port=%u\n",
                        pep_queue_len(&flow->wan_to_lan),
                        pep_queue_len(&flow->lan_to_wan),
                        ntohs(flow->tuple.src_port));
            }
        }
        break;

    default:
        break;
    }
}

/*
 * 功能/Main: 处理pep_check_fastpath相关逻辑（Handle pep_check_fastpath logic）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: ctx, flow, tcph
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static inline bool pep_check_fastpath(struct pep_context *ctx,
                                       struct pep_flow *flow,
                                       struct tcphdr *tcph)
{
    u64 total_packets;

    if (!ctx->config.fastpath_enabled)
        return false;

    if (flow->state != PEP_TCP_ESTABLISHED)
        return false;

    if (tcph->syn || tcph->fin || tcph->rst)
        return false;

    if (test_bit(PEP_FLOW_F_FASTPATH_BIT, &flow->flags)) {
        pep_stats_inc_fastpath();
        return true;
    }

    total_packets = flow->rx_packets + flow->tx_packets;
    if (total_packets >= ctx->config.fastpath_threshold) {
        set_bit(PEP_FLOW_F_FASTPATH_BIT, &flow->flags);
        pep_dbg("Flow %pI4:%u -> %pI4:%u entered Fast Path (pkts=%llu)\n",
                &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
                &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port),
                total_packets);
        pep_stats_inc_fastpath();
        return true;
    }

    return false;
}

/*
 * 功能/Main: 处理Netfilter 报文路径（Handle Netfilter packet path）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；分片重组/重排处理（fragment reassembly）；流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；FEC 编码/映射/恢复（FEC encode/map/recover）
 * 输入/Inputs: 参数/Inputs: priv, skb, state
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
static unsigned int pep_nf_pre_routing(void *priv,
                                        struct sk_buff *skb,
                                        const struct nf_hook_state *state)
{
    struct pep_context *ctx = priv;
    struct pep_tuple tuple;
    struct pep_flow *flow;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len;

    if (!ctx || !atomic_read(&ctx->running) || !ctx->config.enabled)
        return NF_ACCEPT;

    if (!pep_match_wan_in(ctx, state))
        return NF_ACCEPT;

    if (skb->mark == PEP_SKB_MARK ||
        skb->mark == PEP_SKB_MARK_FAKE_ACK ||
        skb->mark == PEP_SKB_MARK_RETRANS)
        return NF_ACCEPT;

    skb = pep_ip_defrag_if_needed(ctx, skb, IP_DEFRAG_CONNTRACK_IN);
    if (!skb)
        return NF_STOLEN;

    if (pskb_may_pull(skb, sizeof(struct iphdr))) {
        iph = ip_hdr(skb);
        if (iph->version == 4 && ctx->config.pmtu_enabled &&
            iph->protocol == IPPROTO_ICMP) {
            pep_pmtu_handle_icmp_frag_needed(skb);
            return NF_ACCEPT;
        }
    }

    if (!pep_extract_tuple(skb, &tuple))
        return NF_ACCEPT;

    if (!pep_should_process(ctx, &tuple))
        return NF_ACCEPT;

    /*
     * v83.2: RX checksum check 移动到 flow lookup 之后
     *
     * 原因: 之前的 RX checksum 检查发生在 flow lookup 之前，
     *       导致非 PEP 流量（如 SSH、预先存在的连接）也被检查，
     *       虚拟网络桥接（如 Parallels）可能产生校验和不正确的包被误丢弃
     *
     * 解决: 将 RX checksum 检查移动到 flow lookup 之后，
     *       只对 PEP 管理的流进行校验，非 PEP 流量直接 NF_ACCEPT
     */

    pep_stats_inc_rx(skb->len);

    if (pep_ctx && pep_ctx->config.debug_level >= 2) {
        iph = ip_hdr(skb);
        ip_hdr_len = iph->ihl * 4;
        tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
        if (ntohs(tcph->source) != 22 && ntohs(tcph->dest) != 22) {
            unsigned int plen = ntohs(iph->tot_len) - ip_hdr_len - (tcph->doff * 4);

            if (plen > 0 || tcph->syn || tcph->rst) {
                pr_info_ratelimited("pep: PRE_ROUTING: %pI4:%u -> %pI4:%u flags=%c%c%c%c len=%u\n",
                                    &tuple.src_addr, ntohs(tuple.src_port),
                                    &tuple.dst_addr, ntohs(tuple.dst_port),
                                    tcph->syn ? 'S' : '-',
                                    tcph->ack ? 'A' : '-',
                                    tcph->fin ? 'F' : '-',
                                    tcph->rst ? 'R' : '-',
                                    plen);
            }
        }
    }

    bool is_server_to_client = false;

    /*
     * v94: 使用 translation-aware 版本的 flow 查找函数
     *
     * 问题：当 TCP 连接关闭时，DEAD_BIT 被设置在 flow 上，
     * 但服务器返回的 in-flight 包仍然需要序列号翻译。
     * 原来的 pep_flow_find() 会跳过 DEAD 流，导致这些包
     * 以错误的序列号传递给客户端，客户端拒绝并触发
     * NS_BINDING_ABORTED 错误。
     *
     * 解决：使用 pep_flow_find_*_for_translation() 函数，
     * 这些函数会返回 DEAD 流（只要 refcnt > 0），
     * 确保 in-flight 包能够正确进行序列号翻译。
     */
    flow = pep_flow_find_reverse_for_translation(&ctx->flow_table, &tuple);
    if (flow) {
        is_server_to_client = true;
    } else {
        flow = pep_flow_find_for_translation(&ctx->flow_table, &tuple);
    }

    if (!flow) {

        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
            if (ntohs(tuple.src_port) != 22 && ntohs(tuple.dst_port) != 22) {
                unsigned int ip_hlen = ip_hdr(skb)->ihl * 4;
                struct tcphdr *th = (struct tcphdr *)((unsigned char *)ip_hdr(skb) + ip_hlen);
                unsigned int plen = ntohs(ip_hdr(skb)->tot_len) - ip_hlen - (th->doff * 4);

                if (plen > 0 || (th->syn && th->ack) || th->rst) {
                    pr_info_ratelimited("pep: PRE_ROUTING no flow: %pI4:%u -> %pI4:%u flags=%c%c%c%c len=%u\n",
                                        &tuple.src_addr, ntohs(tuple.src_port),
                                        &tuple.dst_addr, ntohs(tuple.dst_port),
                                        th->syn ? 'S' : '-', th->ack ? 'A' : '-',
                                        th->fin ? 'F' : '-', th->rst ? 'R' : '-',
                                        plen);
                } else if (th->ack && !th->syn && !th->fin && !th->rst && plen == 0) {
                    /*
                     * v76: 降低日志级别从 CRITICAL 到 debug
                     *
                     * 这不是 bug，而是预期行为：
                     * - 模块只跟踪从 SYN 开始的新连接
                     * - 模块加载前已建立的连接没有 flow 条目
                     * - 这些 Pure ACK 来自预先存在的连接，正常通过即可
                     */
                    pep_dbg("Pure ACK no flow (pre-existing conn): %pI4:%u -> %pI4:%u ack_seq=%u\n",
                            &tuple.src_addr, ntohs(tuple.src_port),
                            &tuple.dst_addr, ntohs(tuple.dst_port),
                            ntohl(th->ack_seq));
                }
            }
        }
        return NF_ACCEPT;
    }

    pep_flow_update_activity(flow);

    /*
     * v83.2: RX checksum check 只对 PEP 管理的流进行
     *
     * 在 flow lookup 之后检查，确保只有 PEP 加速的流才会被丢弃
     * 非 PEP 流量（SSH、预先存在的连接）已经在上面 NF_ACCEPT 返回
     */
    if (ctx->config.rx_csum_enabled && !pep_rx_checksum_ok(skb)) {
        pep_stats_inc_dropped();
        if (pep_ctx && pep_ctx->config.debug_level >= 1) {
            pr_info_ratelimited("pep: RX checksum error (PEP flow) %pI4:%u -> %pI4:%u\n",
                                &tuple.src_addr, ntohs(tuple.src_port),
                                &tuple.dst_addr, ntohs(tuple.dst_port));
        }
        pep_flow_put(flow);
        return NF_DROP;
    }

    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

    if (ctx->config.gro_enabled && is_server_to_client) {
        unsigned int payload_len = ntohs(iph->tot_len) - ip_hdr_len - (tcph->doff * 4);

        if (payload_len > 0 && !tcph->syn && !tcph->fin && !tcph->rst) {
            struct sk_buff *gro_result;
            unsigned long gro_flags;
            /*
             * v68 关键修复: 在 GRO 聚合前保存序列号信息用于 Advance ACK
             *
             * 问题: 之前只在 GRO timer flush 时才调度 Advance ACK，
             *       导致服务器等待 40ms 才能收到 ACK，吞吐量骤降。
             *
             * 解决: 每收到一个数据包就更新 wan.seq_next 并调度 Advance ACK，
             *       即使该包被 GRO 聚合。这样服务器能及时收到 ACK 确认。
             */
            u32 saved_skb_len = skb->len;
            u32 saved_server_seq = ntohl(tcph->seq);
            u32 saved_server_seq_end = saved_server_seq + payload_len;
            u32 saved_payload_len = payload_len;

            /*
             * v63.4 关键修复: 使用 spin_lock_irqsave 防止死锁
             */
            spin_lock_irqsave(&flow->gro_lock, gro_flags);
            gro_result = pep_gro_receive(flow, skb, &flow->gro_queue, flow->gro_max_size);
            spin_unlock_irqrestore(&flow->gro_lock, gro_flags);

            if (gro_result == NULL) {
                /* skb 已被聚合或入队，不要再访问 skb */
                flow->gro_pkts_aggregated++;
                flow->gro_bytes_aggregated += saved_skb_len;

                /*
                 * v69 关键修复: 移除 seq_offset != 0 检查
                 *
                 * 问题: seq_offset 可能在极端情况下为 0 (ISN_pep == ISN_server)
                 *       但 flow 仍然是 spoofed 的，需要发送 advance ACK
                 *
                 * 解决: 只检查 SPOOFED_BIT，translate 函数会正确处理 seq_offset == 0
                 */
                if (test_bit(PEP_FLOW_F_SPOOFED_BIT, &flow->flags)) {
                    /* 更新 WAN 接收序列跟踪（服务器空间） */
                    if (PEP_SEQ_AFTER(saved_server_seq_end, flow->wan.seq_next)) {
                        flow->wan.seq_next = saved_server_seq_end;
                    }

                    /* 调度 Advance ACK 给服务器 */
                    if (pep_ctx && pep_ctx->config.aggressive_ack &&
                        READ_ONCE(flow->wan_state) == PEP_WAN_ESTABLISHED) {
                        pep_schedule_advance_ack(flow, flow->wan.seq_next, saved_payload_len);
                    }
                }

                pep_gro_timer_start(flow);
                pep_flow_put(flow);
                return NF_STOLEN;
            } else if (IS_ERR(gro_result)) {

                pr_debug("pep: GRO failed for flow %pI4:%u\n",
                         &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));
            } else if (gro_result != skb) {
                /*
                 * v63 关键修复: 不要重新入队原始 skb
                 */
                skb = gro_result;

                iph = ip_hdr(skb);
                ip_hdr_len = iph->ihl * 4;
                tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

                pr_debug("pep: GRO flushed aggregated packet, size=%u\n", skb->len);

                pep_gro_timer_start(flow);
            }
        }

        /*
         * v63.8: GRO 超时刷新使用定时器 + 工作队列上下文，避免在 netfilter hook 内递归。
         */
    }

    {
        unsigned int server_payload = 0;

        iph = ip_hdr(skb);
        ip_hdr_len = iph->ihl * 4;
        tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

        if (is_server_to_client) {
            server_payload = ntohs(iph->tot_len) - ip_hdr_len - (tcph->doff * 4);
        }

        if (flow->fec.enabled && server_payload > 0) {

            goto skip_fastpath_pre_routing;
        }
    }

    if (pep_check_fastpath(ctx, flow, tcph)) {

        /*
         * v70 关键修复: 移除 seq_offset != 0 检查 (fastpath)
         *
         * 问题: seq_offset 可能在极端情况下为 0 (ISN_pep == ISN_server)
         *       但 flow 仍然是 spoofed 的，需要完整的 SEQ/ACK 翻译
         *
         * 解决: 只检查 SPOOFED_BIT，translate 函数会正确处理 seq_offset == 0
         */
        if (ctx->config.tcp_spoofing && test_bit(PEP_FLOW_F_SPOOFED_BIT, &flow->flags) &&
            is_server_to_client) {
            bool ecn_active = ctx->config.ecn_enabled &&
                              test_bit(PEP_FLOW_F_ECN_BIT, &flow->flags);

            if (ecn_active && pep_is_ecn_ce(iph)) {
                u32 ce_seq = ntohl(tcph->seq);
                set_bit(PEP_FLOW_F_ECN_CE_SEEN_BIT, &flow->flags);
                flow->ecn_ece_pending = 1;
                if (pep_cc_on_ecn_ce(&flow->cc, ce_seq)) {
                    if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                        pr_info_ratelimited("pep: ECN CE detected (fastpath) from %pI4\n",
                                            &iph->saddr);
                    }
                }
            }

            pep_set_conntrack_liberal(skb);
            if (pep_translate_seq_wan_to_lan(flow, skb) < 0) {
                pep_warn("Fast Path: Failed to translate SEQ\n");

                flow->rx_packets++;
                flow->rx_bytes += skb->len;
                pep_flow_put(flow);
                return NF_ACCEPT;
            }

            iph = ip_hdr(skb);
            ip_hdr_len = iph->ihl * 4;
            tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

            if (ecn_active && tcph->cwr)
                flow->ecn_ece_pending = 0;

            u32 fp_wan_ack_seq = 0;
            if (tcph->ack && READ_ONCE(flow->wan_state) != PEP_WAN_CLOSED) {

                fp_wan_ack_seq = ntohl(tcph->ack_seq);

                if (READ_ONCE(flow->wan_state) == PEP_WAN_ESTABLISHED) {

                    u32 fp_isn_base = flow->isn_pep_wan + 1;
                    u32 fp_max_sent = flow->wan_snd_nxt;
                    bool fp_ack_valid = true;

                    if (PEP_SEQ_BEFORE(fp_wan_ack_seq, fp_isn_base)) {
                        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                            pr_info_ratelimited("pep: FP STALE ACK port=%u: ack=%u < isn_base=%u\n",
                                    ntohs(flow->tuple.src_port), fp_wan_ack_seq, fp_isn_base);
                        }
                        fp_ack_valid = false;
                    } else if (fp_max_sent != 0 && PEP_SEQ_AFTER(fp_wan_ack_seq, fp_max_sent + 65536)) {
                        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                            pr_info_ratelimited("pep: FP FUTURE ACK port=%u: ack=%u >> max=%u\n",
                                    ntohs(flow->tuple.src_port), fp_wan_ack_seq, fp_max_sent);
                        }
                        fp_ack_valid = false;
                    }

                    if (fp_ack_valid) {
                        if (ecn_active && tcph->ece) {
                            set_bit(PEP_FLOW_F_ECN_CE_SEEN_BIT, &flow->flags);
                            pep_cc_on_ecn_ce(&flow->cc, fp_wan_ack_seq);
                        }
                        pep_rtt_probe_on_ack(flow, fp_wan_ack_seq);
                        u32 acked = pep_retrans_ack_received(flow, fp_wan_ack_seq);

                        pep_cc_ecn_cwr_acked(&flow->cc, fp_wan_ack_seq);

                        /* v74: 减少 FP RTX 日志输出频率 (debug_level >= 2) */
                        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                            pr_info_ratelimited("pep: v31 FP RTX port=%u: wan_ack=%u acked=%u in_flight=%u\n",
                                    ntohs(flow->tuple.src_port),
                                    fp_wan_ack_seq, acked, flow->cc.bytes_in_flight);
                        }

                        pep_tlp_on_ack(flow, fp_wan_ack_seq);

                        if (acked > 0) {
                            flow->wan_snd_una = fp_wan_ack_seq;
                            pep_rack_detect_loss(flow);
                            pep_schedule_wan_tx(flow);
                        }

                        if (tcph->doff > 5) {
                            unsigned int tcp_hdr_len_full = tcph->doff * 4;
                            if (pskb_may_pull(skb, ip_hdr_len + tcp_hdr_len_full)) {
                                struct pep_tcp_options opts;

                                iph = ip_hdr(skb);
                                tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
                                memset(&opts, 0, sizeof(opts));
                                pep_parse_tcp_options(tcph, &opts);
                                pep_retrans_process_sack(flow, &opts, fp_wan_ack_seq);
                            }
                        }
                    }
                }

                if (pep_translate_ack_wan_to_client(flow, skb) < 0) {
                    pep_warn("Fast Path: Failed to translate ACK\n");
                }

                iph = ip_hdr(skb);
                ip_hdr_len = iph->ihl * 4;
                tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
            }

            unsigned int fp_payload = ntohs(iph->tot_len) - ip_hdr_len - (tcph->doff * 4);
            if (fp_payload == 0 && tcph->ack && !tcph->syn && !tcph->fin && !tcph->rst) {

                int fp_ret = pep_spoofing_handle_data(ctx, flow, skb, PEP_DIR_WAN_TO_LAN);
                pep_stats_inc_acks_filtered();

                if (fp_ret == 0) {

                    flow->rx_packets++;
                    flow->rx_bytes += skb->len;
                    pep_flow_put(flow);
                    kfree_skb(skb);
                    return NF_STOLEN;
                }

            }

            {
                unsigned int fp_skb_len = skb->len;
                int fp_data_ret = pep_spoofing_handle_data(ctx, flow, skb, PEP_DIR_WAN_TO_LAN);
                if (fp_data_ret == 1) {
                    flow->rx_packets++;
                    flow->rx_bytes += fp_skb_len;
                    pep_flow_put(flow);
                    return NF_STOLEN;
                }
            }
        }

        flow->rx_packets++;
        flow->rx_bytes += skb->len;
        pep_flow_put(flow);
        return NF_ACCEPT;
    }

skip_fastpath_pre_routing:

    if (ctx->config.tcp_spoofing && test_bit(PEP_FLOW_F_SPOOFED_BIT, &flow->flags) && is_server_to_client) {
        bool ecn_active = ctx->config.ecn_enabled &&
                          test_bit(PEP_FLOW_F_ECN_BIT, &flow->flags);

        pep_set_conntrack_liberal(skb);

        if (tcph->syn && tcph->ack) {
            pep_spoofing_handle_synack(ctx, flow, skb);

            if (flow->seq_offset != 0) {
                if (pep_translate_seq_wan_to_lan(flow, skb) < 0) {
                    pep_warn("Failed to translate SYN-ACK SEQ\n");
                }
            }

            iph = ip_hdr(skb);
            ip_hdr_len = iph->ihl * 4;
            tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

            if (ecn_active && tcph->cwr)
                flow->ecn_ece_pending = 0;

            pep_update_flow_state(flow, tcph, PEP_DIR_WAN_TO_LAN);
            flow->rx_packets++;
            flow->rx_bytes += skb->len;
            pep_flow_put(flow);
            kfree_skb(skb);
            return NF_STOLEN;
        }

        u32 wan_ack_seq = 0;
        /*
         * v70 关键修复: 移除 seq_offset != 0 检查 (non-fastpath)
         *
         * 问题: seq_offset 可能在极端情况下为 0 (ISN_pep == ISN_server)
         *       但 flow 仍然是 spoofed 的，需要完整的处理:
         *       - SEQ/ACK 翻译
         *       - ACK 确认处理
         *       - FEC 解码
         *       - 数据投递
         *
         * 解决: 只检查是否为 SYN-ACK (SYN-ACK 在上面单独处理)
         *       translate 函数会正确处理 seq_offset == 0 的情况
         */
        if (!(tcph->syn && tcph->ack)) {
            unsigned int server_payload = ntohs(iph->tot_len) - ip_hdr_len - (tcph->doff * 4);

            if (tcph->ack) {
                wan_ack_seq = ntohl(tcph->ack_seq);

                if (READ_ONCE(flow->wan_state) == PEP_WAN_ESTABLISHED) {

                    u32 isn_base = flow->isn_pep_wan + 1;
                    u32 max_sent = flow->wan_snd_nxt;
                    bool ack_valid = true;

                    if (PEP_SEQ_BEFORE(wan_ack_seq, isn_base)) {

                        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                            pr_info_ratelimited("pep: STALE ACK port=%u: ack=%u < isn_base=%u, isn_wan=%u, skipping RTX\n",
                                    ntohs(flow->tuple.src_port),
                                    wan_ack_seq, isn_base, flow->isn_pep_wan);
                        }
                        ack_valid = false;
                    }

                    else if (max_sent != 0 && PEP_SEQ_AFTER(wan_ack_seq, max_sent + 65536)) {

                        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                            pr_info_ratelimited("pep: FUTURE ACK port=%u: ack=%u >> max_sent=%u, isn_wan=%u, skipping RTX\n",
                                    ntohs(flow->tuple.src_port),
                                    wan_ack_seq, max_sent, flow->isn_pep_wan);
                        }
                        ack_valid = false;
                    }

                    if (ack_valid) {
                        if (ecn_active && tcph->ece) {
                            set_bit(PEP_FLOW_F_ECN_CE_SEEN_BIT, &flow->flags);
                            pep_cc_on_ecn_ce(&flow->cc, wan_ack_seq);
                        }
                        pep_rtt_probe_on_ack(flow, wan_ack_seq);
                        u32 acked = pep_retrans_ack_received(flow, wan_ack_seq);

                        pep_cc_ecn_cwr_acked(&flow->cc, wan_ack_seq);

                        /* v74: 减少 RTX 日志输出频率 (debug_level >= 2) */
                        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                            pr_info_ratelimited("pep: v31 RTX port=%u: wan_ack=%u acked=%u in_flight=%u rtx_bytes=%u state=%d wan_state=%d\n",
                                    ntohs(flow->tuple.src_port),
                                    wan_ack_seq, acked, flow->cc.bytes_in_flight,
                                    flow->rtx_bytes, flow->state, flow->wan_state);
                        }

                        pep_tlp_on_ack(flow, wan_ack_seq);

                        if (acked > 0) {

                            flow->wan_snd_una = wan_ack_seq;

                            pep_rack_detect_loss(flow);

                            pep_schedule_wan_tx(flow);
                        }

                        if (tcph->doff > 5) {
                            unsigned int tcp_hdr_len_full = tcph->doff * 4;
                            if (pskb_may_pull(skb, ip_hdr_len + tcp_hdr_len_full)) {
                                struct pep_tcp_options opts;

                                iph = ip_hdr(skb);
                                tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
                                memset(&opts, 0, sizeof(opts));
                                pep_parse_tcp_options(tcph, &opts);
                                pep_retrans_process_sack(flow, &opts, wan_ack_seq);
                            }
                        }
                    }
                }
            }

            if (pep_ctx && pep_ctx->config.debug_level >= 2 &&
                (server_payload > 0 || tcph->fin || tcph->rst)) {
                pr_info_ratelimited("pep: PRE_ROUTING server->client: %pI4:%u -> %pI4:%u seq=%u->%u flags=%c%c%c len=%u\n",
                                    &tuple.src_addr, ntohs(tuple.src_port),
                                    &tuple.dst_addr, ntohs(tuple.dst_port),
                                    ntohl(tcph->seq), ntohl(tcph->seq) + flow->seq_offset,
                                    tcph->fin ? 'F' : '-',
                                    tcph->rst ? 'R' : '-',
                                    tcph->psh ? 'P' : '-',
                                    server_payload);
            }

            if (flow->fec.enabled && server_payload > 0) {
                if (pep_fec_is_fec_packet(skb)) {

                    unsigned char *payload_ptr = (unsigned char *)tcph + (tcph->doff * 4);
                    struct pep_fec_header *fec_hdr = (struct pep_fec_header *)payload_ptr;

                    int fec_ret = pep_fec_decoder_add_packet(flow, skb,
                                                              fec_hdr->block_id,
                                                              fec_hdr->pkt_idx,
                                                              true);

                    if (fec_ret == 1) {

                        struct sk_buff *recovered_skb;

                        while ((recovered_skb = pep_fec_decoder_try_recover(flow)) != NULL) {

                            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                                pr_info("pep: FEC recovered packet, injecting to data path\n");
                            }

                            if (pep_translate_seq_wan_to_lan(flow, recovered_skb) == 0) {

                                recovered_skb->mark = PEP_SKB_MARK;
                                netif_receive_skb(recovered_skb);
                            } else {
                                kfree_skb(recovered_skb);
                            }
                        }
                    }

                    /* v109: save len before kfree to avoid use-after-free */
                    {
                        u32 saved_len = skb->len;
                        kfree_skb(skb);
                        flow->rx_packets++;
                        flow->rx_bytes += saved_len;
                    }
                    pep_flow_put(flow);
                    return NF_STOLEN;
                } else {

                    u32 seq = ntohl(tcph->seq);
                    int fec_ret = pep_fec_process_data_packet(flow, skb, seq);

                    if (fec_ret == 1) {

                        struct sk_buff *recovered_skb;

                        while ((recovered_skb = pep_fec_decoder_try_recover(flow)) != NULL) {
                            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                                pr_info("pep: FEC recovered data packet from normal packet completion\n");
                            }

                            if (pep_translate_seq_wan_to_lan(flow, recovered_skb) == 0) {
                                recovered_skb->mark = PEP_SKB_MARK;
                                netif_receive_skb(recovered_skb);
                            } else {
                                kfree_skb(recovered_skb);
                            }
                        }
                    }

                }
            }

            if (pep_translate_seq_wan_to_lan(flow, skb) < 0) {
                pep_warn("Failed to translate SEQ for WAN->LAN packet\n");
            }

            iph = ip_hdr(skb);
            ip_hdr_len = iph->ihl * 4;
            tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

            if (tcph->ack && READ_ONCE(flow->wan_state) != PEP_WAN_CLOSED) {
                if (pep_translate_ack_wan_to_client(flow, skb) < 0) {
                    pep_warn("Failed to translate ACK for WAN->LAN packet\n");
                }

                iph = ip_hdr(skb);
                ip_hdr_len = iph->ihl * 4;
                tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
            }
        }

        if (flow->state == PEP_TCP_ESTABLISHED ||
            flow->state == PEP_TCP_FIN_WAIT_1 ||
            flow->state == PEP_TCP_FIN_WAIT_2 ||
            flow->state == PEP_TCP_CLOSING) {
            unsigned int server_payload = ntohs(iph->tot_len) - ip_hdr_len - (tcph->doff * 4);
            int ret;

            if (ecn_active && pep_is_ecn_ce(iph)) {
                u32 seq = ntohl(tcph->seq);
                set_bit(PEP_FLOW_F_ECN_CE_SEEN_BIT, &flow->flags);
                flow->ecn_ece_pending = 1;
                if (pep_cc_on_ecn_ce(&flow->cc, seq)) {
                    if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                        pr_info_ratelimited("pep: ECN CE detected from %pI4, cwnd reduced\n",
                                            &iph->saddr);
                    }
                }
            }

            if (server_payload == 0 && tcph->ack &&
                !tcph->syn && !tcph->fin && !tcph->rst) {

                if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                    pr_info_ratelimited("pep: PRE_ROUTING pure ACK: %pI4:%u -> %pI4:%u ack_seq=%u "
                                        "in_flight=%u rtx_bytes=%u\n",
                                        &tuple.src_addr, ntohs(tuple.src_port),
                                        &tuple.dst_addr, ntohs(tuple.dst_port),
                                        ntohl(tcph->ack_seq),
                                        flow->cc.bytes_in_flight, flow->rtx_bytes);
                }

                ret = pep_spoofing_handle_data(ctx, flow, skb, PEP_DIR_WAN_TO_LAN);

                pep_stats_inc_acks_filtered();

                if (ret == 0) {

                    pep_update_flow_state(flow, tcph, PEP_DIR_WAN_TO_LAN);
                    flow->rx_packets++;
                    flow->rx_bytes += skb->len;
                    pep_flow_put(flow);
                    kfree_skb(skb);
                    return NF_STOLEN;
                }

            } else if (server_payload > 0) {
                unsigned int sp_skb_len = skb->len;
                int data_ret = pep_spoofing_handle_data(ctx, flow, skb, PEP_DIR_WAN_TO_LAN);
                if (data_ret == 1) {
                    /* Note: skb may be freed by split_dl path, don't access it */
                    flow->rx_packets++;
                    flow->rx_bytes += sp_skb_len;
                    pep_flow_put(flow);
                    return NF_STOLEN;
                }
            }
        } else {

            unsigned int server_payload = ntohs(iph->tot_len) - ip_hdr_len - (tcph->doff * 4);
            if (server_payload == 0 && tcph->ack && !tcph->syn && !tcph->fin && !tcph->rst) {

                if (flow->state != PEP_TCP_CLOSE_WAIT &&
                    flow->state != PEP_TCP_LAST_ACK &&
                    flow->state != PEP_TCP_TIME_WAIT) {
                    if (pep_ctx && pep_ctx->config.debug_level >= 1) {
                        pr_info_ratelimited("pep: PRE_ROUTING ACK in unexpected state: %pI4:%u -> %pI4:%u "
                                            "state=%d ack_seq=%u\n",
                                            &tuple.src_addr, ntohs(tuple.src_port),
                                            &tuple.dst_addr, ntohs(tuple.dst_port),
                                            flow->state, ntohl(tcph->ack_seq));
                    }
                }
            }
        }
    }

    /*
     * v89/v101/v105: 处理服务器 FIN - 更新 WAN 侧状态
     *
     * 当服务器发送 FIN（响应我们发送的 WAN FIN）时，
     * 更新 wan_state 为 TIME_WAIT，等待处理重传和延迟包
     *
     * Split-TCP 完整连接终止流程:
     * 1. Client FIN → PEP → (v89) WAN FIN → Server
     * 2. Server FIN-ACK → PEP → (translate) → Client
     * 3. WAN state: FIN_WAIT → TIME_WAIT (v105: 不再直接CLOSED)
     *
     * v101 关键修复: 发送 ACK 确认服务器的 FIN
     *
     * 问题: 之前只设置 wan_state=CLOSED，但不发送 ACK 给服务器
     *       导致服务器不断重传 FIN，最终连接超时
     *       浏览器显示 NS_BINDING_ABORTED 错误
     *
     * v105 关键修复: 使用 TIME_WAIT 而非直接 CLOSED
     *
     * 问题: 直接设为 CLOSED 导致后续服务器 FIN 重传无法处理
     *       wan_state=0 时很多代码路径跳过处理，导致浏览器卡住
     *
     * 解决: 收到服务器 FIN 时，进入 TIME_WAIT 状态
     *       TIME_WAIT 状态仍允许处理 FIN 重传和发送 ACK
     */
    if (tcph->fin && (READ_ONCE(flow->wan_state) == PEP_WAN_FIN_WAIT ||
                      READ_ONCE(flow->wan_state) == PEP_WAN_TIME_WAIT)) {
        u32 server_fin_seq = ntohl(tcph->seq);
        u32 server_payload = ntohs(iph->tot_len) - ip_hdr_len - (tcph->doff * 4);
        u32 ack_seq = server_fin_seq + server_payload + 1;  /* +1 for FIN */

        /* v109: rate-limit FIN retransmit log */
        pr_info_ratelimited("pep: PRE_ROUTING server FIN retransmit: port=%u state=%d wan_state=%d\n",
                ntohs(flow->tuple.src_port), flow->state, flow->wan_state);

        /* v101: 更新 wan.seq_next 以便后续 ACK 正确 */
        if (PEP_SEQ_AFTER(ack_seq, flow->wan.seq_next)) {
            flow->wan.seq_next = ack_seq;
        }

        /* v101: 发送 ACK 给服务器确认 FIN - 这是关键修复! */
        pep_schedule_advance_ack(flow, ack_seq, 1);

        /* v105: 进入 TIME_WAIT 而非直接 CLOSED */
        if (READ_ONCE(flow->wan_state) == PEP_WAN_FIN_WAIT) {
            WRITE_ONCE(flow->wan_state, PEP_WAN_TIME_WAIT);
            if (pep_ctx && pep_ctx->config.debug_level >= 1) {
                pr_info("pep: v105 Server FIN ACKed, wan_state FIN_WAIT -> TIME_WAIT for %pI4:%u\n",
                        &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));
            }
        }
    }

    /*
     * v92/v105: 处理服务器主动关闭（Server-initiated close）
     *
     * 当服务器主动发送 FIN 时（wan_state == ESTABLISHED 或 CLOSE_WAIT）：
     * 1. PEP 发送 ACK 给服务器确认收到 FIN
     * 2. 服务器的 FIN 会被转发给客户端（由内核处理）
     * 3. 当客户端发送 FIN 时，PEP 需要转发给服务器
     *
     * v105: 也处理 CLOSE_WAIT 状态下的 FIN 重传
     *       服务器可能重传 FIN，需要继续发送 ACK
     */
    if (tcph->fin && (READ_ONCE(flow->wan_state) == PEP_WAN_ESTABLISHED ||
                      READ_ONCE(flow->wan_state) == PEP_WAN_CLOSE_WAIT)) {
        /*
         * 服务器主动关闭：发送 ACK 确认收到 FIN
         * FIN 消耗一个序列号，所以 ACK = seq + 1
         */
        u32 server_fin_seq = ntohl(tcph->seq);
        u32 server_payload = ntohs(iph->tot_len) - ip_hdr_len - (tcph->doff * 4);
        u32 ack_seq = server_fin_seq + server_payload + 1;  /* +1 for FIN */

        /* 更新 wan.seq_next 以便后续 ACK 正确 */
        if (PEP_SEQ_AFTER(ack_seq, flow->wan.seq_next)) {
            flow->wan.seq_next = ack_seq;
        }

        /* 发送 ACK 给服务器确认 FIN */
        pep_schedule_advance_ack(flow, ack_seq, 1);

        /* 更新 WAN 状态为 CLOSE_WAIT (被动关闭) - 仅首次 */
        if (READ_ONCE(flow->wan_state) == PEP_WAN_ESTABLISHED) {
            WRITE_ONCE(flow->wan_state, PEP_WAN_CLOSE_WAIT);
            if (pep_ctx && pep_ctx->config.debug_level >= 1) {
                pr_info("pep: v92 Server initiated close, FIN seq=%u, ACK scheduled, wan_state -> CLOSE_WAIT for %pI4:%u\n",
                        server_fin_seq, &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port));
            }
        }
    }

    /* v109: FIN diagnostics only at debug_level >= 3 */
    if (tcph->fin && pep_ctx && pep_ctx->config.debug_level >= 3) {
        pr_info_ratelimited("pep: PRE_ROUTING FIN: port=%u state=%d wan_state=%d\n",
                ntohs(flow->tuple.src_port), flow->state, flow->wan_state);
    }

    pep_update_flow_state(flow, tcph, PEP_DIR_WAN_TO_LAN);

    /* v97 diagnostic removed — covered by above */

    flow->rx_packets++;
    flow->rx_bytes += skb->len;

    pep_flow_put(flow);

    return NF_ACCEPT;
}

/*
 * 功能/Main: 处理Netfilter 报文路径（Handle Netfilter packet path）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；分片重组/重排处理（fragment reassembly）；流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；重传/缓存处理（retransmission/cache）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: priv, skb, state
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
static unsigned int pep_nf_post_routing(void *priv,
                                         struct sk_buff *skb,
                                         const struct nf_hook_state *state)
{
    struct pep_context *ctx = priv;
    struct pep_tuple tuple;
    struct pep_flow *flow;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len;
    unsigned int payload_len;

    if (pep_ctx && pep_ctx->config.debug_level >= 3) {
        static unsigned long last_print_jiffies;
        static int entry_count;
        entry_count++;
        if (time_after(jiffies, last_print_jiffies + HZ)) {
            pr_info("pep: v51 POST_ROUTING CALLED: entries=%d in last second, out=%s\n",
                    entry_count, state->out ? state->out->name : "NULL");
            entry_count = 0;
            last_print_jiffies = jiffies;
        }
    }

    if (pep_ctx && pep_ctx->config.debug_level >= 3 &&
        skb && pskb_may_pull(skb, sizeof(struct iphdr))) {
        struct iphdr *diag_iph = ip_hdr(skb);
        if (diag_iph->protocol == IPPROTO_TCP) {
            unsigned int diag_ip_hdr_len = diag_iph->ihl * 4;
            if (pskb_may_pull(skb, diag_ip_hdr_len + sizeof(struct tcphdr))) {
                struct tcphdr *diag_tcph = (struct tcphdr *)((unsigned char *)diag_iph + diag_ip_hdr_len);
                unsigned int diag_plen = ntohs(diag_iph->tot_len) - diag_ip_hdr_len - (diag_tcph->doff * 4);

                if (ntohs(diag_tcph->source) != 22 && ntohs(diag_tcph->dest) != 22 && diag_plen > 0) {
                    pr_info_ratelimited("pep: v49 POST_ROUTING ENTRY: %pI4:%u -> %pI4:%u len=%u mark=0x%x\n",
                            &diag_iph->saddr, ntohs(diag_tcph->source),
                            &diag_iph->daddr, ntohs(diag_tcph->dest),
                            diag_plen, skb->mark);
                }
            }
        }
    }

    if (!ctx || !atomic_read(&ctx->running))
        return NF_ACCEPT;

    if (!ctx->config.enabled)
        return NF_ACCEPT;

    if (!pep_match_wan_out(ctx, state))
        return NF_ACCEPT;
    if (!pep_match_lan_in(ctx, state))
        return NF_ACCEPT;

    if (skb->mark == PEP_SKB_MARK ||
        skb->mark == PEP_SKB_MARK_FAKE_ACK ||
        skb->mark == PEP_SKB_MARK_RETRANS)
        return NF_ACCEPT;

    skb = pep_ip_defrag_if_needed(ctx, skb, IP_DEFRAG_CONNTRACK_OUT);
    if (!skb)
        return NF_STOLEN;

    if (!pep_extract_tuple(skb, &tuple))
        return NF_ACCEPT;

    if (pep_ctx && pep_ctx->config.debug_level >= 2) {
        iph = ip_hdr(skb);
        ip_hdr_len = iph->ihl * 4;
        tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
        if (ntohs(tcph->source) != 22 && ntohs(tcph->dest) != 22) {
            unsigned int plen = ntohs(iph->tot_len) - ip_hdr_len - (tcph->doff * 4);

            if (tcph->syn || tcph->fin || tcph->rst || plen > 0) {
                pr_info_ratelimited("pep: POST_ROUTING raw: %pI4:%u -> %pI4:%u flags=%c%c%c%c len=%u\n",
                        &tuple.src_addr, ntohs(tuple.src_port),
                        &tuple.dst_addr, ntohs(tuple.dst_port),
                        tcph->syn ? 'S' : '-', tcph->ack ? 'A' : '-',
                        tcph->fin ? 'F' : '-', tcph->rst ? 'R' : '-',
                        plen);
            }
        }
    }

    if (!pep_should_process(ctx, &tuple))
        return NF_ACCEPT;

    pep_stats_inc_tx(skb->len);

    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
    payload_len = ntohs(iph->tot_len) - ip_hdr_len - (tcph->doff * 4);

    if (tcph->syn && !tcph->ack) {
        if (pep_syn_fail_open_active(ctx)) {
            pep_stats_inc_wan_syn_bypass();
            if (pep_ctx && pep_ctx->config.debug_level >= 1) {
                pr_info_ratelimited("pep: WAN SYN fail-open active, bypass spoofing for %pI4:%u -> %pI4:%u\n",
                        &tuple.src_addr, ntohs(tuple.src_port),
                        &tuple.dst_addr, ntohs(tuple.dst_port));
            }
            return NF_ACCEPT;
        }
        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
            pr_info("pep: POST_ROUTING SYN: %pI4:%u -> %pI4:%u\n",
                    &tuple.src_addr, ntohs(tuple.src_port),
                    &tuple.dst_addr, ntohs(tuple.dst_port));
        }
        flow = pep_handle_syn(ctx, skb, &tuple);
        if (flow) {

            if (ctx->config.tcp_spoofing) {
                pep_spoofing_handle_syn(ctx, flow, skb, PEP_DIR_LAN_TO_WAN, state->out);

                flow->state = PEP_TCP_SYN_RECV;

                pep_set_conntrack_liberal(skb);

                if (pep_wan_syn_rewrite(flow, skb) == 0) {
                    pep_flow_put(flow);
                    return NF_ACCEPT;
                }

                if (pep_wan_syn_send(flow, skb) < 0) {
                    pep_warn("Complete Split-TCP: Failed to send WAN SYN\n");
                    pep_stats_inc_wan_syn_fail_open();
                    if (ctx->config.wan_syn_fail_open_ms > 0) {
                        WRITE_ONCE(ctx->syn_fail_open_until_ns,
                                   ktime_get_ns() +
                                   (u64)ctx->config.wan_syn_fail_open_ms * NSEC_PER_MSEC);
                    }

                    pep_flow_put(flow);
                    return NF_ACCEPT;
                }

                pep_flow_put(flow);
                return NF_DROP;
            }
            pep_flow_put(flow);
        }
        return NF_ACCEPT;
    }

    flow = pep_flow_find(&ctx->flow_table, &tuple);
    if (!flow) {

        if (payload_len > 0 && ctx->config.debug_level >= 2) {
            pr_info_ratelimited("pep: POST_ROUTING: FLOW NOT FOUND for data! "
                    "src=%pI4:%u dst=%pI4:%u payload=%u\n",
                    &tuple.src_addr, ntohs(tuple.src_port),
                    &tuple.dst_addr, ntohs(tuple.dst_port), payload_len);
        }
        return NF_ACCEPT;
    }

    pep_flow_update_activity(flow);

    if (ctx->config.local_retrans && payload_len == 0 && tcph->ack) {
        if (!skb->sk)
            pep_lan_retrans_on_ack(flow, ntohl(tcph->ack_seq));
    }

    if (pep_check_fastpath(ctx, flow, tcph)) {

        if (ctx->config.tcp_spoofing && test_bit(PEP_FLOW_F_SPOOFED_BIT, &flow->flags)) {
            pep_set_conntrack_liberal(skb);

            if (flow->seq_offset != 0) {

                if (payload_len > 0 && ctx->config.fake_ack) {
                    if (pep_spoofing_handle_data(ctx, flow, skb, PEP_DIR_LAN_TO_WAN) == 0) {

                        flow->tx_packets++;
                        flow->tx_bytes += skb->len;
                        pep_flow_put(flow);
                        kfree_skb(skb);
                        return NF_STOLEN;
                    }

                    pep_flow_put(flow);
                    return NF_DROP;
                }

            } else if (payload_len > 0 && ctx->config.fake_ack) {

                if (READ_ONCE(flow->wan_state) != PEP_WAN_CLOSED) {
                    /*
                     * v110: Zero-copy upload fast path for seq_offset==0.
                     *
                     * When seq_offset==0 (single-interface mode), the client's
                     * packet needs no seq/ack translation. Instead of copying
                     * the skb into a queue and forwarding via WAN TX worker,
                     * send a fake ACK directly and let the original packet
                     * pass through (NF_ACCEPT). This eliminates:
                     * - skb_copy overhead (~20% CPU per packet)
                     * - queue/dequeue latency
                     * - WAN TX worker scheduling delay
                     *
                     * The client's own TCP stack handles pacing, congestion
                     * control, and retransmission. PEP just accelerates the
                     * client's cwnd growth via immediate fake ACKs.
                     */
                    u32 ul_seq = ntohl(tcph->seq);
                    u32 ul_ack_seq = ul_seq + payload_len;

                    if (PEP_SEQ_AFTER(ul_ack_seq, flow->lan.ack_seq))
                        flow->lan.ack_seq = ul_ack_seq;

                    {
                        struct sk_buff *ack_skb;
                        u32 pep_seq = flow->isn_pep + 1;

                        ack_skb = pep_create_fake_ack(flow, pep_seq, ul_ack_seq);
                        if (ack_skb) {
                            if (pep_send_lan_skb(flow, ack_skb) == 0) {
                                pep_stats_inc_fake_ack();
                                flow->fake_acks_sent++;
                            }
                        }
                    }

                    flow->tx_packets++;
                    flow->tx_bytes += skb->len;
                    pep_flow_put(flow);
                    return NF_ACCEPT;
                }

                pr_info_ratelimited("pep: Fast Path: DATA before WAN SYN sent, DROP\n");
                pep_flow_put(flow);
                return NF_DROP;
            }

            /*
             * Split DL: filter client pure ACKs for spoofed flows.
             * PEP sends advance ACKs to server; client ACKs carry
             * client-space SEQ/ACK which are wrong for server anyway.
             */
            if (ctx->config.split_dl_enabled && payload_len == 0 &&
                tcph->ack && !tcph->fin && !tcph->rst && !tcph->syn) {
                pep_flow_put(flow);
                kfree_skb(skb);
                return NF_STOLEN;
            }
        }

        flow->tx_packets++;
        flow->tx_bytes += skb->len;
        pep_flow_put(flow);
        return NF_ACCEPT;
    }

    if (payload_len > 0 && ctx->config.debug_level >= 2) {
        pr_info_ratelimited("pep: POST_ROUTING DATA: port=%u tcp_spoof=%u SPOOFED=%d flags=0x%lx payload=%u\n",
                ntohs(tuple.src_port), ctx->config.tcp_spoofing,
                test_bit(PEP_FLOW_F_SPOOFED_BIT, &flow->flags),
                flow->flags, payload_len);
    }

    if (ctx->config.tcp_spoofing && test_bit(PEP_FLOW_F_SPOOFED_BIT, &flow->flags)) {

        pep_set_conntrack_liberal(skb);

        if (tcph->rst) {
            flow->state = PEP_TCP_CLOSED;

            set_bit(PEP_FLOW_F_DEAD_BIT, &flow->flags);
            pep_dbg("Spoofing: RST received from client, closing flow\n");
            goto out_accept;
        }

        if (flow->state == PEP_TCP_SYN_RECV && flow->isn_server == 0) {

            pep_dbg("Spoofing: ACK arrived before server SYN-ACK, waiting...\n");
            pep_flow_put(flow);
            return NF_DROP;
        }

        if (flow->state == PEP_TCP_SYN_RECV && tcph->ack && !tcph->syn) {
            flow->state = PEP_TCP_ESTABLISHED;
            set_bit(PEP_FLOW_F_ACCELERATED_BIT, &flow->flags);
            set_bit(PEP_FLOW_F_ESTABLISHED_BIT, &flow->flags);
            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                pr_info("pep: Connection ESTABLISHED %pI4:%u -> %pI4:%u "
                        "(isn_pep=%u isn_server=%u offset=%d)\n",
                        &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
                        &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port),
                        flow->isn_pep, flow->isn_server, flow->seq_offset);
            }
        }

        s32 seq_off = READ_ONCE(flow->seq_offset);

        if (payload_len > 0 && pep_ctx && pep_ctx->config.debug_level >= 2) {
            pr_info_ratelimited("pep: POST_ROUTING DATA DIAG port=%u: "
                    "payload=%u seq_off=%d fake_ack=%u state=%d wan_state=%d flags=0x%lx\n",
                    ntohs(tuple.src_port), payload_len, seq_off,
                    ctx->config.fake_ack, flow->state, flow->wan_state, flow->flags);
        }

        if (payload_len > 0 && seq_off != 0 && ctx->config.fake_ack) {

            if (flow->state == PEP_TCP_SYN_RECV) {
                flow->state = PEP_TCP_ESTABLISHED;
                set_bit(PEP_FLOW_F_ACCELERATED_BIT, &flow->flags);
                set_bit(PEP_FLOW_F_ESTABLISHED_BIT, &flow->flags);
                pep_dbg("POST_ROUTING: state updated to ESTABLISHED (by DATA packet)\n");
            }

            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                pr_info("pep: POST_ROUTING data: %pI4:%u -> %pI4:%u seq=%u len=%u state=%d\n",
                        &tuple.src_addr, ntohs(tuple.src_port),
                        &tuple.dst_addr, ntohs(tuple.dst_port),
                        ntohl(tcph->seq), payload_len, flow->state);
            }

            if (pep_spoofing_handle_data(ctx, flow, skb, PEP_DIR_LAN_TO_WAN) == 0) {

                pep_dbg("POST_ROUTING NF_STOLEN: seq=%u len=%u\n",
                        ntohl(tcph->seq), payload_len);
                flow->tx_packets++;
                flow->tx_bytes += skb->len;
                pep_flow_put(flow);
                kfree_skb(skb);
                return NF_STOLEN;
            }

            pr_warn_ratelimited("pep: POST_ROUTING NF_DROP (queue full): seq=%u len=%u\n",
                    ntohl(tcph->seq), payload_len);
            pep_flow_put(flow);
            return NF_DROP;
        } else if (payload_len > 0 && seq_off == 0 && ctx->config.fake_ack) {

            if (READ_ONCE(flow->wan_state) != PEP_WAN_CLOSED) {

                if (flow->state == PEP_TCP_SYN_RECV) {
                    flow->state = PEP_TCP_ESTABLISHED;
                    set_bit(PEP_FLOW_F_ACCELERATED_BIT, &flow->flags);
                    set_bit(PEP_FLOW_F_ESTABLISHED_BIT, &flow->flags);
                }

                /*
                 * v110: Zero-copy upload (slow path, seq_offset==0).
                 * Same optimization as fast path — send fake ACK and
                 * let original packet pass through.
                 */
                {
                    u32 ul_seq = ntohl(tcph->seq);
                    u32 ul_ack_seq = ul_seq + payload_len;

                    if (PEP_SEQ_AFTER(ul_ack_seq, flow->lan.ack_seq))
                        flow->lan.ack_seq = ul_ack_seq;

                    {
                        struct sk_buff *ack_skb;
                        u32 pep_seq = flow->isn_pep + 1;

                        ack_skb = pep_create_fake_ack(flow, pep_seq, ul_ack_seq);
                        if (ack_skb) {
                            if (pep_send_lan_skb(flow, ack_skb) == 0) {
                                pep_stats_inc_fake_ack();
                                flow->fake_acks_sent++;
                            }
                        }
                    }
                }

                flow->tx_packets++;
                flow->tx_bytes += skb->len;
                pep_flow_put(flow);
                return NF_ACCEPT;
            } else {

                pr_info_ratelimited("pep: POST_ROUTING DATA: wan_state=CLOSED (no WAN SYN?), "
                        "%pI4:%u -> %pI4:%u seq=%u len=%u (DROP)\\n",
                        &tuple.src_addr, ntohs(tuple.src_port),
                        &tuple.dst_addr, ntohs(tuple.dst_port),
                        ntohl(tcph->seq), payload_len);
                pep_flow_put(flow);
                return NF_DROP;
            }
        }

        /*
         * Split DL: filter client pure ACKs for spoofed flows (slow path).
         * Same logic as fast path — PEP sends advance ACKs to server.
         */
        if (ctx->config.split_dl_enabled && payload_len == 0 &&
            tcph->ack && !tcph->fin && !tcph->rst && !tcph->syn &&
            flow->state == PEP_TCP_ESTABLISHED) {
            pep_flow_put(flow);
            kfree_skb(skb);
            return NF_STOLEN;
        }

        /*
         * v102 关键修复: 同时处理 ESTABLISHED 和 CLOSE_WAIT 状态的 FIN
         *
         * 问题: 之前只处理 state == ESTABLISHED 时的客户端 FIN
         *       当服务器主动关闭时，flow->state 已经是 CLOSE_WAIT
         *       客户端发送 FIN 时，这段代码被跳过，WAN FIN 永不发送
         *       导致 WAN 侧连接挂起，服务器等待超时
         *
         * TCP 四次挥手状态转换:
         *   客户端主动关闭: ESTABLISHED → FIN_WAIT_1 (发送 FIN)
         *   服务器主动关闭: CLOSE_WAIT → LAST_ACK (发送 FIN)
         *
         * 解决: 同时检查 ESTABLISHED 和 CLOSE_WAIT 状态
         */
        if (tcph->fin && (flow->state == PEP_TCP_ESTABLISHED ||
                          flow->state == PEP_TCP_CLOSE_WAIT)) {
            if (flow->state == PEP_TCP_ESTABLISHED) {
                /* 客户端主动关闭: ESTABLISHED → FIN_WAIT_1 */
                flow->state = PEP_TCP_FIN_WAIT_1;
                pep_dbg("POST_ROUTING FIN (client-initiated): port=%u\n",
                        ntohs(flow->tuple.src_port));
            } else {
                /* 服务器主动关闭后客户端响应: CLOSE_WAIT → LAST_ACK */
                flow->state = PEP_TCP_LAST_ACK;
                pep_dbg("POST_ROUTING FIN (server-initiated response): port=%u\n",
                        ntohs(flow->tuple.src_port));
            }

            set_bit(PEP_FLOW_F_CLOSING_BIT, &flow->flags);

            /*
             * v89/v102: 向 WAN 服务器发送 FIN
             * pep_send_wan_fin() 现在支持 ESTABLISHED 和 CLOSE_WAIT 两种 wan_state
             */
            pep_send_wan_fin(flow);
            pep_dbg("POST_ROUTING FIN done: port=%u state=%d wan_state=%d\n",
                    ntohs(flow->tuple.src_port), flow->state, flow->wan_state);
        } else if (tcph->fin) {
            /* v109: rate-limit unexpected FIN log */
            pr_info_ratelimited("pep: POST_ROUTING FIN skipped: port=%u state=%d\n",
                    ntohs(flow->tuple.src_port), flow->state);
        }
    } else {
        pep_update_flow_state(flow, tcph, PEP_DIR_LAN_TO_WAN);
    }

out_accept:

    flow->tx_packets++;
    flow->tx_bytes += skb->len;

    pep_flow_put(flow);

    return NF_ACCEPT;
}

/*
 * 功能/Main: 处理Netfilter 报文路径（Handle Netfilter packet path）
 * 细节/Details: Netfilter 钩子处理（netfilter hook）
 * 输入/Inputs: 参数/Inputs: priv, skb, state
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
static unsigned int pep_nf_local_in(void *priv,
                                     struct sk_buff *skb,
                                     const struct nf_hook_state *state)
{
    return NF_ACCEPT;
}

/*
 * 功能/Main: 处理Netfilter 报文路径（Handle Netfilter packet path）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；分片重组/重排处理（fragment reassembly）；流表查找/创建/状态更新（flow lookup/create/update）；重传/缓存处理（retransmission/cache）；并发同步（spinlock/atomic/rcu）；Netfilter 钩子处理（netfilter hook）
 * 输入/Inputs: 参数/Inputs: priv, skb, state
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
static unsigned int pep_nf_local_out(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
{
    struct pep_context *ctx = priv;
    struct pep_tuple tuple;
    struct pep_flow *flow;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int ip_hdr_len;

    if (!ctx || !atomic_read(&ctx->running))
        return NF_ACCEPT;

    if (!ctx->config.enabled || !ctx->config.tcp_spoofing)
        return NF_ACCEPT;

    if (pep_iface_bound(ctx) && !pep_single_iface(ctx))
        return NF_ACCEPT;

    if (skb->mark == PEP_SKB_MARK ||
        skb->mark == PEP_SKB_MARK_FAKE_ACK ||
        skb->mark == PEP_SKB_MARK_RETRANS)
        return NF_ACCEPT;

    skb = pep_ip_defrag_if_needed(ctx, skb, IP_DEFRAG_CONNTRACK_OUT);
    if (!skb)
        return NF_STOLEN;

    if (!pep_extract_tuple(skb, &tuple))
        return NF_ACCEPT;

    if (!pep_should_process(ctx, &tuple))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

    if (tcph->syn && !tcph->ack) {
        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
            pr_info("pep: LOCAL_OUT SYN: %pI4:%u -> %pI4:%u\n",
                    &tuple.src_addr, ntohs(tuple.src_port),
                    &tuple.dst_addr, ntohs(tuple.dst_port));
        }
    }

    flow = pep_flow_find(&ctx->flow_table, &tuple);
    if (!flow) {

        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
            if (ntohs(tuple.src_port) != 22 && ntohs(tuple.dst_port) != 22) {
                if (tcph->ack && !tcph->syn) {
                    pr_info_ratelimited("pep: LOCAL_OUT no flow: %pI4:%u -> %pI4:%u ack=%u\n",
                            &tuple.src_addr, ntohs(tuple.src_port),
                            &tuple.dst_addr, ntohs(tuple.dst_port),
                            ntohl(tcph->ack_seq));
                }
            }
        }
        return NF_ACCEPT;
    }

    if (!test_bit(PEP_FLOW_F_SPOOFED_BIT, &flow->flags)) {

        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
            if (ntohs(tuple.src_port) != 22 && ntohs(tuple.dst_port) != 22) {
                if (tcph->ack && !tcph->syn) {
                    pr_info_ratelimited("pep: LOCAL_OUT not SPOOFED: %pI4:%u flags=0x%lx\n",
                            &tuple.src_addr, ntohs(tuple.src_port), flow->flags);
                }
            }
        }
        pep_flow_put(flow);
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);
    ip_hdr_len = iph->ihl * 4;
    tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

    if (tcph->ack && flow->seq_offset != 0) {

        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
            pr_info("pep: LOCAL_OUT ACK translate: %pI4:%u ack_seq=%u seq_offset=%d\n",
                    &tuple.src_addr, ntohs(tuple.src_port),
                    ntohl(tcph->ack_seq), flow->seq_offset);
        }
        if (pep_translate_ack_lan_to_wan(flow, skb) < 0) {
            pep_warn("LOCAL_OUT: Failed to translate ACK\n");
        }
    } else if (tcph->ack && flow->seq_offset == 0) {

        unsigned int payload_len;
        u32 ack_seq = ntohl(tcph->ack_seq);
        u32 expected_3rd_ack = flow->isn_pep + 1;

        payload_len = ntohs(iph->tot_len) - ip_hdr_len - (tcph->doff * 4);

        if (payload_len == 0 && !tcph->syn && !tcph->fin && !tcph->rst &&
            ack_seq == expected_3rd_ack && flow->state == PEP_TCP_SYN_RECV) {

            flow->state = PEP_TCP_ESTABLISHED;
            set_bit(PEP_FLOW_F_ACCELERATED_BIT, &flow->flags);
            set_bit(PEP_FLOW_F_ESTABLISHED_BIT, &flow->flags);

            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                pr_info("pep: LOCAL_OUT 3rd ACK: %pI4:%u -> %pI4:%u ESTABLISHED (ack=%u == isn_pep+1=%u)\n",
                        &tuple.src_addr, ntohs(tuple.src_port),
                        &tuple.dst_addr, ntohs(tuple.dst_port),
                        ack_seq, expected_3rd_ack);
            }

            pep_flow_put(flow);
            return NF_DROP;
        }

        if (payload_len > 0) {

            if (pep_ctx && pep_ctx->config.debug_level >= 2) {
                pr_info_ratelimited("pep: LOCAL_OUT DATA (seq_offset=0): %pI4:%u -> %pI4:%u "
                        "ack=%u payload=%u state=%d -> NF_ACCEPT (let POST_ROUTING handle)\n",
                        &tuple.src_addr, ntohs(tuple.src_port),
                        &tuple.dst_addr, ntohs(tuple.dst_port),
                        ack_seq, payload_len, flow->state);
            }
            pep_flow_put(flow);
            return NF_ACCEPT;
        }

        if (pep_ctx && pep_ctx->config.debug_level >= 2) {
            pr_info_ratelimited("pep: LOCAL_OUT ACK DROP (seq_offset=0): %pI4:%u -> %pI4:%u "
                    "ack=%u expected=%u payload=%u state=%d\n",
                    &tuple.src_addr, ntohs(tuple.src_port),
                    &tuple.dst_addr, ntohs(tuple.dst_port),
                    ack_seq, expected_3rd_ack, payload_len, flow->state);
        }
        pep_flow_put(flow);
        return NF_DROP;
    }

    pep_flow_put(flow);
    return NF_ACCEPT;
}

#define PEP_NF_PRI_BEFORE_CONNTRACK  (NF_IP_PRI_CONNTRACK - 1)
#define PEP_NF_PRI_AFTER_CONNTRACK   (NF_IP_PRI_CONNTRACK + 1)

/*
 * 功能/Main: 初始化Netfilter 报文路径（Initialize Netfilter packet path）
 * 细节/Details: Netfilter 钩子处理（netfilter hook）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: ctx
 * 影响/Effects: 注册/处理 Netfilter 钩子，影响报文路径（register/handle Netfilter hooks, affects packet path）
 * 重要程度/Importance: 高/High
 */
int pep_netfilter_init(struct pep_context *ctx)
{
    int ret;
    const char *mode_str;
    int pre_routing_pri, local_out_pri, post_routing_pri;

    if (!ctx)
        return -EINVAL;

    mode_str = ctx->config.tcp_spoofing ? "Spoofing" : "Monitor";

    if (ctx->config.tcp_spoofing) {
        pre_routing_pri = PEP_NF_PRI_BEFORE_CONNTRACK;
        local_out_pri = PEP_NF_PRI_BEFORE_CONNTRACK;
        post_routing_pri = PEP_NF_PRI_BEFORE_CONNTRACK;
    } else {
        pre_routing_pri = NF_IP_PRI_LAST;
        local_out_pri = NF_IP_PRI_LAST;
        post_routing_pri = NF_IP_PRI_LAST;
    }

    ctx->nf_ops[0].hook = pep_nf_pre_routing;
    ctx->nf_ops[0].pf = NFPROTO_IPV4;
    ctx->nf_ops[0].hooknum = NF_INET_PRE_ROUTING;
    ctx->nf_ops[0].priority = pre_routing_pri;
    ctx->nf_ops[0].priv = ctx;

    ctx->nf_ops[1].hook = pep_nf_local_in;
    ctx->nf_ops[1].pf = NFPROTO_IPV4;
    ctx->nf_ops[1].hooknum = NF_INET_LOCAL_IN;
    ctx->nf_ops[1].priority = NF_IP_PRI_LAST;
    ctx->nf_ops[1].priv = ctx;

    ctx->nf_ops[2].hook = pep_nf_local_out;
    ctx->nf_ops[2].pf = NFPROTO_IPV4;
    ctx->nf_ops[2].hooknum = NF_INET_LOCAL_OUT;
    ctx->nf_ops[2].priority = local_out_pri;
    ctx->nf_ops[2].priv = ctx;

    ctx->nf_ops[3].hook = pep_nf_post_routing;
    ctx->nf_ops[3].pf = NFPROTO_IPV4;
    ctx->nf_ops[3].hooknum = NF_INET_POST_ROUTING;
    ctx->nf_ops[3].priority = post_routing_pri;
    ctx->nf_ops[3].priv = ctx;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    ret = nf_register_net_hooks(&init_net, ctx->nf_ops, 4);
#else
    ret = nf_register_hooks(ctx->nf_ops, 4);
#endif

    if (ret < 0) {
        pep_err("Failed to register netfilter hooks: %d\n", ret);
        return ret;
    }

    ctx->nf_registered = 1;
    pep_info("Netfilter hooks registered (%s mode)\n", mode_str);

    return 0;
}

/*
 * 功能/Main: 清理Netfilter 报文路径（Cleanup Netfilter packet path）
 * 细节/Details: 并发同步（spinlock/atomic/rcu）；Netfilter 钩子处理（netfilter hook）
 * 输入/Inputs: 参数/Inputs: ctx
 * 影响/Effects: 注册/处理 Netfilter 钩子，影响报文路径（register/handle Netfilter hooks, affects packet path）
 * 重要程度/Importance: 高/High
 */
void pep_netfilter_exit(struct pep_context *ctx)
{
    if (!ctx || !ctx->nf_registered)
        return;

    pr_info("pep: [NF_EXIT] Unregistering netfilter hooks...\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    nf_unregister_net_hooks(&init_net, ctx->nf_ops, 4);
#else
    nf_unregister_hooks(ctx->nf_ops, 4);
#endif

    ctx->nf_registered = 0;

    pr_info("pep: [NF_EXIT] synchronize_rcu (wait for in-progress hooks)...\n");
    synchronize_rcu();
    pr_info("pep: [NF_EXIT] Done\n");

    pep_info("Netfilter hooks unregistered\n");
}
