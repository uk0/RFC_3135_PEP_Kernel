/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"

extern struct pep_context *pep_ctx;

#define PEP_CARRY4(a, b)    ((u32)(~(a)) < (u32)(b))

/*
 * 功能/Main: 校验和处理（Handle checksum handling）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: sum
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static inline __sum16 pep_fast_csum_fold(u32 sum)
{
	u32 high, low;

	high = sum >> 16;
	low = sum & 0xFFFF;
	sum = high + low;

	sum = (sum >> 16) + (sum & 0xFFFF);

	return (__sum16)~sum;
}

/*
 * 功能/Main: 处理pep_fast_pseudo_header_sum相关逻辑（Handle pep_fast_pseudo_header_sum logic）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: saddr, daddr, protocol, len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static inline u32 pep_fast_pseudo_header_sum(__be32 saddr, __be32 daddr,
					      u8 protocol, u16 len)
{
	u32 sum1, sum2, carry1, carry2;

	sum1 = (__force u32)saddr + (__force u32)daddr;
	carry1 = PEP_CARRY4((__force u32)saddr, (__force u32)daddr);

	sum2 = ((u32)protocol << 8) | ((u32)htons(len));

	sum1 = sum1 + sum2 + carry1;
	carry2 = PEP_CARRY4(sum1 - carry1, sum2) || PEP_CARRY4(sum1 - carry1 - sum2 + carry1, carry1);

	sum1 = sum1 + carry2;

	return sum1;
}

/*
 * 功能/Main: 校验和处理（Handle checksum handling）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: data, len, sum
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static __maybe_unused u32 pep_fast_csum_partial(const void *data,
						 unsigned int len, u32 sum)
{
	const u16 *ptr = (const u16 *)data;
	unsigned int count;

	count = len >> 1;
	while (count > 0) {
		sum += *ptr++;
		count--;
	}

	if (len & 1) {
		sum += *(const u8 *)ptr;
	}

	return sum;
}

/*
 * 功能/Main: 校验和处理（Handle checksum handling）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: data, len, sum
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static __maybe_unused u32 pep_fast_csum_partial_32(const void *data,
						    unsigned int len, u32 sum)
{
	const u32 *ptr32 = (const u32 *)data;
	const u16 *ptr16;
	unsigned int count32, count16;
	u32 sum1, carry;

	count32 = len >> 2;
	while (count32 > 0) {
		sum1 = *ptr32++;
		sum = sum + sum1;

		if (sum < sum1)
			sum++;
		count32--;
	}

	ptr16 = (const u16 *)ptr32;
	count16 = (len & 3) >> 1;
	while (count16 > 0) {
		sum += *ptr16++;
		count16--;
	}

	if (len & 1) {
		sum += *(const u8 *)ptr16;
	}

	carry = sum >> 16;
	sum = (sum & 0xFFFF) + carry;
	sum = (sum >> 16) + (sum & 0xFFFF);

	return sum;
}

/*
 * 功能/Main: 更新校验和处理（Update checksum handling）
 * 细节/Details: 校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: iph
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 中/Medium
 */
void pep_update_ip_checksum(struct iphdr *iph)
{
	if (!iph)
		return;

	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

/*
 * 功能/Main: 更新校验和处理（Update checksum handling）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: skb, iph, tcph
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 中/Medium
 */
void pep_update_tcp_checksum(struct sk_buff *skb, struct iphdr *iph,
			     struct tcphdr *tcph)
{
	unsigned int tcp_len;
	unsigned int ip_hdr_len;

	if (!skb || !iph || !tcph)
		return;

	ip_hdr_len = iph->ihl * 4;
	tcp_len = ntohs(iph->tot_len) - ip_hdr_len;

	tcph->check = 0;
	tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
					 tcp_len, IPPROTO_TCP,
					 csum_partial(tcph, tcp_len, 0));

	skb->ip_summed = CHECKSUM_NONE;
}

/*
 * 功能/Main: 校验和处理（Handle checksum handling）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: skb, iph, tcph, hw_offload
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
/*
 * v83: 修复 CHECKSUM_PARTIAL 模式的伪头校验和计算
 *
 * 问题: 之前使用自定义的 pep_fast_pseudo_header_sum() 计算伪头校验和，
 *       但该实现在处理 protocol 和 length 字段时有字节序问题，
 *       导致 skb_checksum_help() 完成校验和时得到错误的结果。
 *
 * 解决: 使用标准的内核函数 csum_tcpudp_magic() 计算伪头校验和，
 *       然后取反（~）得到 CHECKSUM_PARTIAL 模式需要的初始值。
 *       这与内核的 __tcp_v4_send_check() 实现一致。
 *
 * 参考: net/ipv4/tcp_output.c 中的 __tcp_v4_send_check()
 */
void pep_fast_tcp_checksum(struct sk_buff *skb, struct iphdr *iph,
			   struct tcphdr *tcph, bool hw_offload)
{
	unsigned int tcp_len;
	unsigned int ip_hdr_len;

	if (!skb || !iph || !tcph)
		return;

	ip_hdr_len = iph->ihl * 4;
	tcp_len = ntohs(iph->tot_len) - ip_hdr_len;

	tcph->check = 0;

	if (hw_offload) {
		/*
		 * v83: 使用标准内核方法设置 CHECKSUM_PARTIAL
		 *
		 * 伪头校验和 = ~csum_tcpudp_magic(saddr, daddr, len, proto, 0)
		 *
		 * 这里 csum_tcpudp_magic 返回的是 16 位折叠后的校验和，
		 * 取反后存入 tcph->check 供 skb_checksum_help() 或硬件使用。
		 */
		tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
						  tcp_len, IPPROTO_TCP, 0);

		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		/*
		 * 软件校验和模式：直接计算完整校验和
		 */
		tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
						 tcp_len, IPPROTO_TCP,
						 csum_partial(tcph, tcp_len, 0));
		skb->ip_summed = CHECKSUM_NONE;
	}
}

/*
 * 功能/Main: 更新校验和处理（Update checksum handling）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: sum, old_val, new_val, is_partial
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 中/Medium
 */
void pep_incremental_csum_update(__sum16 *sum, __be32 old_val, __be32 new_val,
				 bool is_partial)
{
	u32 old_sum, diff;

	if (!sum)
		return;

	if (old_val == new_val)
		return;

	old_sum = (__force u32)~(*sum) & 0xFFFF;

	old_sum += ((__force u32)new_val & 0xFFFF);
	old_sum += ((__force u32)new_val >> 16);
	old_sum -= ((__force u32)old_val & 0xFFFF);
	old_sum -= ((__force u32)old_val >> 16);

	while ((s32)old_sum < 0)
		old_sum += 0x10000;

	diff = (old_sum >> 16) + (old_sum & 0xFFFF);
	diff = (diff >> 16) + (diff & 0xFFFF);

	if (is_partial) {

		*sum = (__force __sum16)~diff;
	} else {

		*sum = (__force __sum16)(~diff & 0xFFFF);
	}
}

/*
 * 功能/Main: 校验和处理（Handle checksum handling）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: sum, old_val, new_val, is_partial
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_incremental_csum_update16(__sum16 *sum, __be16 old_val, __be16 new_val,
				   bool is_partial)
{
	u32 old_sum, diff;

	if (!sum)
		return;

	if (old_val == new_val)
		return;

	old_sum = (__force u32)~(*sum) & 0xFFFF;
	old_sum += (__force u32)new_val;
	old_sum -= (__force u32)old_val;

	while ((s32)old_sum < 0)
		old_sum += 0x10000;

	diff = (old_sum >> 16) + (old_sum & 0xFFFF);
	diff = (diff >> 16) + (diff & 0xFFFF);

	*sum = (__force __sum16)(is_partial ? ~diff : (~diff & 0xFFFF));
}

/*
 * 功能/Main: 处理pep_create_tcp_packet相关逻辑（Handle pep_create_tcp_packet logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；frag/分片结构处理（frag list handling）；访问/维护流状态（flow state access/maintenance）；并发同步（spinlock/atomic/rcu）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: flow, seq, ack, flags, data, data_len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
struct sk_buff *pep_create_tcp_packet(struct pep_flow *flow,
				       u32 seq, u32 ack, u16 flags,
				       const void *data, u32 data_len)
{
	struct sk_buff *skb;
	struct iphdr *iph;
	struct tcphdr *tcph;
	unsigned int ip_hdr_len = sizeof(struct iphdr);
	unsigned int tcp_hdr_len = sizeof(struct tcphdr);
	unsigned int total_len;
	unsigned int headroom;

	if (!flow)
		return NULL;

	headroom = LL_MAX_HEADER + ip_hdr_len;
	total_len = ip_hdr_len + tcp_hdr_len + data_len;

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

	iph->saddr = flow->tuple.dst_addr;
	iph->daddr = flow->tuple.src_addr;

	skb_set_transport_header(skb, ip_hdr_len);
	tcph = skb_put(skb, tcp_hdr_len);

	memset(tcph, 0, tcp_hdr_len);
	tcph->source = flow->tuple.dst_port;
	tcph->dest = flow->tuple.src_port;
	tcph->seq = htonl(seq);
	tcph->ack_seq = htonl(ack);
	tcph->doff = tcp_hdr_len / 4;

	if (flags & TCPHDR_SYN)
		tcph->syn = 1;
	if (flags & TCPHDR_ACK)
		tcph->ack = 1;
	if (flags & TCPHDR_FIN)
		tcph->fin = 1;
	if (flags & TCPHDR_RST)
		tcph->rst = 1;
	if (flags & TCPHDR_PSH)
		tcph->psh = 1;

	tcph->window = htons(65535);

	if (data && data_len > 0) {
		void *payload = skb_put(skb, data_len);
		memcpy(payload, data, data_len);
	}

	pep_update_ip_checksum(iph);
	pep_update_tcp_checksum(skb, iph, tcph);

	skb->protocol = htons(ETH_P_IP);
	skb->mark = PEP_SKB_MARK;
	skb->priority = 0;

	return skb;
}

/*
 * 功能/Main: 处理pep_create_tcp_packet_hw相关逻辑（Handle pep_create_tcp_packet_hw logic）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；frag/分片结构处理（frag list handling）；访问/维护流状态（flow state access/maintenance）；并发同步（spinlock/atomic/rcu）；校验和处理（checksum adjust）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow, seq, ack, flags, data, data_len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
struct sk_buff *pep_create_tcp_packet_hw(struct pep_flow *flow,
					  u32 seq, u32 ack, u16 flags,
					  const void *data, u32 data_len)
{
	struct sk_buff *skb;
	struct iphdr *iph;
	struct tcphdr *tcph;
	unsigned int ip_hdr_len = sizeof(struct iphdr);
	unsigned int tcp_hdr_len = sizeof(struct tcphdr);
	unsigned int total_len;
	unsigned int headroom;

	if (!flow)
		return NULL;

	headroom = LL_MAX_HEADER + ip_hdr_len;
	total_len = ip_hdr_len + tcp_hdr_len + data_len;

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
	iph->saddr = flow->tuple.dst_addr;
	iph->daddr = flow->tuple.src_addr;

	skb_set_transport_header(skb, ip_hdr_len);
	tcph = skb_put(skb, tcp_hdr_len);

	memset(tcph, 0, tcp_hdr_len);
	tcph->source = flow->tuple.dst_port;
	tcph->dest = flow->tuple.src_port;
	tcph->seq = htonl(seq);
	tcph->ack_seq = htonl(ack);
	tcph->doff = tcp_hdr_len / 4;

	if (flags & TCPHDR_SYN)
		tcph->syn = 1;
	if (flags & TCPHDR_ACK)
		tcph->ack = 1;
	if (flags & TCPHDR_FIN)
		tcph->fin = 1;
	if (flags & TCPHDR_RST)
		tcph->rst = 1;
	if (flags & TCPHDR_PSH)
		tcph->psh = 1;

	tcph->window = htons(65535);

	if (data && data_len > 0) {
		void *payload = skb_put(skb, data_len);
		memcpy(payload, data, data_len);
	}

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
 * 功能/Main: 接收校验和处理（Receive checksum handling）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；解析/修改 IP/TCP 头字段（IP/TCP header handling）；校验和处理（checksum adjust）
 * 输入/Inputs: 参数/Inputs: skb
 * 影响/Effects: 接收并处理入站数据，更新流状态或队列（receive inbound data, updates flow/queue state）
 * 重要程度/Importance: 高/High
 */
bool pep_rx_checksum_ok(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	unsigned int ip_hdr_len;
	unsigned int tcp_hdr_len;
	unsigned int tcp_len;

	if (!skb)
		return false;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return false;

	iph = ip_hdr(skb);
	if (iph->version != 4)
		return true;

	ip_hdr_len = iph->ihl * 4;
	if (ip_hdr_len < sizeof(struct iphdr))
		return false;

	if (!pskb_may_pull(skb, ip_hdr_len))
		return false;

	if (ip_fast_csum((unsigned char *)iph, iph->ihl) != 0)
		return false;

	if (iph->protocol != IPPROTO_TCP)
		return true;

	if (skb->ip_summed == CHECKSUM_UNNECESSARY)
		return true;

	if (!pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr)))
		return false;

	tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
	tcp_hdr_len = tcph->doff * 4;
	if (tcp_hdr_len < sizeof(struct tcphdr))
		return false;

	tcp_len = ntohs(iph->tot_len) - ip_hdr_len;
	if (tcp_len < tcp_hdr_len)
		return false;

	if (csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len, IPPROTO_TCP,
			      csum_partial(tcph, tcp_len, 0)) != 0)
		return false;

	return true;
}
