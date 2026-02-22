/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"

extern struct pep_context *pep_ctx;

/*
 * 功能/Main: 处理pep_prefix_mask相关逻辑（Handle pep_prefix_mask logic）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: prefix_len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static inline __be32 pep_prefix_mask(u8 prefix_len)
{
    if (prefix_len == 0)
        return 0;
    if (prefix_len >= 32)
        return ~0U;
    return htonl(~((1U << (32 - prefix_len)) - 1));
}

/*
 * 功能/Main: 获取pep_get_prefix相关逻辑（Get pep_get_prefix logic）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: addr, prefix_len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static inline __be32 pep_get_prefix(__be32 addr, u8 prefix_len)
{
    return addr & pep_prefix_mask(prefix_len);
}

/*
 * 功能/Main: 处理区域统计/学习（Handle regional stats/learning）
 * 细节/Details: 围绕模块内部逻辑展开（module internal logic）
 * 输入/Inputs: 参数/Inputs: prefix, prefix_len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static inline u32 pep_region_hash(__be32 prefix, u8 prefix_len)
{
    return jhash_2words(prefix, prefix_len, 0);
}

/*
 * 功能/Main: 释放区域统计/学习（Free regional stats/learning）
 * 细节/Details: 学习控制/区域统计（learning/regional stats）；内存池管理（mempool management）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: rcu
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 中/Medium
 */
static void pep_region_free_rcu(struct rcu_head *rcu)
{
    struct pep_region_state *region = container_of(rcu, struct pep_region_state, rcu);
    struct pep_context *ctx = READ_ONCE(pep_ctx);

    if (ctx && ctx->region_table.region_cache) {
        kmem_cache_free(ctx->region_table.region_cache, region);
    }
}

/*
 * 功能/Main: 初始化区域统计/学习（Initialize regional stats/learning）
 * 细节/Details: 学习控制/区域统计（learning/regional stats）；内存池管理（mempool management）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: table, max_regions, prefix_len
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
int pep_region_table_init(struct pep_region_table *table, u32 max_regions, u8 prefix_len)
{
    if (!table)
        return -EINVAL;

    hash_init(table->regions);
    raw_spin_lock_init(&table->lock);
    atomic_set(&table->count, 0);
    table->max_regions = max_regions;
    table->default_prefix_len = prefix_len;

    table->region_cache = kmem_cache_create("pep_region_cache",
                                             sizeof(struct pep_region_state),
                                             0, SLAB_HWCACHE_ALIGN, NULL);
    if (!table->region_cache) {
        pep_err("Failed to create region cache\n");
        return -ENOMEM;
    }

    pep_info("Region table initialized: max=%u, prefix_len=%u\n",
             max_regions, prefix_len);

    return 0;
}

/*
 * 功能/Main: 清理区域统计/学习（Cleanup regional stats/learning）
 * 细节/Details: 学习控制/区域统计（learning/regional stats）；内存池管理（mempool management）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: table
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_region_table_exit(struct pep_region_table *table)
{
    struct pep_region_state *region;
    struct hlist_node *tmp;
    int bkt;
    unsigned long flags;
    int count = 0;

    if (!table)
        return;

    raw_spin_lock_irqsave(&table->lock, flags);

    hash_for_each_safe(table->regions, bkt, tmp, region, hnode) {
        hash_del_rcu(&region->hnode);
        atomic_dec(&table->count);
        call_rcu(&region->rcu, pep_region_free_rcu);
        count++;
    }

    raw_spin_unlock_irqrestore(&table->lock, flags);

    synchronize_rcu();
    rcu_barrier();

    if (table->region_cache) {
        kmem_cache_destroy(table->region_cache);
        table->region_cache = NULL;
    }

    pep_info("Region table destroyed, %d regions released\n", count);
}

/*
 * 功能/Main: 查询区域统计/学习（Lookup regional stats/learning）
 * 细节/Details: 学习控制/区域统计（learning/regional stats）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: dst_addr, prefix_len
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
struct pep_region_state *pep_region_lookup(__be32 dst_addr, u8 prefix_len)
{
    struct pep_region_state *region;
    struct pep_context *ctx = READ_ONCE(pep_ctx);
    __be32 prefix;
    u32 hash;

    if (!ctx)
        return NULL;

    prefix = pep_get_prefix(dst_addr, prefix_len);
    hash = pep_region_hash(prefix, prefix_len);

    rcu_read_lock();
    hash_for_each_possible_rcu(ctx->region_table.regions, region, hnode, hash) {
        if (region->dst_prefix == prefix && region->prefix_len == prefix_len) {
            rcu_read_unlock();
            return region;
        }
    }
    rcu_read_unlock();

    return NULL;
}

/*
 * 功能/Main: 处理区域统计/学习（Handle regional stats/learning）
 * 细节/Details: 重传/缓存处理（retransmission/cache）；RTT/RTO 估计（RTT/RTO estimation）；PMTU/MSS 更新（PMTU/MSS update）；学习控制/区域统计（learning/regional stats）；内存池管理（mempool management）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: dst_addr
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static struct pep_region_state *pep_region_create(__be32 dst_addr)
{
    struct pep_region_state *region;
    struct pep_context *ctx = READ_ONCE(pep_ctx);
    struct pep_region_table *table;
    __be32 prefix;
    u8 prefix_len;
    unsigned long flags;

    if (!ctx)
        return NULL;

    table = &ctx->region_table;
    prefix_len = table->default_prefix_len;
    prefix = pep_get_prefix(dst_addr, prefix_len);

    if (atomic_read(&table->count) >= table->max_regions) {
        pep_warn("Region table full: max=%u\n", table->max_regions);
        return NULL;
    }

    region = kmem_cache_zalloc(table->region_cache, GFP_ATOMIC);
    if (!region)
        return NULL;

    region->dst_prefix = prefix;
    region->prefix_len = prefix_len;

    region->base_rtt_us = UINT_MAX;
    region->avg_rtt_us = 0;
    region->rtt_variance_us = 0;
    region->estimated_bw_kbps = 0;
    region->loss_rate_ppm = 0;

    #define PEP_REGION_MSS 1460
    region->optimal_init_cwnd = ctx->config.init_cwnd * PEP_REGION_MSS;
    region->optimal_ssthresh = (ctx->config.max_cwnd * PEP_REGION_MSS) / 2;
    region->optimal_rto_min_ms = ctx->config.rto_min_ms;
    region->optimal_ack_interval_us = ctx->config.ack_delay_us;

    region->flow_count = 0;
    region->active_flows = 0;
    region->total_bytes = 0;
    region->total_packets = 0;
    region->total_retrans = 0;

    region->create_time = ktime_get();
    region->last_update = region->create_time;
    region->last_flow_time = region->create_time;

    spin_lock_init(&region->lock);

    raw_spin_lock_irqsave(&table->lock, flags);
    hash_add_rcu(table->regions, &region->hnode, pep_region_hash(prefix, prefix_len));
    atomic_inc(&table->count);
    raw_spin_unlock_irqrestore(&table->lock, flags);

    pep_dbg("Region created: %pI4/%u\n", &prefix, prefix_len);

    return region;
}

/*
 * 功能/Main: 获取区域统计/学习（Get regional stats/learning）
 * 细节/Details: 学习控制/区域统计（learning/regional stats）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: dst_addr
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
struct pep_region_state *pep_region_get_or_create(__be32 dst_addr)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);
    struct pep_region_state *region;
    u8 prefix_len;

    if (!ctx || !ctx->config.region_learning_enabled)
        return NULL;

    prefix_len = ctx->region_table.default_prefix_len;

    region = pep_region_lookup(dst_addr, prefix_len);
    if (region)
        return region;

    return pep_region_create(dst_addr);
}

/*
 * 功能/Main: 处理流表/会话状态（Handle flow/session state）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；学习控制/区域统计（learning/regional stats）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
void pep_region_flow_start(struct pep_flow *flow)
{
    struct pep_region_state *region;
    unsigned long flags;

    if (!flow)
        return;

    region = pep_region_get_or_create(flow->tuple.dst_addr);
    if (!region)
        return;

    spin_lock_irqsave(&region->lock, flags);
    region->flow_count++;
    region->active_flows++;
    region->last_flow_time = ktime_get();
    spin_unlock_irqrestore(&region->lock, flags);
}

/*
 * 功能/Main: 处理流表/会话状态（Handle flow/session state）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；重传/缓存处理（retransmission/cache）；学习控制/区域统计（learning/regional stats）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
void pep_region_flow_end(struct pep_flow *flow)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);
    struct pep_region_state *region;
    unsigned long flags;

    if (!flow || !ctx || !ctx->config.region_learning_enabled)
        return;

    region = pep_region_lookup(flow->tuple.dst_addr, ctx->region_table.default_prefix_len);
    if (!region)
        return;

    spin_lock_irqsave(&region->lock, flags);

    if (region->active_flows > 0)
        region->active_flows--;

    region->total_bytes += flow->rx_bytes + flow->tx_bytes;
    region->total_packets += flow->rx_packets + flow->tx_packets;
    region->total_retrans += flow->retrans_packets;

    region->last_update = ktime_get();

    spin_unlock_irqrestore(&region->lock, flags);

    pep_region_update_from_flow(flow);
}

/*
 * 功能/Main: 更新流表/会话状态（Update flow/session state）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；重传/缓存处理（retransmission/cache）；RTT/RTO 估计（RTT/RTO estimation）；PMTU/MSS 更新（PMTU/MSS update）；学习控制/区域统计（learning/regional stats）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 维护状态/参数，影响稳定性与性能（maintain state/params, affects stability/perf）
 * 重要程度/Importance: 高/High
 */
void pep_region_update_from_flow(struct pep_flow *flow)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);
    struct pep_region_state *region;
    unsigned long flags;
    u32 flow_rtt_us;
    u32 flow_bw_kbps;
    u64 total_bytes;
    u64 duration_us;

    if (!flow || !ctx || !ctx->config.region_learning_enabled)
        return;

    total_bytes = flow->rx_bytes + flow->tx_bytes;
    if (total_bytes < PEP_REGION_MIN_BYTES_TO_LEARN)
        return;

    region = pep_region_lookup(flow->tuple.dst_addr, ctx->region_table.default_prefix_len);
    if (!region)
        return;

    if (region->flow_count < PEP_REGION_MIN_FLOWS_TO_LEARN)
        return;

    flow_rtt_us = flow->rtt.min_rtt;
    if (flow_rtt_us == UINT_MAX || flow_rtt_us == 0)
        flow_rtt_us = flow->rtt.srtt >> 3;

    duration_us = ktime_us_delta(ktime_get(), flow->create_time);
    if (duration_us > 0 && total_bytes > 0) {

        flow_bw_kbps = div64_u64(total_bytes * 8 * 1000, duration_us);
    } else {
        flow_bw_kbps = 0;
    }

    spin_lock_irqsave(&region->lock, flags);

    if (flow_rtt_us > 0 && flow_rtt_us != UINT_MAX) {

        if (flow_rtt_us < region->base_rtt_us)
            region->base_rtt_us = flow_rtt_us;

        if (region->avg_rtt_us == 0) {
            region->avg_rtt_us = flow_rtt_us;
        } else {
            region->avg_rtt_us = (7 * region->avg_rtt_us + flow_rtt_us) / 8;
        }

        if (flow_rtt_us > region->avg_rtt_us) {
            u32 diff = flow_rtt_us - region->avg_rtt_us;
            region->rtt_variance_us = (3 * region->rtt_variance_us + diff) / 4;
        }
    }

    if (flow_bw_kbps > 0) {
        if (region->estimated_bw_kbps == 0) {
            region->estimated_bw_kbps = flow_bw_kbps;
        } else {
            region->estimated_bw_kbps = (7 * region->estimated_bw_kbps + flow_bw_kbps) / 8;
        }
    }

    if (flow->tx_packets > 0) {
        u32 flow_loss_ppm = div64_u64(flow->retrans_packets * 1000000ULL, flow->tx_packets);
        if (region->loss_rate_ppm == 0) {
            region->loss_rate_ppm = flow_loss_ppm;
        } else {
            region->loss_rate_ppm = (7 * region->loss_rate_ppm + flow_loss_ppm) / 8;
        }
    }

    if (region->estimated_bw_kbps > 0 && region->avg_rtt_us > 0) {

        u32 bdp_bytes = (region->estimated_bw_kbps * (region->avg_rtt_us / 1000)) / 8;

        u32 min_cwnd_bytes = ctx->config.init_cwnd * PEP_REGION_MSS;
        u32 max_cwnd_bytes = ctx->config.max_cwnd * PEP_REGION_MSS;
        if (bdp_bytes < min_cwnd_bytes)
            bdp_bytes = min_cwnd_bytes;
        if (bdp_bytes > max_cwnd_bytes)
            bdp_bytes = max_cwnd_bytes;

        region->optimal_init_cwnd = (3 * region->optimal_init_cwnd + bdp_bytes) / 4;
    }

    region->optimal_ssthresh = region->optimal_init_cwnd * 3 / 4;

    if (region->avg_rtt_us > 0) {
        u32 rto_us = region->avg_rtt_us + 4 * region->rtt_variance_us;
        u32 rto_ms = rto_us / 1000;
        if (rto_ms < ctx->config.rto_min_ms)
            rto_ms = ctx->config.rto_min_ms;
        if (rto_ms > ctx->config.rto_max_ms)
            rto_ms = ctx->config.rto_max_ms;
        region->optimal_rto_min_ms = rto_ms;
    }

    if (region->estimated_bw_kbps > 0) {

        u32 interval_us = (PEP_DEFAULT_ACK_BYTES_THRESHOLD * 8 * 1000) / region->estimated_bw_kbps;
        if (interval_us < 100)
            interval_us = 100;
        if (interval_us > 10000)
            interval_us = 10000;
        region->optimal_ack_interval_us = interval_us;
    }

    region->last_update = ktime_get();

    spin_unlock_irqrestore(&region->lock, flags);

    if (ctx->config.debug_level >= 2) {
        pep_info("Region %pI4/%u updated: rtt=%u/%u us, bw=%u kbps, "
                 "cwnd=%u, ssthresh=%u, rto=%u ms\n",
                 &region->dst_prefix, region->prefix_len,
                 region->base_rtt_us, region->avg_rtt_us,
                 region->estimated_bw_kbps,
                 region->optimal_init_cwnd, region->optimal_ssthresh,
                 region->optimal_rto_min_ms);
    }
}

/*
 * 功能/Main: 初始化流表/会话状态（Initialize flow/session state）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；RTT/RTO 估计（RTT/RTO estimation）；学习控制/区域统计（learning/regional stats）；并发同步（spinlock/atomic/rcu）；统计计数更新（stats counters）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
void pep_flow_init_from_region(struct pep_flow *flow)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);
    struct pep_region_state *region;
    unsigned long flags;

    if (!flow || !ctx || !ctx->config.region_learning_enabled)
        return;

    region = pep_region_lookup(flow->tuple.dst_addr, ctx->region_table.default_prefix_len);
    if (!region)
        return;

    if (region->flow_count < PEP_REGION_MIN_FLOWS_TO_LEARN)
        return;

    spin_lock_irqsave(&region->lock, flags);

    if (region->optimal_init_cwnd > 0) {
        flow->cc.cwnd = region->optimal_init_cwnd;
        flow->cc.ssthresh = region->optimal_ssthresh;
    }

    if (region->optimal_rto_min_ms > 0) {
        flow->rtt.rto = region->optimal_rto_min_ms;
    }

    if (region->optimal_ack_interval_us > 0) {
        flow->ack_pacer.ack_interval_us = region->optimal_ack_interval_us;
    }

    if (region->avg_rtt_us > 0 && region->avg_rtt_us != UINT_MAX) {
        flow->rtt.srtt = region->avg_rtt_us << 3;
        flow->rtt.rttvar = region->rtt_variance_us << 2;
        flow->rtt.min_rtt = region->base_rtt_us;
    }

    set_bit(PEP_FLOW_F_REGION_INIT_BIT, &flow->flags);

    spin_unlock_irqrestore(&region->lock, flags);

    if (ctx->config.debug_level >= 2) {
        pep_info("Flow %pI4:%u -> %pI4:%u initialized from region: "
                 "cwnd=%u, ssthresh=%u, rto=%u ms\n",
                 &flow->tuple.src_addr, ntohs(flow->tuple.src_port),
                 &flow->tuple.dst_addr, ntohs(flow->tuple.dst_port),
                 flow->cc.cwnd, flow->cc.ssthresh, flow->rtt.rto);
    }
}
