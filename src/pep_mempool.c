/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"

/*
 * 功能/Main: 初始化内存池管理（Initialize memory pool management）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；内存池管理（mempool management）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: pool
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
int pep_mempool_init(struct pep_mempool *pool)
{
    if (!pool)
        return -EINVAL;

    pool->flow_cache = kmem_cache_create(PEP_MEMPOOL_FLOW_CACHE_NAME,
                                          sizeof(struct pep_flow),
                                          __alignof__(struct pep_flow),
                                          SLAB_HWCACHE_ALIGN | SLAB_PANIC,
                                          NULL);
    if (!pool->flow_cache) {
        pep_err("Failed to create flow cache\n");
        return -ENOMEM;
    }

    atomic_set(&pool->flow_alloc, 0);
    atomic_set(&pool->flow_free, 0);
    pool->max_cache_bytes = 0;

    pep_info("Memory pool initialized: flow_size=%lu\n",
             sizeof(struct pep_flow));

    return 0;
}

/*
 * 功能/Main: 清理内存池管理（Cleanup memory pool management）
 * 细节/Details: 内存池管理（mempool management）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: pool
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_mempool_exit(struct pep_mempool *pool)
{
    int allocs, frees;

    if (!pool)
        return;

    allocs = atomic_read(&pool->flow_alloc);
    frees = atomic_read(&pool->flow_free);

    if (allocs != frees) {
        pep_warn("Memory leak detected: alloc=%d, free=%d, diff=%d\n",
                 allocs, frees, allocs - frees);
    }

    if (pool->flow_cache) {
        kmem_cache_destroy(pool->flow_cache);
        pool->flow_cache = NULL;
    }

    pep_info("Memory pool destroyed: alloc=%d, free=%d\n", allocs, frees);
}

/*
 * 功能/Main: 分配流表/会话状态（Allocate flow/session state）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；内存池管理（mempool management）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: pool
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
struct pep_flow *pep_mempool_alloc_flow(struct pep_mempool *pool)
{
    struct pep_flow *flow;
    u32 in_use;

    if (!pool || !pool->flow_cache)
        return NULL;

    if (pool->max_cache_bytes > 0) {
        in_use = atomic_read(&pool->flow_alloc) - atomic_read(&pool->flow_free);
        if ((u64)in_use * sizeof(struct pep_flow) >= pool->max_cache_bytes)
            return NULL;
    }

    flow = kmem_cache_zalloc(pool->flow_cache, GFP_ATOMIC);
    if (flow) {
        atomic_inc(&pool->flow_alloc);
    }

    return flow;
}

/*
 * 功能/Main: 释放流表/会话状态（Free flow/session state）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；内存池管理（mempool management）；并发同步（spinlock/atomic/rcu）
 * 输入/Inputs: 参数/Inputs: pool, flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
void pep_mempool_free_flow(struct pep_mempool *pool, struct pep_flow *flow)
{
    if (!pool || !pool->flow_cache || !flow)
        return;

    kmem_cache_free(pool->flow_cache, flow);
    atomic_inc(&pool->flow_free);
}
