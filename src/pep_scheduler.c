/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"

extern struct pep_context *pep_ctx;

/*
 * 功能/Main: 处理流表/会话状态（Handle flow/session state）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；配置/参数应用（config/params）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
u8 pep_classify_flow(const struct pep_flow *flow)
{
    struct pep_context *ctx = READ_ONCE(pep_ctx);
    u64 bytes = 0;
    u32 small_bytes = PEP_DEFAULT_CLASSIFY_SMALL_FLOW_BYTES;

    if (!flow)
        return PEP_SCHED_PRIO_NORMAL;

    if (ctx)
        small_bytes = ctx->config.classify_small_flow_bytes;

    bytes = flow->rx_bytes + flow->tx_bytes;

    if (flow->tuple.src_port == htons(22) || flow->tuple.dst_port == htons(22) ||
        flow->tuple.src_port == htons(53) || flow->tuple.dst_port == htons(53) ||
        flow->tuple.src_port == htons(123) || flow->tuple.dst_port == htons(123) ||
        flow->tuple.src_port == htons(3389) || flow->tuple.dst_port == htons(3389)) {
        return PEP_SCHED_PRIO_HIGH;
    }

    if (small_bytes > 0 && bytes < small_bytes)
        return PEP_SCHED_PRIO_HIGH;

    if (small_bytes > 0 && bytes > (u64)small_bytes * 8)
        return PEP_SCHED_PRIO_BULK;

    return PEP_SCHED_PRIO_NORMAL;
}

/*
 * 功能/Main: 处理调度/引擎线程（Handle scheduler/engine threads）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: sched
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
static struct pep_flow *pep_scheduler_dequeue(struct pep_scheduler *sched)
{
    int prio;
    struct pep_flow *flow = NULL;

    for (prio = 0; prio < PEP_SCHED_PRIO_MAX; prio++) {
        struct list_head *head = &sched->queues[prio];
        if (!list_empty(head)) {
            struct list_head *node = head->next;
            if (sched->dir == PEP_SCHED_DIR_WAN) {
                flow = list_entry(node, struct pep_flow, sched_node_wan);
                list_del_init(&flow->sched_node_wan);
                flow->sched_queued_wan = 0;
            } else {
                flow = list_entry(node, struct pep_flow, sched_node_lan);
                list_del_init(&flow->sched_node_lan);
                flow->sched_queued_lan = 0;
            }
            return flow;
        }
    }

    return NULL;
}

/*
 * 功能/Main: 后台处理调度/引擎线程（Work task scheduler/engine threads）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；并发同步（spinlock/atomic/rcu）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: work
 * 影响/Effects: 后台维护/调度，影响吞吐与时延（background maintenance/scheduling, affects throughput/latency）
 * 重要程度/Importance: 中/Medium
 */
static void pep_scheduler_work_handler(struct work_struct *work)
{
    struct pep_scheduler *sched = container_of(work, struct pep_scheduler, work.work);
    struct pep_flow *flow;
    unsigned long flags;

    for (;;) {
        spin_lock_irqsave(&sched->lock, flags);
        flow = pep_scheduler_dequeue(sched);
        if (!flow) {
            if (sched->resched) {
                sched->resched = 0;
                spin_unlock_irqrestore(&sched->lock, flags);
                continue;
            }
            sched->work_scheduled = 0;
            spin_unlock_irqrestore(&sched->lock, flags);
            break;
        }
        spin_unlock_irqrestore(&sched->lock, flags);

        if (sched->dir == PEP_SCHED_DIR_WAN) {
            pep_wan_tx_work_handler(&flow->wan_tx_work);
        } else {
            pep_lan_tx_work_handler(&flow->lan_tx_work);
        }

        cond_resched();
    }
}

/*
 * 功能/Main: 初始化调度/引擎线程（Initialize scheduler/engine threads）
 * 细节/Details: 队列/链表维护（queue/list maintenance）；定时器/工作队列上下文（timer/workqueue context）；并发同步（spinlock/atomic/rcu）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: sched, dir, wq, delay_ms
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
void pep_scheduler_init(struct pep_scheduler *sched, u8 dir,
                         struct workqueue_struct *wq, u32 delay_ms)
{
    int i;

    if (!sched)
        return;

    spin_lock_init(&sched->lock);
    for (i = 0; i < PEP_SCHED_PRIO_MAX; i++)
        INIT_LIST_HEAD(&sched->queues[i]);

    sched->dir = dir;
    sched->work_scheduled = 0;
    sched->resched = 0;
    sched->wq = wq;
    sched->delay_ms = delay_ms;
    INIT_DELAYED_WORK(&sched->work, pep_scheduler_work_handler);
}

/*
 * 功能/Main: 清理调度/引擎线程（Cleanup scheduler/engine threads）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；并发同步（spinlock/atomic/rcu）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: sched
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_scheduler_cleanup(struct pep_scheduler *sched)
{
    unsigned long flags;
    int prio;

    if (!sched)
        return;

    spin_lock_irqsave(&sched->lock, flags);
    for (prio = 0; prio < PEP_SCHED_PRIO_MAX; prio++) {
        while (!list_empty(&sched->queues[prio])) {
            struct pep_flow *flow;
            if (sched->dir == PEP_SCHED_DIR_WAN) {
                flow = list_first_entry(&sched->queues[prio],
                                        struct pep_flow, sched_node_wan);
                list_del_init(&flow->sched_node_wan);
                flow->sched_queued_wan = 0;
            } else {
                flow = list_first_entry(&sched->queues[prio],
                                        struct pep_flow, sched_node_lan);
                list_del_init(&flow->sched_node_lan);
                flow->sched_queued_lan = 0;
            }
            pep_flow_put(flow);
        }
    }
    sched->work_scheduled = 0;
    sched->resched = 0;
    spin_unlock_irqrestore(&sched->lock, flags);
}

/*
 * 功能/Main: 处理调度/引擎线程（Handle scheduler/engine threads）
 * 细节/Details: 访问/维护流状态（flow state access/maintenance）；队列/链表维护（queue/list maintenance）；定时器/工作队列上下文（timer/workqueue context）；并发同步（spinlock/atomic/rcu）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: sched, flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_scheduler_enqueue(struct pep_scheduler *sched, struct pep_flow *flow)
{
    unsigned long flags;
    u8 prio;
    bool need_queue = false;

    if (!sched || !flow || !sched->wq)
        return;

    prio = pep_classify_flow(flow);
    flow->sched_prio = prio;

    spin_lock_irqsave(&sched->lock, flags);
    if (sched->dir == PEP_SCHED_DIR_WAN) {
        if (!flow->sched_queued_wan) {
            list_add_tail(&flow->sched_node_wan, &sched->queues[prio]);
            flow->sched_queued_wan = 1;
        }
    } else {
        if (!flow->sched_queued_lan) {
            list_add_tail(&flow->sched_node_lan, &sched->queues[prio]);
            flow->sched_queued_lan = 1;
        }
    }

    if (!sched->work_scheduled) {
        sched->work_scheduled = 1;
        need_queue = true;
    } else {
        sched->resched = 1;
    }
    spin_unlock_irqrestore(&sched->lock, flags);

    if (need_queue)
        queue_delayed_work(sched->wq, &sched->work,
                           msecs_to_jiffies(sched->delay_ms));
}

/*
 * 功能/Main: 处理流表/会话状态（Handle flow/session state）
 * 细节/Details: 流表查找/创建/状态更新（flow lookup/create/update）；队列/链表维护（queue/list maintenance）；并发同步（spinlock/atomic/rcu）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: sched, flow
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
void pep_scheduler_remove_flow(struct pep_scheduler *sched, struct pep_flow *flow)
{
    unsigned long flags;

    if (!sched || !flow)
        return;

    spin_lock_irqsave(&sched->lock, flags);
    if (sched->dir == PEP_SCHED_DIR_WAN) {
        if (flow->sched_queued_wan) {
            list_del_init(&flow->sched_node_wan);
            flow->sched_queued_wan = 0;
            pep_flow_put(flow);
        }
    } else {
        if (flow->sched_queued_lan) {
            list_del_init(&flow->sched_node_lan);
            flow->sched_queued_lan = 0;
            pep_flow_put(flow);
        }
    }
    spin_unlock_irqrestore(&sched->lock, flags);
}
