/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) github.com/uk0 */

#include "pep_core.h"

extern struct pep_context *pep_ctx;

#ifndef TCPOPT_SACK
#define TCPOPT_SACK     5
#endif

/*
 * 功能/Main: 处理pep_parse_tcp_options相关逻辑（Handle pep_parse_tcp_options logic）
 * 细节/Details: 解析/修改 IP/TCP 头字段（IP/TCP header handling）；PMTU/MSS 更新（PMTU/MSS update）
 * 输入/Inputs: 参数/Inputs: tcph, opts
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 低/Low
 */
void pep_parse_tcp_options(const struct tcphdr *tcph,
                           struct pep_tcp_options *opts)
{
    const unsigned char *ptr;
    int length;
    int opcode, opsize;

    if (!tcph || !opts)
        return;

    memset(opts, 0, sizeof(*opts));

    ptr = (const unsigned char *)(tcph + 1);
    length = (tcph->doff * 4) - sizeof(struct tcphdr);

    while (length > 0) {
        opcode = *ptr++;
        length--;

        switch (opcode) {
        case TCPOPT_EOL:
            return;
        case TCPOPT_NOP:
            continue;
        default:
            if (length < 1)
                return;
            opsize = *ptr++;
            length--;
            if (opsize < 2 || opsize > length + 2)
                return;

            switch (opcode) {
            case TCPOPT_MSS:
                if (opsize == TCPOLEN_MSS) {
                    opts->mss = get_unaligned_be16(ptr);
                }
                break;
            case TCPOPT_WINDOW:
                if (opsize == TCPOLEN_WINDOW) {
                    opts->wscale = *ptr;
                    if (opts->wscale > 14)
                        opts->wscale = 14;
                }
                break;
            case TCPOPT_SACK_PERM:
                if (opsize == TCPOLEN_SACK_PERM) {
                    opts->sack_ok = 1;
                }
                break;
            case TCPOPT_SACK:

                if (opsize >= 10 && ((opsize - 2) % 8) == 0) {
                    int num_blocks = (opsize - 2) / 8;
                    int i;
                    if (num_blocks > 4)
                        num_blocks = 4;
                    opts->sack_blocks_count = num_blocks;
                    for (i = 0; i < num_blocks; i++) {
                        opts->sack_blocks[i].start = get_unaligned_be32(ptr + i * 8);
                        opts->sack_blocks[i].end = get_unaligned_be32(ptr + i * 8 + 4);
                    }
                }
                break;
            case TCPOPT_TIMESTAMP:
                if (opsize == TCPOLEN_TIMESTAMP) {
                    opts->ts_val = get_unaligned_be32(ptr);
                    opts->ts_ecr = get_unaligned_be32(ptr + 4);
                }
                break;
            }
            ptr += opsize - 2;
            length -= opsize - 2;
        }
    }
}

/*
 * 功能/Main: 处理引擎/工作线程（Process engine/workers）
 * 细节/Details: 处理 skb/packet（touch skb headers/csum）；Netfilter 钩子处理（netfilter hook）；配置/参数应用（config/params）
 * 输入/Inputs: 参数/Inputs: ctx, skb, dir
 * 影响/Effects: 更新模块内部状态或处理数据路径（update internal state or data path）
 * 重要程度/Importance: 高/High
 */
unsigned int pep_engine_process(struct pep_context *ctx, struct sk_buff *skb,
                                 enum pep_direction dir)
{
    if (!ctx || !skb)
        return NF_ACCEPT;

    if (!ctx->config.tcp_spoofing)
        return NF_ACCEPT;

    return NF_ACCEPT;
}

/*
 * 功能/Main: 初始化引擎/工作线程（Initialize engine/workers）
 * 细节/Details: 队列/链表维护（queue/list maintenance）；配置/参数应用（config/params）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: ctx
 * 影响/Effects: 初始化资源/表/定时器，影响后续模块运行（init resources/tables/timers, affects module runtime）
 * 重要程度/Importance: 高/High
 */
int pep_engine_init(struct pep_context *ctx)
{
    u32 engine_num;
    u32 i;
    int ret = 0;

    if (!ctx)
        return -EINVAL;

    engine_num = ctx->config.engine_num;
    if (engine_num == 0)
        engine_num = num_online_cpus();
    if (engine_num == 0)
        engine_num = 1;

    ctx->engine_num = engine_num;

    ctx->engine_wq = kcalloc(engine_num, sizeof(*ctx->engine_wq), GFP_KERNEL);
    ctx->sched_wan = kcalloc(engine_num, sizeof(*ctx->sched_wan), GFP_KERNEL);
    ctx->sched_lan = kcalloc(engine_num, sizeof(*ctx->sched_lan), GFP_KERNEL);
    if (!ctx->engine_wq || !ctx->sched_wan || !ctx->sched_lan) {
        ret = -ENOMEM;
        goto err;
    }

    for (i = 0; i < engine_num; i++) {
        char name[32];

        snprintf(name, sizeof(name), "pep_eng_%u", i);
        ctx->engine_wq[i] = alloc_workqueue(name,
                                            WQ_HIGHPRI | WQ_MEM_RECLAIM | WQ_UNBOUND,
                                            1);
        if (!ctx->engine_wq[i]) {
            ret = -ENOMEM;
            goto err;
        }

        pep_scheduler_init(&ctx->sched_wan[i], PEP_SCHED_DIR_WAN,
                           ctx->engine_wq[i], ctx->config.task_sched_delay_wan_ms);
        pep_scheduler_init(&ctx->sched_lan[i], PEP_SCHED_DIR_LAN,
                           ctx->engine_wq[i], ctx->config.task_sched_delay_lan_ms);
    }

    pep_info("Engine scheduler: engines=%u (delay wan=%u ms lan=%u ms)\n",
             ctx->engine_num, ctx->config.task_sched_delay_wan_ms,
             ctx->config.task_sched_delay_lan_ms);
    return 0;

err:
    pep_engine_exit(ctx);
    return ret;
}

/*
 * 功能/Main: 清理引擎/工作线程（Cleanup engine/workers）
 * 细节/Details: 队列/链表维护（queue/list maintenance）；定时器/工作队列上下文（timer/workqueue context）；引擎调度/任务分发（engine scheduling）
 * 输入/Inputs: 参数/Inputs: ctx
 * 影响/Effects: 释放资源/注销钩子，影响模块收尾（release resources/unregister hooks, affects teardown）
 * 重要程度/Importance: 高/High
 */
void pep_engine_exit(struct pep_context *ctx)
{
    u32 i;

    if (!ctx)
        return;

    if (ctx->sched_wan && ctx->sched_lan) {
        for (i = 0; i < ctx->engine_num; i++) {
            if (ctx->sched_wan[i].wq || ctx->sched_lan[i].wq) {
                cancel_delayed_work_sync(&ctx->sched_wan[i].work);
                cancel_delayed_work_sync(&ctx->sched_lan[i].work);
                pep_scheduler_cleanup(&ctx->sched_wan[i]);
                pep_scheduler_cleanup(&ctx->sched_lan[i]);
            }
        }
    }

    if (ctx->engine_wq) {
        for (i = 0; i < ctx->engine_num; i++) {
            if (ctx->engine_wq[i])
                destroy_workqueue(ctx->engine_wq[i]);
        }
    }

    kfree(ctx->sched_wan);
    kfree(ctx->sched_lan);
    kfree(ctx->engine_wq);
    ctx->sched_wan = NULL;
    ctx->sched_lan = NULL;
    ctx->engine_wq = NULL;
    ctx->engine_num = 0;

    pep_info("PEP engine destroyed\n");
}
