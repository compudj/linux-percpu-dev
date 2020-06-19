/* SPDX-License-Identifier: LGPL-2.1 OR MIT */
/*
 * percpu-op.h
 *
 * (C) Copyright 2017-2018 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef PERCPU_OP_H
#define PERCPU_OP_H

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <syscall.h>
#include <unistd.h>
#include <linux/sched.h>
#include "rseq.h"

static inline uint32_t percpu_current_cpu(void)
{
	return rseq_current_cpu();
}

static inline int sys_cpu_mutex(int cmd, int flags, int cpu)
{
	return syscall(__NR_sched_pair_cpu, cmd, flags, cpu);
}

static inline void cpu_mutex_set(int cpu)
{
	int ret;

	ret = sys_cpu_mutex(SCHED_PAIR_CPU_CMD_SET, 0, cpu);
	if (ret)
		abort();
}

static inline void cpu_mutex_clear(void)
{
	int ret;

	ret = sys_cpu_mutex(SCHED_PAIR_CPU_CMD_CLEAR, 0, 0);
	if (ret)
		abort();
}

static inline __attribute__((always_inline))
int percpu_fence(int cpu)
{
	if (cpu < 0)
		return -1;
	if ((uint32_t) cpu == percpu_current_cpu())
		return 0;
	/*
	 * Temporarily pinning to the target CPU acts as a rseq fence
	 * for that CPU.
	 */
	cpu_mutex_set(cpu);
	cpu_mutex_clear();
	return 0;
}

static inline __attribute__((always_inline))
int percpu_cmpeqv_storev(intptr_t *v, intptr_t expect, intptr_t newv,
			 int cpu)
{
	int ret;

	ret = rseq_cmpeqv_storev(v, expect, newv, cpu);
check:
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		cpu_mutex_set(cpu);
		ret = rseq_cmpeqv_storev(v, expect, newv, percpu_current_cpu());
		cpu_mutex_clear();
		goto check;
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_cmpnev_storeoffp_load(intptr_t *v, intptr_t expectnot,
			       off_t voffp, intptr_t *load, int cpu)
{
	int ret;

	ret = rseq_cmpnev_storeoffp_load(v, expectnot, voffp, load, cpu);
check:
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		cpu_mutex_set(cpu);
		ret = rseq_cmpnev_storeoffp_load(v, expectnot, voffp, load,
						 percpu_current_cpu());
		cpu_mutex_clear();
		goto check;
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_addv(intptr_t *v, intptr_t count, int cpu)
{
	int ret;

	ret = rseq_addv(v, count, cpu);
check:
	if (rseq_unlikely(ret)) {
		cpu_mutex_set(cpu);
		ret = rseq_addv(v, count, percpu_current_cpu());
		cpu_mutex_clear();
		goto check;
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_cmpeqv_storev_storev(intptr_t *v, intptr_t expect,
				intptr_t *v2, intptr_t newv2,
				intptr_t newv, int cpu)
{
	int ret;

	ret = rseq_cmpeqv_trystorev_storev(v, expect, v2, newv2,
					   newv, cpu);
check:
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		cpu_mutex_set(cpu);
		ret = rseq_cmpeqv_trystorev_storev(v, expect, v2, newv2,
						   newv, percpu_current_cpu());
		cpu_mutex_clear();
		goto check;
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_cmpeqv_storev_storev_release(intptr_t *v, intptr_t expect,
					intptr_t *v2, intptr_t newv2,
					intptr_t newv, int cpu)
{
	int ret;

	ret = rseq_cmpeqv_trystorev_storev_release(v, expect, v2, newv2,
						   newv, cpu);
check:
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		cpu_mutex_set(cpu);
		ret = rseq_cmpeqv_trystorev_storev_release(v, expect, v2, newv2,
							   newv,
							   percpu_current_cpu());
		cpu_mutex_clear();
		goto check;
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_cmpeqv_cmpeqv_storev(intptr_t *v, intptr_t expect,
				intptr_t *v2, intptr_t expect2,
				intptr_t newv, int cpu)
{
	int ret;

	ret = rseq_cmpeqv_cmpeqv_storev(v, expect, v2, expect2, newv, cpu);
check:
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		cpu_mutex_set(cpu);
		ret = rseq_cmpeqv_cmpeqv_storev(v, expect, v2, expect2,
						newv, percpu_current_cpu());
		cpu_mutex_clear();
		goto check;
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_cmpeqv_memcpy_storev(intptr_t *v, intptr_t expect,
				void *dst, void *src, size_t len,
				intptr_t newv, int cpu)
{
	int ret;

	ret = rseq_cmpeqv_trymemcpy_storev(v, expect, dst, src, len,
					   newv, cpu);
check:
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		cpu_mutex_set(cpu);
		ret = rseq_cmpeqv_trymemcpy_storev(v, expect, dst, src, len,
						   newv, percpu_current_cpu());
		cpu_mutex_clear();
		goto check;
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_cmpeqv_memcpy_storev_release(intptr_t *v, intptr_t expect,
					void *dst, void *src, size_t len,
					intptr_t newv, int cpu)
{
	int ret;

	ret = rseq_cmpeqv_trymemcpy_storev_release(v, expect, dst, src, len,
						   newv, cpu);
check:
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		cpu_mutex_set(cpu);
		ret = rseq_cmpeqv_trymemcpy_storev_release(v, expect, dst, src, len,
							   newv, percpu_current_cpu());
		cpu_mutex_clear();
		goto check;
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_deref_loadoffp(intptr_t *p, off_t voffp, intptr_t *load, int cpu)
{
	int ret;

	ret = rseq_deref_loadoffp(p, voffp, load, cpu);
check:
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		cpu_mutex_set(cpu);
		ret = rseq_deref_loadoffp(p, voffp, load, percpu_current_cpu());
		cpu_mutex_clear();
		goto check;
	}
	return 0;
}

#endif  /* PERCPU_OP_H_ */
