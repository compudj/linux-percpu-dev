/*
 * cpu-op.c
 *
 * Copyright (C) 2017 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>
#include <assert.h>
#include <signal.h>

#include "cpu-op.h"

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

int cpu_opv(struct cpu_op *cpu_opv, int cpuopcnt, int cpu, int flags)
{
	return syscall(__NR_cpu_opv, cpu_opv, cpuopcnt, cpu, flags);
}

int cpu_op_get_current_cpu(void)
{
	int cpu;

	cpu = sched_getcpu();
	if (cpu < 0) {
		perror("sched_getcpu()");
		abort();
	}
	return cpu;
}

int cpu_op_cmpstore(void *v, void *expect, void *n, size_t len, int cpu)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = len,
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)expect,
		},
		[1] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)n,
		},
	};

	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int cpu_op_2cmp1store(void *v, void *expect, void *n, void *check2,
		void *expect2, size_t len, int cpu)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = len,
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)expect,
		},
		[1] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = len,
			.u.compare_op.a = (unsigned long)check2,
			.u.compare_op.b = (unsigned long)expect2,
		},
		[2] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)n,
		},
	};

	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int cpu_op_1cmp2store(void *v, void *expect, void *_new,
		void *v2, void *_new2, size_t len, int cpu)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = len,
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)expect,
		},
		[1] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)_new,
		},
		[2] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)v2,
			.u.memcpy_op.src = (unsigned long)_new2,
		},
	};

	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int cpu_op_cmpxchg(void *v, void *expect, void *old, void *n,
		size_t len, int cpu)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)old,
			.u.memcpy_op.src = (unsigned long)v,
		},
		[1] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = len,
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)expect,
		},
		[2] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)n,
		},
	};

	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int cpu_op_add(void *v, int64_t count, size_t len, int cpu)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_ADD_OP,
			.len = len,
			.u.arithmetic_op.p = (unsigned long)v,
			.u.arithmetic_op.count = count,
		},
	};

	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int cpu_op_cmpstorememcpy(void *v, void *expect, void *_new, size_t len,
		void *dst, void *src, size_t copylen, int cpu)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = len,
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)expect,
		},
		[1] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)_new,
		},
		[2] = {
			.op = CPU_MEMCPY_OP,
			.len = copylen,
			.u.memcpy_op.dst = (unsigned long)dst,
			.u.memcpy_op.src = (unsigned long)src,
		},
	};

	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}
