/*
 * rseq.c
 *
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <rseq.h>

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

__attribute__((weak)) __thread volatile struct rseq __rseq_abi = {
	.u.e.cpu_id = -1,
};

static int sys_rseq(volatile struct rseq *rseq_abi, int flags)
{
	return syscall(__NR_rseq, rseq_abi, flags);
}

int rseq_op(struct rseq_op *rseqop, int rseqopcnt, int cpu, int flags)
{
	return syscall(__NR_rseq_op, rseqop, rseqopcnt, cpu, flags);
}

int rseq_register_current_thread(void)
{
	int rc;

	rc = sys_rseq(&__rseq_abi, 0);
	if (rc) {
		fprintf(stderr, "Error: sys_rseq(...) failed(%d): %s\n",
			errno, strerror(errno));
		return -1;
	}
	assert(rseq_current_cpu() >= 0);
	return 0;
}

int rseq_unregister_current_thread(void)
{
	int rc;

	rc = sys_rseq(NULL, 0);
	if (rc) {
		fprintf(stderr, "Error: sys_rseq(...) failed(%d): %s\n",
			errno, strerror(errno));
		return -1;
	}
	return 0;
}

int rseq_fallback_current_cpu(void)
{
	int cpu;

	cpu = sched_getcpu();
	if (cpu < 0) {
		perror("sched_getcpu()");
		abort();
	}
	return cpu;
}

int rseq_op_cmpstore(void *v, void *expect, void *n, size_t len, int cpu)
{
	struct rseq_op opvec[] = {
		[0] = {
			.op = RSEQ_COMPARE_EQ_OP,
			.len = len,
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)expect,
		},
		[1] = {
			.op = RSEQ_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)n,
		},
	};

	return rseq_op(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int rseq_op_2cmp1store(void *v, void *expect, void *n, void *check2,
		void *expect2, size_t len, int cpu)
{
	struct rseq_op opvec[] = {
		[0] = {
			.op = RSEQ_COMPARE_EQ_OP,
			.len = len,
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)expect,
		},
		[1] = {
			.op = RSEQ_COMPARE_EQ_OP,
			.len = len,
			.u.compare_op.a = (unsigned long)check2,
			.u.compare_op.b = (unsigned long)expect2,
		},
		[2] = {
			.op = RSEQ_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)n,
		},
	};

	return rseq_op(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int rseq_op_1cmp2store(void *v, void *expect, void *_new,
		void *v2, void *_new2, size_t len, int cpu)
{
	struct rseq_op opvec[] = {
		[0] = {
			.op = RSEQ_COMPARE_EQ_OP,
			.len = len,
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)expect,
		},
		[1] = {
			.op = RSEQ_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)_new,
		},
		[2] = {
			.op = RSEQ_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)v2,
			.u.memcpy_op.src = (unsigned long)_new2,
		},
	};

	return rseq_op(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int rseq_op_cmpxchg(void *v, void *expect, void *old, void *n,
		size_t len, int cpu)
{
	struct rseq_op opvec[] = {
		[0] = {
			.op = RSEQ_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)old,
			.u.memcpy_op.src = (unsigned long)v,
		},
		[1] = {
			.op = RSEQ_COMPARE_EQ_OP,
			.len = len,
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)expect,
		},
		[2] = {
			.op = RSEQ_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)n,
		},
	};

	return rseq_op(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int rseq_op_add(void *v, int64_t count, size_t len, int cpu)
{
	struct rseq_op opvec[] = {
		[0] = {
			.op = RSEQ_ADD_OP,
			.len = len,
			.u.arithmetic_op.p = (unsigned long)v,
			.u.arithmetic_op.count = count,
		},
	};

	return rseq_op(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int rseq_op_cmpstorememcpy(void *v, void *expect, void *_new, size_t len,
		void *dst, void *src, size_t copylen, int cpu)
{
	struct rseq_op opvec[] = {
		[0] = {
			.op = RSEQ_COMPARE_EQ_OP,
			.len = len,
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)expect,
		},
		[1] = {
			.op = RSEQ_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)_new,
		},
		[2] = {
			.op = RSEQ_MEMCPY_OP,
			.len = copylen,
			.u.memcpy_op.dst = (unsigned long)dst,
			.u.memcpy_op.src = (unsigned long)src,
		},
	};

	return rseq_op(opvec, ARRAY_SIZE(opvec), cpu, 0);
}
