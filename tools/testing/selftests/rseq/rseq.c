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

#include "rseq.h"

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

__attribute__((weak)) __thread volatile struct rseq __rseq_abi = {
	.u.e.cpu_id = -1,
};

static int sys_rseq(volatile struct rseq *rseq_abi, int flags)
{
	return syscall(__NR_rseq, rseq_abi, flags);
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
