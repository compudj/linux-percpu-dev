// SPDX-License-Identifier: LGPL-2.1
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
#include <limits.h>

#include "rseq.h"

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

__thread struct rseq __rseq_abi = {
	.cpu_id = RSEQ_CPU_ID_UNINITIALIZED,
};

/*
 * Shared with other libraries. This library may take rseq ownership if it is
 * still 0 when executing the library constructor. Set to 1 by library
 * constructor when handling rseq. Set to 0 in destructor if handling rseq.
 */
int __rseq_handled;

/* Whether this library have ownership of rseq registration. */
static int rseq_ownership;

static __thread volatile uint32_t __rseq_refcount;

static int sys_rseq(void *ptr, uint32_t rseq_len,
		    int flags, uint32_t sig)
{
	return syscall(__NR_rseq, ptr, rseq_len, flags, sig);
}

int rseq_register_current_thread(void)
{
	int rc;

	rc = sys_rseq(NULL, 0, RSEQ_FLAG_SET_KTLS_THREAD, 0);
	if (rc) {
		abort();
	}
	return 0;
}

int rseq_unregister_current_thread(void)
{
	return 0;
}

int32_t rseq_fallback_current_cpu(void)
{
	int32_t cpu;

	cpu = sched_getcpu();
	if (cpu < 0) {
		perror("sched_getcpu()");
		abort();
	}
	return cpu;
}

void __attribute__((constructor)) rseq_init(void)
{
	int rc;
	long rseq_abi_offset;
	struct rseq_ktls_layout layout;
	struct rseq_ktls_offset offset;

	/* Check whether rseq is handled by another library. */
	if (__rseq_handled)
		return;
	__rseq_handled = 1;
	rseq_ownership = 1;

	rseq_abi_offset = (long) &__rseq_abi - (long) rseq_get_thread_pointer();

	rc = sys_rseq(&layout, 0, RSEQ_FLAG_GET_KTLS_LAYOUT, 0);
	if (rc) {
		abort();
	}
	if (layout.size > sizeof(struct rseq) || layout.alignment > __alignof__(struct rseq)) {
		abort();
	}
	offset.offset = rseq_abi_offset;
	rc = sys_rseq(&offset, 0, RSEQ_FLAG_SET_KTLS_OFFSET, 0);
	if (rc) {
		abort();
	}
	rc = sys_rseq(NULL, 0, RSEQ_FLAG_SET_SIG, RSEQ_SIG);
	if (rc) {
		abort();
	}

	assert(rseq_current_cpu_raw() >= 0);
}

void __attribute__((destructor)) rseq_fini(void)
{
	if (!rseq_ownership)
		return;
	__rseq_handled = 0;
	rseq_ownership = 0;
}
