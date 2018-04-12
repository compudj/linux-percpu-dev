/*
 * percpu-op.h
 *
 * (C) Copyright 2017 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef PERCPU_OP_H
#define PERCPU_OP_H

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include "rseq.h"
#include "cpu-op.h"

static inline __attribute__((always_inline))
int percpu_cmpeqv_storev(intptr_t *v, intptr_t expect, intptr_t newv,
			 int cpu)
{
	int ret;

	ret = rseq_cmpeqv_storev(v, expect, newv, cpu);
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		return cpu_op_cmpeqv_storev(v, expect, newv, cpu);
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_cmpnev_storeoffp_load(intptr_t *v, intptr_t expectnot,
			       off_t voffp, intptr_t *load, int cpu)
{
	int ret;

	ret = rseq_cmpnev_storeoffp_load(v, expectnot, voffp, load, cpu);
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		return cpu_op_cmpnev_storeoffp_load(v, expectnot, voffp,
						    load, cpu);
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_addv(intptr_t *v, intptr_t count, int cpu)
{
	if (rseq_unlikely(rseq_addv(v, count, cpu)))
		return cpu_op_addv(v, count, cpu);
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
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		return cpu_op_cmpeqv_storev_storev(v, expect, v2, newv2,
						   newv, cpu);
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
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		return cpu_op_cmpeqv_storev_mb_storev(v, expect, v2, newv2,
						      newv, cpu);
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
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		return cpu_op_cmpeqv_cmpeqv_storev(v, expect, v2, expect2,
						   newv, cpu);
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
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		return cpu_op_cmpeqv_memcpy_storev(v, expect, dst, src, len,
						   newv, cpu);
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
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		return cpu_op_cmpeqv_memcpy_mb_storev(v, expect, dst, src, len,
						      newv, cpu);
	}
	return 0;
}

#endif  /* PERCPU_OP_H_ */
