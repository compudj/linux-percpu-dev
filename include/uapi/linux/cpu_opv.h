#ifndef _UAPI_LINUX_CPU_OPV_H
#define _UAPI_LINUX_CPU_OPV_H

/*
 * linux/cpu_opv.h
 *
 * CPU preempt-off operation vector system call API
 *
 * Copyright (c) 2017 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#ifdef __KERNEL__
# include <linux/types.h>
#else
# include <stdint.h>
#endif

#include <linux/types_32_64.h>

#define CPU_OP_VEC_LEN_MAX		16
#define CPU_OP_ARG_LEN_MAX		24
/* Maximum data len per operation. */
#define CPU_OP_DATA_LEN_MAX		4096
/*
 * Maximum data len for overall vector. Restrict the amount of user-space
 * data touched by the kernel in non-preemptible context, so it does not
 * introduce long scheduler latencies.
 * This allows one copy of up to 4096 bytes, and 15 operations touching 8
 * bytes each.
 * This limit is applied to the sum of length specified for all operations
 * in a vector.
 */
#define CPU_OP_MEMCPY_EXPECT_LEN	4096
#define CPU_OP_EXPECT_LEN		8
#define CPU_OP_VEC_DATA_LEN_MAX		\
	(CPU_OP_MEMCPY_EXPECT_LEN +	\
	 (CPU_OP_VEC_LEN_MAX - 1) * CPU_OP_EXPECT_LEN)

enum cpu_op_flags {
	CPU_OP_NR_FLAG =	(1U << 0),
};

enum cpu_op_type {
	/* compare */
	CPU_COMPARE_EQ_OP,
	CPU_COMPARE_NE_OP,
	/* memcpy */
	CPU_MEMCPY_OP,
	/* arithmetic */
	CPU_ADD_OP,
	/* bitwise */
	CPU_OR_OP,
	CPU_AND_OP,
	CPU_XOR_OP,
	/* shift */
	CPU_LSHIFT_OP,
	CPU_RSHIFT_OP,
	/* memory barrier */
	CPU_MB_OP,

	NR_CPU_OPS,
};

/* Vector of operations to perform. Limited to 16. */
struct cpu_op {
	/* enum cpu_op_type. */
	int32_t op;
	/* data length, in bytes. */
	uint32_t len;
	union {
		struct {
			LINUX_FIELD_u32_u64(a);
			LINUX_FIELD_u32_u64(b);
			uint8_t expect_fault_a;
			uint8_t expect_fault_b;
		} compare_op;
		struct {
			LINUX_FIELD_u32_u64(dst);
			LINUX_FIELD_u32_u64(src);
			uint8_t expect_fault_dst;
			uint8_t expect_fault_src;
		} memcpy_op;
		struct {
			LINUX_FIELD_u32_u64(p);
			int64_t count;
			uint8_t expect_fault_p;
		} arithmetic_op;
		struct {
			LINUX_FIELD_u32_u64(p);
			uint64_t mask;
			uint8_t expect_fault_p;
		} bitwise_op;
		struct {
			LINUX_FIELD_u32_u64(p);
			uint32_t bits;
			uint8_t expect_fault_p;
		} shift_op;
		char __padding[CPU_OP_ARG_LEN_MAX];
	} u;
};

#endif /* _UAPI_LINUX_CPU_OPV_H */
