#ifndef _UAPI_LINUX_RSEQ_H
#define _UAPI_LINUX_RSEQ_H

/*
 * linux/rseq.h
 *
 * Restartable sequences system call API
 *
 * Copyright (c) 2015-2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
#else	/* #ifdef __KERNEL__ */
# include <stdint.h>
#endif	/* #else #ifdef __KERNEL__ */

#include <asm/byteorder.h>

#ifdef __LP64__
# define RSEQ_FIELD_u32_u64(field)	uint64_t field
#elif defined(__BYTE_ORDER) ? \
	__BYTE_ORDER == __BIG_ENDIAN : defined(__BIG_ENDIAN)
# define RSEQ_FIELD_u32_u64(field)	uint32_t _padding ## field, field
#else
# define RSEQ_FIELD_u32_u64(field)	uint32_t field, _padding ## field
#endif

enum rseq_flags {
	RSEQ_FORCE_UNREGISTER = (1 << 0),
};

enum rseq_cs_flags {
	RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT	= (1U << 0),
	RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL	= (1U << 1),
	RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE	= (1U << 2),
};

/*
 * struct rseq_cs is aligned on 4 * 8 bytes to ensure it is always
 * contained within a single cache-line. It is usually declared as
 * link-time constant data.
 */
struct rseq_cs {
	RSEQ_FIELD_u32_u64(start_ip);
	RSEQ_FIELD_u32_u64(post_commit_ip);
	RSEQ_FIELD_u32_u64(abort_ip);
	uint32_t flags;
} __attribute__((aligned(4 * sizeof(uint64_t))));

union rseq_cpu_event {
	struct {
		/*
		 * Restartable sequences cpu_id field.
		 * Updated by the kernel, and read by user-space with
		 * single-copy atomicity semantics. Aligned on 32-bit.
		 * Negative values are reserved for user-space.
		 */
		int32_t cpu_id;
		/*
		 * Restartable sequences event_counter field.
		 * Updated by the kernel, and read by user-space with
		 * single-copy atomicity semantics. Aligned on 32-bit.
		 */
		uint32_t event_counter;
	} e;
	/*
	 * On architectures with 64-bit aligned reads, both cpu_id and
	 * event_counter can be read with single-copy atomicity
	 * semantics.
	 */
	uint64_t v;
};

/*
 * struct rseq is aligned on 4 * 8 bytes to ensure it is always
 * contained within a single cache-line.
 */
struct rseq {
	union rseq_cpu_event u;
	/*
	 * Restartable sequences rseq_cs field.
	 * Contains NULL when no critical section is active for the
	 * current thread, or holds a pointer to the currently active
	 * struct rseq_cs.
	 * Updated by user-space at the beginning and end of assembly
	 * instruction sequence block, and by the kernel when it
	 * restarts an assembly instruction sequence block. Read by the
	 * kernel with single-copy atomicity semantics. Aligned on
	 * 64-bit.
	 */
	RSEQ_FIELD_u32_u64(rseq_cs);
	/*
	 * - RSEQ_DISABLE flag:
	 *
	 * Fallback fast-track flag for single-stepping.
	 * Set by user-space if lack of progress is detected.
	 * Cleared by user-space after rseq finish.
	 * Read by the kernel.
	 * - RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT
	 *     Inhibit instruction sequence block restart and event
	 *     counter increment on preemption for this thread.
	 * - RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL
	 *     Inhibit instruction sequence block restart and event
	 *     counter increment on signal delivery for this thread.
	 * - RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE
	 *     Inhibit instruction sequence block restart and event
	 *     counter increment on migration for this thread.
	 */
	uint32_t flags;
} __attribute__((aligned(4 * sizeof(uint64_t))));

#define RSEQ_OP_VEC_LEN_MAX		16
#define RSEQ_OP_ARG_LEN_MAX		24
#define RSEQ_OP_DATA_LEN_MAX		PAGE_SIZE
#define RSEQ_OP_MAX_PAGES		4	/* Max. pages per op. */

enum rseq_op_type {
	RSEQ_COMPARE_EQ_OP,	/* compare */
	RSEQ_COMPARE_NE_OP,	/* compare */
	RSEQ_MEMCPY_OP,		/* memcpy */
	RSEQ_ADD_OP,		/* arithmetic */
	RSEQ_OR_OP,		/* bitwise */
	RSEQ_AND_OP,		/* bitwise */
	RSEQ_XOR_OP,		/* bitwise */
	RSEQ_LSHIFT_OP,		/* shift */
	RSEQ_RSHIFT_OP,		/* shift */
};

/* Vector of operations to perform. Limited to 16. */
struct rseq_op {
	int32_t op;	/* enum rseq_op_type. */
	uint32_t len;	/* data length, in bytes. */
	union {
		struct {
			RSEQ_FIELD_u32_u64(a);
			RSEQ_FIELD_u32_u64(b);
		} compare_op;
		struct {
			RSEQ_FIELD_u32_u64(dst);
			RSEQ_FIELD_u32_u64(src);
		} memcpy_op;
		struct {
			RSEQ_FIELD_u32_u64(p);
			int64_t count;
		} arithmetic_op;
		struct {
			RSEQ_FIELD_u32_u64(p);
			uint64_t mask;
		} bitwise_op;
		struct {
			RSEQ_FIELD_u32_u64(p);
			uint32_t bits;
		} shift_op;
		char __padding[RSEQ_OP_ARG_LEN_MAX];
	} u;
};

#endif /* _UAPI_LINUX_RSEQ_H */
