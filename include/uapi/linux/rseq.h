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
#else
# include <stdint.h>
#endif

#include <linux/types_32_64.h>

enum rseq_cpu_id_state {
	RSEQ_CPU_ID_UNINITIALIZED		= -1,
	RSEQ_CPU_ID_REGISTRATION_FAILED		= -2,
};

enum rseq_flags {
	RSEQ_FLAG_UNREGISTER = (1 << 0),
};

enum rseq_cs_flags_bit {
	RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT_BIT	= 0,
	RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL_BIT	= 1,
	RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE_BIT	= 2,
};

enum rseq_cs_flags {
	RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT	=
		(1U << RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT_BIT),
	RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL	=
		(1U << RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL_BIT),
	RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE	=
		(1U << RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE_BIT),
};

/*
 * struct rseq_cs is aligned on 4 * 8 bytes to ensure it is always
 * contained within a single cache-line. It is usually declared as
 * link-time constant data.
 */
struct rseq_cs {
	/* Version of this structure. */
	uint32_t version;
	/* enum rseq_cs_flags */
	uint32_t flags;
	LINUX_FIELD_u32_u64(start_ip);
	/* Offset from start_ip. */
	LINUX_FIELD_u32_u64(post_commit_offset);
	LINUX_FIELD_u32_u64(abort_ip);
} __attribute__((aligned(4 * sizeof(uint64_t))));

/*
 * struct rseq is aligned on 4 * 8 bytes to ensure it is always
 * contained within a single cache-line.
 *
 * A single struct rseq per thread is allowed.
 */
struct rseq {
	/*
	 * Restartable sequences cpu_id_start field. Updated by the
	 * kernel, and read by user-space with single-copy atomicity
	 * semantics. Aligned on 32-bit. Always contains a value in the
	 * range of possible CPUs, although the value may not be the
	 * actual current CPU (e.g. if rseq is not initialized). This
	 * CPU number value should always be compared against the value
	 * of the cpu_id field before performing a rseq commit or
	 * returning a value read from a data structure indexed using
	 * the cpu_id_start value.
	 */
	uint32_t cpu_id_start;
	/*
	 * Restartable sequences cpu_id field. Updated by the kernel,
	 * and read by user-space with single-copy atomicity semantics.
	 * Aligned on 32-bit. Values RSEQ_CPU_ID_UNINITIALIZED and
	 * RSEQ_CPU_ID_REGISTRATION_FAILED have a special semantic: the
	 * former means "rseq uninitialized", and latter means "rseq
	 * initialization failed". This value is meant to be read within
	 * rseq critical sections and compared with the cpu_id_start
	 * value previously read, before performing the commit instruction,
	 * or read and compared with the cpu_id_start value before returning
	 * a value loaded from a data structure indexed using the
	 * cpu_id_start value.
	 */
	uint32_t cpu_id;
	/*
	 * Restartable sequences rseq_cs field.
	 *
	 * Contains NULL when no critical section is active for the current
	 * thread, or holds a pointer to the currently active struct rseq_cs.
	 *
	 * Updated by user-space, which sets the address of the currently
	 * active rseq_cs at the beginning of assembly instruction sequence
	 * block, and set to NULL by the kernel when it restarts an assembly
	 * instruction sequence block, as well as when the kernel detects that
	 * it is preempting or delivering a signal outside of the range
	 * targeted by the rseq_cs. Also needs to be set to NULL by user-space
	 * before reclaiming memory that contains the targeted struct rseq_cs.
	 *
	 * Read and set by the kernel with single-copy atomicity semantics.
	 * Set by user-space with single-copy atomicity semantics. Aligned
	 * on 64-bit.
	 */
	LINUX_FIELD_u32_u64(rseq_cs);
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

#endif /* _UAPI_LINUX_RSEQ_H */
