/*
 * rseq.h
 *
 * (C) Copyright 2016 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#ifndef RSEQ_H
#define RSEQ_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <linux/rseq.h>

/*
 * Empty code injection macros, override when testing.
 * It is important to consider that the ASM injection macros need to be
 * fully reentrant (e.g. do not modify the stack).
 */
#ifndef RSEQ_INJECT_ASM
#define RSEQ_INJECT_ASM(n)
#endif

#ifndef RSEQ_INJECT_C
#define RSEQ_INJECT_C(n)
#endif

#ifndef RSEQ_INJECT_INPUT
#define RSEQ_INJECT_INPUT
#endif

#ifndef RSEQ_INJECT_CLOBBER
#define RSEQ_INJECT_CLOBBER
#endif

#ifndef RSEQ_INJECT_FAILED
#define RSEQ_INJECT_FAILED
#endif

#ifndef RSEQ_FALLBACK_CNT
#define RSEQ_FALLBACK_CNT	3
#endif

extern __thread volatile struct rseq __rseq_abi;
extern int rseq_has_sys_membarrier;

#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)
#define barrier()		__asm__ __volatile__("" : : : "memory")

#define ACCESS_ONCE(x)		(*(__volatile__  __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v)	__extension__ ({ ACCESS_ONCE(x) = (v); })
#define READ_ONCE(x)		ACCESS_ONCE(x)

#if defined(__x86_64__) || defined(__i386__)
#include <rseq-x86.h>
#elif defined(__ARMEL__)
#include <rseq-arm.h>
#elif defined(__PPC__)
#include <rseq-ppc.h>
#else
#error unsupported target
#endif

/* State returned by rseq_start, passed as argument to rseq_finish. */
struct rseq_state {
	volatile struct rseq *rseqp;
	int32_t cpu_id;		/* cpu_id at start. */
	uint32_t event_counter;	/* event_counter at start. */
};

int rseq_op(struct rseq_op *rseqop, int rseqopcnt, int cpu, int flags);

/*
 * Register rseq for the current thread. This needs to be called once
 * by any thread which uses restartable sequences, before they start
 * using restartable sequences. If initialization is not invoked, or if
 * it fails, the restartable critical sections will fall-back on locking
 * (rseq_lock).
 */
int rseq_register_current_thread(void);

/*
 * Unregister rseq for current thread.
 */
int rseq_unregister_current_thread(void);

/*
 * Restartable sequence fallback for reading the current CPU number.
 */
int rseq_fallback_current_cpu(void);

static inline int32_t rseq_cpu_at_start(struct rseq_state start_value)
{
	return start_value.cpu_id;
}

static inline int32_t rseq_current_cpu_raw(void)
{
	return ACCESS_ONCE(__rseq_abi.u.e.cpu_id);
}

static inline int32_t rseq_current_cpu(void)
{
	int32_t cpu;

	cpu = rseq_current_cpu_raw();
	if (unlikely(cpu < 0))
		cpu = rseq_fallback_current_cpu();
	return cpu;
}

static inline __attribute__((always_inline))
struct rseq_state rseq_start(void)
{
	struct rseq_state result;

	result.rseqp = &__rseq_abi;
	if (has_single_copy_load_64()) {
		union rseq_cpu_event u;

		u.v = ACCESS_ONCE(result.rseqp->u.v);
		result.event_counter = u.e.event_counter;
		result.cpu_id = u.e.cpu_id;
	} else {
		result.event_counter =
			ACCESS_ONCE(result.rseqp->u.e.event_counter);
		/* load event_counter before cpu_id. */
		RSEQ_INJECT_C(6)
		result.cpu_id = ACCESS_ONCE(result.rseqp->u.e.cpu_id);
	}
	RSEQ_INJECT_C(7)
	/*
	 * Ensure the compiler does not re-order loads of protected
	 * values before we load the event counter.
	 */
	barrier();
	return result;
}

enum rseq_finish_type {
	RSEQ_FINISH_SINGLE,
	RSEQ_FINISH_TWO,
	RSEQ_FINISH_MEMCPY,
};

/*
 * p_spec and to_write_spec are used for a speculative write attempted
 * near the end of the restartable sequence. A rseq_finish2 may fail
 * even after this write takes place.
 *
 * p_final and to_write_final are used for the final write. If this
 * write takes place, the rseq_finish2 is guaranteed to succeed.
 */
static inline __attribute__((always_inline))
bool __rseq_finish(intptr_t *p_spec, intptr_t to_write_spec,
		void *p_memcpy, void *to_write_memcpy, size_t len_memcpy,
		intptr_t *p_final, intptr_t to_write_final,
		struct rseq_state start_value,
		enum rseq_finish_type type, bool release)
{
	RSEQ_INJECT_C(9)

	switch (type) {
	case RSEQ_FINISH_SINGLE:
		RSEQ_FINISH_ASM(p_final, to_write_final, start_value, failure,
			/* no speculative write */, /* no speculative write */,
			RSEQ_FINISH_FINAL_STORE_ASM(),
			RSEQ_FINISH_FINAL_STORE_INPUT(p_final, to_write_final),
			/* no extra clobber */, /* no arg */, /* no arg */,
			/* no arg */
		);
		break;
	case RSEQ_FINISH_TWO:
		if (release) {
			RSEQ_FINISH_ASM(p_final, to_write_final, start_value, failure,
				RSEQ_FINISH_SPECULATIVE_STORE_ASM(),
				RSEQ_FINISH_SPECULATIVE_STORE_INPUT(p_spec, to_write_spec),
				RSEQ_FINISH_FINAL_STORE_RELEASE_ASM(),
				RSEQ_FINISH_FINAL_STORE_INPUT(p_final, to_write_final),
				/* no extra clobber */, /* no arg */, /* no arg */,
				/* no arg */
			);
		} else {
			RSEQ_FINISH_ASM(p_final, to_write_final, start_value, failure,
				RSEQ_FINISH_SPECULATIVE_STORE_ASM(),
				RSEQ_FINISH_SPECULATIVE_STORE_INPUT(p_spec, to_write_spec),
				RSEQ_FINISH_FINAL_STORE_ASM(),
				RSEQ_FINISH_FINAL_STORE_INPUT(p_final, to_write_final),
				/* no extra clobber */, /* no arg */, /* no arg */,
				/* no arg */
			);
		}
		break;
	case RSEQ_FINISH_MEMCPY:
		if (release) {
			RSEQ_FINISH_ASM(p_final, to_write_final, start_value, failure,
				RSEQ_FINISH_MEMCPY_STORE_ASM(),
				RSEQ_FINISH_MEMCPY_STORE_INPUT(p_memcpy, to_write_memcpy, len_memcpy),
				RSEQ_FINISH_FINAL_STORE_RELEASE_ASM(),
				RSEQ_FINISH_FINAL_STORE_INPUT(p_final, to_write_final),
				RSEQ_FINISH_MEMCPY_CLOBBER(),
				RSEQ_FINISH_MEMCPY_SETUP(),
				RSEQ_FINISH_MEMCPY_TEARDOWN(),
				RSEQ_FINISH_MEMCPY_SCRATCH()
			);
		} else {
			RSEQ_FINISH_ASM(p_final, to_write_final, start_value, failure,
				RSEQ_FINISH_MEMCPY_STORE_ASM(),
				RSEQ_FINISH_MEMCPY_STORE_INPUT(p_memcpy, to_write_memcpy, len_memcpy),
				RSEQ_FINISH_FINAL_STORE_ASM(),
				RSEQ_FINISH_FINAL_STORE_INPUT(p_final, to_write_final),
				RSEQ_FINISH_MEMCPY_CLOBBER(),
				RSEQ_FINISH_MEMCPY_SETUP(),
				RSEQ_FINISH_MEMCPY_TEARDOWN(),
				RSEQ_FINISH_MEMCPY_SCRATCH()
			);
		}
		break;
	}
	return true;
failure:
	RSEQ_INJECT_FAILED
	return false;
}

static inline __attribute__((always_inline))
bool rseq_finish(intptr_t *p, intptr_t to_write,
		struct rseq_state start_value)
{
	return __rseq_finish(NULL, 0,
			NULL, NULL, 0,
			p, to_write, start_value,
			RSEQ_FINISH_SINGLE, false);
}

static inline __attribute__((always_inline))
bool rseq_finish2(intptr_t *p_spec, intptr_t to_write_spec,
		intptr_t *p_final, intptr_t to_write_final,
		struct rseq_state start_value)
{
	return __rseq_finish(p_spec, to_write_spec,
			NULL, NULL, 0,
			p_final, to_write_final, start_value,
			RSEQ_FINISH_TWO, false);
}

static inline __attribute__((always_inline))
bool rseq_finish2_release(intptr_t *p_spec, intptr_t to_write_spec,
		intptr_t *p_final, intptr_t to_write_final,
		struct rseq_state start_value)
{
	return __rseq_finish(p_spec, to_write_spec,
			NULL, NULL, 0,
			p_final, to_write_final, start_value,
			RSEQ_FINISH_TWO, true);
}

static inline __attribute__((always_inline))
bool rseq_finish_memcpy(void *p_memcpy, void *to_write_memcpy,
		size_t len_memcpy, intptr_t *p_final, intptr_t to_write_final,
		struct rseq_state start_value)
{
	return __rseq_finish(NULL, 0,
			p_memcpy, to_write_memcpy, len_memcpy,
			p_final, to_write_final, start_value,
			RSEQ_FINISH_MEMCPY, false);
}

static inline __attribute__((always_inline))
bool rseq_finish_memcpy_release(void *p_memcpy, void *to_write_memcpy,
		size_t len_memcpy, intptr_t *p_final, intptr_t to_write_final,
		struct rseq_state start_value)
{
	return __rseq_finish(NULL, 0,
			p_memcpy, to_write_memcpy, len_memcpy,
			p_final, to_write_final, start_value,
			RSEQ_FINISH_MEMCPY, true);
}

int rseq_op_cmpstore(void *v, void *expect, void *_new, size_t len, int cpu);
int rseq_op_2cmp1store(void *v, void *expect, void *_new, void *check2,
		void *expect2, size_t len, int cpu);
int rseq_op_1cmp2store(void *v, void *expect, void *_new,
		void *v2, void *_new2, size_t len, int cpu);
int rseq_op_cmpxchg(void *v, void *expect, void *old, void *_new,
		size_t len, int cpu);
int rseq_op_add(void *v, int64_t count, size_t len, int cpu);
int rseq_op_cmpstorememcpy(void *v, void *expect, void *_new, size_t len,
		void *dst, void *src, size_t copylen, int cpu);

#endif  /* RSEQ_H_ */
