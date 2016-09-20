/*
 * rseq-arm.h
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

#define smp_mb()	__asm__ __volatile__ ("dmb" : : : "memory")
#define smp_rmb()	__asm__ __volatile__ ("dmb" : : : "memory")
#define smp_wmb()	__asm__ __volatile__ ("dmb" : : : "memory")

#define smp_load_acquire(p)						\
__extension__ ({							\
	__typeof(*p) ____p1 = READ_ONCE(*p);				\
	smp_mb();							\
	____p1;								\
})

#define smp_acquire__after_ctrl_dep()	smp_rmb()

#define smp_store_release(p, v)						\
do {									\
	smp_mb();							\
	WRITE_ONCE(*p, v);						\
} while (0)

#define has_fast_acquire_release()	0
#define has_single_copy_load_64()	1

/*
 * The __rseq_table section can be used by debuggers to better handle
 * single-stepping through the restartable critical sections.
 *
 * Load the immediate value 0 into register r1 right after the ldr
 * instruction to improve instruction-level parallelism: load the
 * constant while the processor is stalled waiting for the load to
 * complete, which is required by the following comparison and branch.
 */

#define RSEQ_FINISH_ASM(_target_final, _to_write_final, _start_value, \
		_failure, _spec_store, _spec_input, \
		_final_store, _final_input, _extra_clobber, \
		_setup, _teardown, _scratch) \
do { \
	_scratch \
	__asm__ __volatile__ goto ( \
		".pushsection __rseq_table, \"aw\"\n\t" \
		".balign 32\n\t" \
		".word 1f, 0x0, 2f, 0x0, 5f, 0x0, 0x0, 0x0\n\t" \
		".popsection\n\t" \
		"1:\n\t" \
		_setup \
		RSEQ_INJECT_ASM(1) \
		"adr r0, 3f\n\t" \
		"str r0, [%[rseq_cs]]\n\t" \
		RSEQ_INJECT_ASM(2) \
		"ldr r0, %[current_event_counter]\n\t" \
		"mov r1, #0\n\t" \
		"cmp %[start_event_counter], r0\n\t" \
		"bne 5f\n\t" \
		RSEQ_INJECT_ASM(3) \
		_spec_store \
		_final_store \
		"2:\n\t" \
		RSEQ_INJECT_ASM(5) \
		"str r1, [%[rseq_cs]]\n\t" \
		_teardown \
		"b 4f\n\t" \
		".balign 32\n\t" \
		"3:\n\t" \
		".word 1b, 0x0, 2b, 0x0, 5f, 0x0, 0x0, 0x0\n\t" \
		"5:\n\t" \
		"mov r1, #0\n\t" \
		"str r1, [%[rseq_cs]]\n\t" \
		_teardown \
		"b %l[failure]\n\t" \
		"4:\n\t" \
		: /* gcc asm goto does not allow outputs */ \
		: [start_event_counter]"r"((_start_value).event_counter), \
		  [current_event_counter]"m"((_start_value).rseqp->u.e.event_counter), \
		  [rseq_cs]"r"(&(_start_value).rseqp->rseq_cs) \
		  _spec_input \
		  _final_input \
		  RSEQ_INJECT_INPUT \
		: "r0", "r1", "memory", "cc" \
		  _extra_clobber \
		  RSEQ_INJECT_CLOBBER \
		: _failure \
	); \
} while (0)

#define RSEQ_FINISH_FINAL_STORE_ASM() \
		"str %[to_write_final], [%[target_final]]\n\t"

#define RSEQ_FINISH_FINAL_STORE_RELEASE_ASM() \
		"dmb\n\t" \
		RSEQ_FINISH_FINAL_STORE_ASM()

#define RSEQ_FINISH_FINAL_STORE_INPUT(_target_final, _to_write_final) \
		, [to_write_final]"r"(_to_write_final), \
		[target_final]"r"(_target_final)

#define RSEQ_FINISH_SPECULATIVE_STORE_ASM() \
		"str %[to_write_spec], [%[target_spec]]\n\t" \
		RSEQ_INJECT_ASM(4)

#define RSEQ_FINISH_SPECULATIVE_STORE_INPUT(_target_spec, _to_write_spec) \
		, [to_write_spec]"r"(_to_write_spec), \
		[target_spec]"r"(_target_spec)

/* TODO: implement a faster memcpy. */
#define RSEQ_FINISH_MEMCPY_STORE_ASM() \
		"cmp %[len_memcpy], #0\n\t" \
		"beq 333f\n\t" \
		"222:\n\t" \
		"ldrb %%r0, [%[to_write_memcpy]]\n\t" \
		"strb %%r0, [%[target_memcpy]]\n\t" \
		"adds %[to_write_memcpy], #1\n\t" \
		"adds %[target_memcpy], #1\n\t" \
		"subs %[len_memcpy], #1\n\t" \
		"bne 222b\n\t" \
		"333:\n\t" \
		RSEQ_INJECT_ASM(4)

#define RSEQ_FINISH_MEMCPY_STORE_INPUT(_target_memcpy, _to_write_memcpy, _len_memcpy) \
		, [to_write_memcpy]"r"(_to_write_memcpy), \
		[target_memcpy]"r"(_target_memcpy), \
		[len_memcpy]"r"(_len_memcpy), \
		[rseq_scratch0]"m"(rseq_scratch[0]), \
		[rseq_scratch1]"m"(rseq_scratch[1]), \
		[rseq_scratch2]"m"(rseq_scratch[2])

/* We can use r0. */
#define RSEQ_FINISH_MEMCPY_CLOBBER()

#define RSEQ_FINISH_MEMCPY_SCRATCH() \
		uint32_t rseq_scratch[3];

/*
 * We need to save and restore those input registers so they can be
 * modified within the assembly.
 */
#define RSEQ_FINISH_MEMCPY_SETUP() \
		"str %[to_write_memcpy], %[rseq_scratch0]\n\t" \
		"str %[target_memcpy], %[rseq_scratch1]\n\t" \
		"str %[len_memcpy], %[rseq_scratch2]\n\t"

#define RSEQ_FINISH_MEMCPY_TEARDOWN() \
		"ldr %[len_memcpy], %[rseq_scratch2]\n\t" \
		"ldr %[target_memcpy], %[rseq_scratch1]\n\t" \
		"ldr %[to_write_memcpy], %[rseq_scratch0]\n\t"
