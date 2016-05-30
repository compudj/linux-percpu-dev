/*
 * rseq-ppc.h
 *
 * (C) Copyright 2016 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * (C) Copyright 2016 - Boqun Feng <boqun.feng@gmail.com>
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

#define smp_mb()	__asm__ __volatile__ ("sync" : : : "memory")
#define smp_lwsync()	__asm__ __volatile__ ("lwsync" : : : "memory")
#define smp_rmb()	smp_lwsync()
#define smp_wmb()	smp_lwsync()

#define smp_load_acquire(p)						\
__extension__ ({							\
	__typeof(*p) ____p1 = READ_ONCE(*p);				\
	smp_lwsync();							\
	____p1;								\
})

#define smp_acquire__after_ctrl_dep()	smp_lwsync()

#define smp_store_release(p, v)						\
do {									\
	smp_lwsync();							\
	WRITE_ONCE(*p, v);						\
} while (0)

#define has_fast_acquire_release()	0

#ifdef __PPC64__
#define has_single_copy_load_64()	1
#else
#define has_single_copy_load_64()	0
#endif

/*
 * The __rseq_table section can be used by debuggers to better handle
 * single-stepping through the restartable critical sections.
 */

#ifdef __PPC64__

#define RSEQ_FINISH_ASM(_target_final, _to_write_final, _start_value, \
		_failure, _spec_store, _spec_input, \
		_final_store, _final_input, _extra_clobber, \
		_setup, _teardown, _scratch) \
	__asm__ __volatile__ goto ( \
		".pushsection __rseq_table, \"aw\"\n\t" \
		".balign 32\n\t" \
		"3:\n\t" \
		".quad 1f, 2f, 4f, 0x0\n\t" \
		".popsection\n\t" \
		"1:\n\t" \
		_setup \
		RSEQ_INJECT_ASM(1) \
		"lis %%r17, (3b)@highest\n\t" \
		"ori %%r17, %%r17, (3b)@higher\n\t" \
		"rldicr %%r17, %%r17, 32, 31\n\t" \
		"oris %%r17, %%r17, (3b)@h\n\t" \
		"ori %%r17, %%r17, (3b)@l\n\t" \
		"std %%r17, 0(%[rseq_cs])\n\t" \
		RSEQ_INJECT_ASM(2) \
		"lwz %%r17, %[current_event_counter]\n\t" \
		"cmpw cr7, %[start_event_counter], %%r17\n\t" \
		"bne- cr7, 4f\n\t" \
		RSEQ_INJECT_ASM(3) \
		_spec_store \
		_final_store \
		"2:\n\t" \
		RSEQ_INJECT_ASM(5) \
		"li %%r17, 0\n\t" \
		"std %%r17, 0(%[rseq_cs])\n\t" \
		_teardown \
		"b 5f\n\t" \
		"4:\n\t" \
		"li %%r17, 0\n\t" \
		"std %%r17, 0(%[rseq_cs])\n\t" \
		_teardown \
		"b %l[failure]\n\t" \
		"5:\n\t" \
		: /* gcc asm goto does not allow outputs */ \
		: [start_event_counter]"r"((_start_value).event_counter), \
		  [current_event_counter]"m"((_start_value).rseqp->u.e.event_counter), \
		  [rseq_cs]"b"(&(_start_value).rseqp->rseq_cs) \
		  _spec_input \
		  _final_input \
		  RSEQ_INJECT_INPUT \
		: "r17", "memory", "cc" \
		  _extra_clobber \
		  RSEQ_INJECT_CLOBBER \
		: _failure \
	)

#define RSEQ_FINISH_FINAL_STORE_ASM() \
		"std %[to_write_final], 0(%[target_final])\n\t"

#define RSEQ_FINISH_FINAL_STORE_RELEASE_ASM() \
		"lwsync\n\t" \
		RSEQ_FINISH_FINAL_STORE_ASM()

#define RSEQ_FINISH_FINAL_STORE_INPUT(_target_final, _to_write_final) \
		, [to_write_final]"r"(_to_write_final), \
		[target_final]"b"(_target_final)

#define RSEQ_FINISH_SPECULATIVE_STORE_ASM() \
		"std %[to_write_spec], 0(%[target_spec])\n\t" \
		RSEQ_INJECT_ASM(4)

#define RSEQ_FINISH_SPECULATIVE_STORE_INPUT(_target_spec, _to_write_spec) \
		, [to_write_spec]"r"(_to_write_spec), \
		[target_spec]"b"(_target_spec)

/* TODO: implement a faster memcpy. */
#define RSEQ_FINISH_MEMCPY_STORE_ASM() \
		"cmpdi %%r19, 0\n\t" \
		"beq 333f\n\t" \
		"addi %%r20, %%r20, -1\n\t" \
		"addi %%r21, %%r21, -1\n\t" \
		"222:\n\t" \
		"lbzu %%r18, 1(%%r20)\n\t" \
		"stbu %%r18, 1(%%r21)\n\t" \
		"addi %%r19, %%r19, -1\n\t" \
		"cmpdi %%r19, 0\n\t" \
		"bne 222b\n\t" \
		"333:\n\t" \
		RSEQ_INJECT_ASM(4)

#define RSEQ_FINISH_MEMCPY_STORE_INPUT(_target_memcpy, _to_write_memcpy, _len_memcpy) \
		, [to_write_memcpy]"r"(_to_write_memcpy), \
		[target_memcpy]"r"(_target_memcpy), \
		[len_memcpy]"r"(_len_memcpy)

#define RSEQ_FINISH_MEMCPY_CLOBBER() \
		, "r18", "r19", "r20", "r21"

#define RSEQ_FINISH_MEMCPY_SCRATCH()

/*
 * We use extra registers to hold the input registers, and we don't need to
 * save and restore the input registers.
 */
#define RSEQ_FINISH_MEMCPY_SETUP() \
		"mr %%r19, %[len_memcpy]\n\t" \
		"mr %%r20, %[to_write_memcpy]\n\t" \
		"mr %%r21, %[target_memcpy]\n\t" \

#define RSEQ_FINISH_MEMCPY_TEARDOWN()

#else	/* #ifdef __PPC64__ */

#define RSEQ_FINISH_ASM(_target_final, _to_write_final, _start_value, \
		_failure, _spec_store, _spec_input, \
		_final_store, _final_input, _extra_clobber, \
		_setup, _teardown, _scratch) \
	__asm__ __volatile__ goto ( \
		".pushsection __rseq_table, \"aw\"\n\t" \
		".balign 32\n\t" \
		"3:\n\t" \
		/* 32-bit only supported on BE */ \
		".long 0x0, 1f, 0x0, 2f, 0x0, 4f, 0x0, 0x0\n\t" \
		".popsection\n\t" \
		"1:\n\t" \
		_setup \
		RSEQ_INJECT_ASM(1) \
		"lis %%r17, (3b)@ha\n\t" \
		"addi %%r17, %%r17, (3b)@l\n\t" \
		"stw %%r17, 0(%[rseq_cs])\n\t" \
		RSEQ_INJECT_ASM(2) \
		"lwz %%r17, %[current_event_counter]\n\t" \
		"cmpw cr7, %[start_event_counter], %%r17\n\t" \
		"bne- cr7, 4f\n\t" \
		RSEQ_INJECT_ASM(3) \
		_spec_store \
		_final_store \
		"2:\n\t" \
		RSEQ_INJECT_ASM(5) \
		"li %%r17, 0\n\t" \
		"stw %%r17, 0(%[rseq_cs])\n\t" \
		_teardown \
		"b 5f\n\t" \
		"4:\n\t" \
		"li %%r17, 0\n\t" \
		"std %%r17, 0(%[rseq_cs])\n\t" \
		_teardown \
		"b %l[failure]\n\t" \
		"5:\n\t" \
		: /* gcc asm goto does not allow outputs */ \
		: [start_event_counter]"r"((_start_value).event_counter), \
		  [current_event_counter]"m"((_start_value).rseqp->u.e.event_counter), \
		  [rseq_cs]"b"(&(_start_value).rseqp->rseq_cs) \
		  _spec_input \
		  _final_input \
		  RSEQ_INJECT_INPUT \
		: "r17", "memory", "cc" \
		  _extra_clobber \
		  RSEQ_INJECT_CLOBBER \
		: _failure \
	)

#define RSEQ_FINISH_FINAL_STORE_ASM() \
		"stw %[to_write_final], 0(%[target_final])\n\t"

#define RSEQ_FINISH_FINAL_STORE_RELEASE_ASM() \
		"lwsync\n\t" \
		RSEQ_FINISH_FINAL_STORE_ASM()

#define RSEQ_FINISH_FINAL_STORE_INPUT(_target_final, _to_write_final) \
		, [to_write_final]"r"(_to_write_final), \
		[target_final]"b"(_target_final)

#define RSEQ_FINISH_SPECULATIVE_STORE_ASM() \
		"stw %[to_write_spec], 0(%[target_spec])\n\t" \
		RSEQ_INJECT_ASM(4)

#define RSEQ_FINISH_SPECULATIVE_STORE_INPUT(_target_spec, _to_write_spec) \
		, [to_write_spec]"r"(_to_write_spec), \
		[target_spec]"b"(_target_spec)

/* TODO: implement a faster memcpy. */
#define RSEQ_FINISH_MEMCPY_STORE_ASM() \
		"cmpwi %%r19, 0\n\t" \
		"beq 333f\n\t" \
		"addi %%r20, %%r20, -1\n\t" \
		"addi %%r21, %%r21, -1\n\t" \
		"222:\n\t" \
		"lbzu %%r18, 1(%%r20)\n\t" \
		"stbu %%r18, 1(%%r21)\n\t" \
		"addi %%r19, %%r19, -1\n\t" \
		"cmpwi %%r19, 0\n\t" \
		"bne 222b\n\t" \
		"333:\n\t" \
		RSEQ_INJECT_ASM(4)

#define RSEQ_FINISH_MEMCPY_STORE_INPUT(_target_memcpy, _to_write_memcpy, _len_memcpy) \
		, [to_write_memcpy]"r"(_to_write_memcpy), \
		[target_memcpy]"r"(_target_memcpy), \
		[len_memcpy]"r"(_len_memcpy)

#define RSEQ_FINISH_MEMCPY_CLOBBER() \
		, "r18", "r19", "r20", "r21"

#define RSEQ_FINISH_MEMCPY_SCRATCH()

/*
 * We use extra registers to hold the input registers, and we don't need to
 * save and restore the input registers.
 */
#define RSEQ_FINISH_MEMCPY_SETUP() \
		"mr %%r19, %[len_memcpy]\n\t" \
		"mr %%r20, %[to_write_memcpy]\n\t" \
		"mr %%r21, %[target_memcpy]\n\t" \

#define RSEQ_FINISH_MEMCPY_TEARDOWN()

#endif	/* #else #ifdef __PPC64__ */
