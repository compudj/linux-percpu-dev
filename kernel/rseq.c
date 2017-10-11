/*
 * Restartable sequences system call
 *
 * Restartable sequences are a lightweight interface that allows
 * user-level code to be executed atomically relative to scheduler
 * preemption and signal delivery. Typically used for implementing
 * per-cpu operations.
 *
 * It allows user-space to perform update operations on per-cpu data
 * without requiring heavy-weight atomic operations.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Copyright (C) 2015, Google, Inc.,
 * Paul Turner <pjt@google.com> and Andrew Hunter <ahh@google.com>
 * Copyright (C) 2015-2016, EfficiOS Inc.,
 * Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/rseq.h>
#include <linux/types.h>
#include <asm/ptrace.h>

#define CREATE_TRACE_POINTS
#include <trace/events/rseq.h>

#define TMP_BUFLEN			64
#define NR_PINNED_PAGES_ON_STACK	8

/*
 * The restartable sequences mechanism is the overlap of two distinct
 * restart mechanisms: a sequence counter tracking preemption and signal
 * delivery for high-level code, and an ip-fixup-based mechanism for the
 * final assembly instruction sequence.
 *
 * A high-level summary of the algorithm to use rseq from user-space is
 * as follows:
 *
 * The high-level code between rseq_start() and rseq_finish() loads the
 * current value of the sequence counter in rseq_start(), and then it
 * gets compared with the new current value within the rseq_finish()
 * restartable instruction sequence. Between rseq_start() and
 * rseq_finish(), the high-level code can perform operations that do not
 * have side-effects, such as getting the current CPU number, and
 * loading from variables.
 *
 * Stores are performed at the very end of the restartable sequence
 * assembly block. Each assembly block within rseq_finish() defines a
 * "struct rseq_cs" structure which describes the start_ip and
 * post_commit_ip addresses, as well as the abort_ip address where the
 * kernel should move the thread instruction pointer if a rseq critical
 * section assembly block is preempted or if a signal is delivered on
 * top of a rseq critical section assembly block.
 *
 * Detailed algorithm of rseq use:
 *
 * rseq_start()
 *
 *   0. Userspace loads the current event counter value from the
 *      event_counter field of the registered struct rseq TLS area,
 *
 * rseq_finish()
 *
 *   Steps [1]-[3] (inclusive) need to be a sequence of instructions in
 *   userspace that can handle being moved to the abort_ip between any
 *   of those instructions.
 *
 *   The abort_ip address needs to be less than start_ip, or
 *   greater-or-equal the post_commit_ip. Step [4] and the failure
 *   code step [F1] need to be at addresses lesser than start_ip, or
 *   greater-or-equal the post_commit_ip.
 *
 *       [start_ip]
 *   1.  Userspace stores the address of the struct rseq_cs assembly
 *       block descriptor into the rseq_cs field of the registered
 *       struct rseq TLS area. This update is performed through a single
 *       store, followed by a compiler barrier which prevents the
 *       compiler from moving following loads or stores before this
 *       store.
 *
 *   2.  Userspace tests to see whether the current event counter value
 *       match the value loaded at [0]. Manually jumping to [F1] in case
 *       of a mismatch.
 *
 *       Note that if we are preempted or interrupted by a signal
 *       after [1] and before post_commit_ip, then the kernel also
 *       performs the comparison performed in [2], and conditionally
 *       clears the rseq_cs field of struct rseq, then jumps us to
 *       abort_ip.
 *
 *   3.  Userspace critical section final instruction before
 *       post_commit_ip is the commit. The critical section is
 *       self-terminating.
 *       [post_commit_ip]
 *
 *   4.  Userspace clears the rseq_cs field of the struct rseq
 *       TLS area.
 *
 *   5.  Return true.
 *
 *   On failure at [2]:
 *
 *   F1. Userspace clears the rseq_cs field of the struct rseq
 *       TLS area. Followed by step [F2].
 *
 *       [abort_ip]
 *   F2. Return false.
 */

/*
 * The rseq_event_counter allow user-space to detect preemption and
 * signal delivery. It increments at least once before returning to
 * user-space if a thread is preempted or has a signal delivered. It is
 * not meant to be an exact counter of such events.
 *
 * Overflow of the event counter is not a problem in practice. It
 * increments at most once between each user-space thread instruction
 * executed, so we would need a thread to execute 2^32 instructions or
 * more between rseq_start() and rseq_finish(), while single-stepping,
 * for this to be an issue.
 *
 * On 64-bit architectures, both cpu_id and event_counter can be updated
 * with a single 64-bit store. On 32-bit architectures, __put_user() is
 * expected to perform two 32-bit single-copy stores to guarantee
 * single-copy atomicity semantics for other threads.
 */
static bool rseq_update_cpu_id_event_counter(struct task_struct *t,
		bool inc_event_counter)
{
	union rseq_cpu_event u;

	u.e.cpu_id = raw_smp_processor_id();
	u.e.event_counter = inc_event_counter ? ++t->rseq_event_counter :
			t->rseq_event_counter;
	if (__put_user(u.v, &t->rseq->u.v))
		return false;
	trace_rseq_update(t);
	return true;
}

static bool rseq_get_rseq_cs(struct task_struct *t,
		void __user **start_ip,
		void __user **post_commit_ip,
		void __user **abort_ip,
		uint32_t *cs_flags)
{
	unsigned long ptr;
	struct rseq_cs __user *urseq_cs;
	struct rseq_cs rseq_cs;

	if (__get_user(ptr, &t->rseq->rseq_cs))
		return false;
	if (!ptr)
		return true;
	urseq_cs = (struct rseq_cs __user *)ptr;
	if (copy_from_user(&rseq_cs, urseq_cs, sizeof(rseq_cs)))
		return false;
	/*
	 * We need to clear rseq_cs upon entry into a signal handler
	 * nested on top of a rseq assembly block, so the signal handler
	 * will not be fixed up if itself interrupted by a nested signal
	 * handler or preempted.  We also need to clear rseq_cs if we
	 * preempt or deliver a signal on top of code outside of the
	 * rseq assembly block, to ensure that a following preemption or
	 * signal delivery will not try to perform a fixup needlessly.
	 */
	if (clear_user(&t->rseq->rseq_cs, sizeof(t->rseq->rseq_cs)))
		return false;
	*start_ip = (void __user *)rseq_cs.start_ip;
	*post_commit_ip = (void __user *)rseq_cs.post_commit_ip;
	*abort_ip = (void __user *)rseq_cs.abort_ip;
	*cs_flags = rseq_cs.flags;
	return true;
}

static int rseq_need_restart(struct task_struct *t, uint32_t cs_flags)
{
	bool need_restart = false;
	uint32_t flags;

	/* Get thread flags. */
	if (__get_user(flags, &t->rseq->flags))
		return -EFAULT;

	/* Take into account critical section flags. */
	flags |= cs_flags;

	/*
	 * Restart on signal can only be inhibited when restart on
	 * preempt and restart on migrate are inhibited too. Otherwise,
	 * a preempted signal handler could fail to restart the prior
	 * execution context on sigreturn.
	 */
	if (flags & RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL) {
		if (!(flags & RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE))
			return -EINVAL;
		if (!(flags & RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT))
			return -EINVAL;
	}
	if (t->rseq_migrate
			&& !(flags & RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE))
		need_restart = true;
	else if (t->rseq_preempt
			&& !(flags & RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT))
		need_restart = true;
	else if (t->rseq_signal
			&& !(flags & RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL))
		need_restart = true;

	t->rseq_preempt = false;
	t->rseq_signal = false;
	t->rseq_migrate = false;
	if (need_restart)
		return 1;
	return 0;
}

static int rseq_ip_fixup(struct pt_regs *regs)
{
	struct task_struct *t = current;
	void __user *start_ip = NULL;
	void __user *post_commit_ip = NULL;
	void __user *abort_ip = NULL;
	uint32_t cs_flags = 0;
	int ret;

	ret = rseq_get_rseq_cs(t, &start_ip, &post_commit_ip, &abort_ip,
			&cs_flags);
	trace_rseq_ip_fixup((void __user *)instruction_pointer(regs),
		start_ip, post_commit_ip, abort_ip, t->rseq_event_counter,
		ret);
	if (!ret)
		return -EFAULT;

	ret = rseq_need_restart(t, cs_flags);
	if (ret < 0)
		return -EFAULT;
	if (!ret)
		return 0;

	/* Handle potentially not being within a critical section. */
	if ((void __user *)instruction_pointer(regs) >= post_commit_ip ||
			(void __user *)instruction_pointer(regs) < start_ip)
		return 1;

	/*
	 * We set this after potentially failing in
	 * clear_user so that the signal arrives at the
	 * faulting rip.
	 */
	instruction_pointer_set(regs, (unsigned long)abort_ip);
	return 1;
}

/*
 * This resume handler should always be executed between any of:
 * - preemption,
 * - signal delivery,
 * and return to user-space.
 *
 * This is how we can ensure that the entire rseq critical section,
 * consisting of both the C part and the assembly instruction sequence,
 * will issue the commit instruction only if executed atomically with
 * respect to other threads scheduled on the same CPU, and with respect
 * to signal handlers.
 */
void __rseq_handle_notify_resume(struct pt_regs *regs)
{
	struct task_struct *t = current;
	int ret;

	if (unlikely(t->flags & PF_EXITING))
		return;
	if (unlikely(!access_ok(VERIFY_WRITE, t->rseq, sizeof(*t->rseq))))
		goto error;
	ret = rseq_ip_fixup(regs);
	if (unlikely(ret < 0))
		goto error;
	if (unlikely(!rseq_update_cpu_id_event_counter(t, ret)))
		goto error;
	return;

error:
	force_sig(SIGSEGV, t);
}

/*
 * sys_rseq - setup restartable sequences for caller thread.
 */
SYSCALL_DEFINE2(rseq, struct rseq __user *, rseq, int, flags)
{
	if (!rseq) {
		/* Unregister rseq for current thread. */
		if (unlikely(flags & ~RSEQ_FORCE_UNREGISTER))
			return -EINVAL;
		if (flags & RSEQ_FORCE_UNREGISTER) {
			current->rseq = NULL;
			current->rseq_refcount = 0;
			return 0;
		}
		if (!current->rseq_refcount)
			return -ENOENT;
		if (!--current->rseq_refcount)
			current->rseq = NULL;
		return 0;
	}

	if (unlikely(flags))
		return -EINVAL;

	if (current->rseq) {
		/*
		 * If rseq is already registered, check whether
		 * the provided address differs from the prior
		 * one.
		 */
		BUG_ON(!current->rseq_refcount);
		if (current->rseq != rseq)
			return -EBUSY;
		if (current->rseq_refcount == UINT_MAX)
			return -EOVERFLOW;
		current->rseq_refcount++;
	} else {
		/*
		 * If there was no rseq previously registered,
		 * we need to ensure the provided rseq is
		 * properly aligned and valid.
		 */
		BUG_ON(current->rseq_refcount);
		if (!IS_ALIGNED((unsigned long)rseq, __alignof__(*rseq)))
			return -EINVAL;
		if (!access_ok(VERIFY_WRITE, rseq, sizeof(*rseq)))
			return -EFAULT;
		current->rseq = rseq;
		current->rseq_refcount = 1;
		/*
		 * If rseq was previously inactive, and has just
		 * been registered, ensure the cpu_id and
		 * event_counter fields are updated before
		 * returning to user-space.
		 */
		rseq_set_notify_resume(current);
	}

	return 0;
}

/*
 * Check operation types and length parameters.
 */
static int rseq_op_vec_check(struct rseq_op *rseqop, int rseqopcnt)
{
	int i;

	for (i = 0; i < rseqopcnt; i++) {
		struct rseq_op *op = &rseqop[i];

		switch (op->op) {
		case RSEQ_COMPARE_EQ_OP:
		case RSEQ_MEMCPY_OP:
			if (op->len > RSEQ_OP_DATA_LEN_MAX)
				return -EINVAL;
			break;
		case RSEQ_ADD_OP:
		case RSEQ_OR_OP:
		case RSEQ_AND_OP:
		case RSEQ_XOR_OP:
			switch (op->len) {
			case 1:
			case 2:
			case 4:
			case 8:
				break;
			default:
				return -EINVAL;
			}
			break;
		case RSEQ_LSHIFT_OP:
		case RSEQ_RSHIFT_OP:
			switch (op->len) {
			case 1:
				if (op->u.shift_op.bits > 7)
					return -EINVAL;
				break;
			case 2:
				if (op->u.shift_op.bits > 15)
					return -EINVAL;
				break;
			case 4:
				if (op->u.shift_op.bits > 31)
					return -EINVAL;
				break;
			case 8:
				if (op->u.shift_op.bits > 63)
					return -EINVAL;
				break;
			default:
				return -EINVAL;
			}
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static unsigned long rseq_op_range_nr_pages(unsigned long addr,
		unsigned long len)
{
	return ((addr + len - 1) >> PAGE_SHIFT) - (addr >> PAGE_SHIFT) + 1;
}

static int rseq_op_pin_pages(unsigned long addr, unsigned long len,
		struct page ***pinned_pages_ptr, size_t *nr_pinned)
{
	unsigned long nr_pages;
	struct page *pages[2];
	int ret;

	if (!len)
		return 0;
	nr_pages = rseq_op_range_nr_pages(addr, len);
	BUG_ON(nr_pages > 2);
	if (*nr_pinned + nr_pages > NR_PINNED_PAGES_ON_STACK) {
		struct page **pinned_pages =
			kzalloc(RSEQ_OP_VEC_LEN_MAX * RSEQ_OP_MAX_PAGES
				* sizeof(struct page *), GFP_KERNEL);
		if (!pinned_pages)
			return -ENOMEM;
		memcpy(pinned_pages, *pinned_pages_ptr,
			*nr_pinned * sizeof(struct page *));
		*pinned_pages_ptr = pinned_pages;
	}
	ret = get_user_pages_fast(addr, nr_pages, 0, pages);
	if (ret < nr_pages) {
		if (ret > 0) {
			put_page(pages[0]);
		}
		return -EFAULT;
	}
	(*pinned_pages_ptr)[(*nr_pinned)++] = pages[0];
	if (nr_pages > 1)
		(*pinned_pages_ptr)[(*nr_pinned)++] = pages[1];
	return 0;
}

static int rseq_op_vec_pin_pages(struct rseq_op *rseqop, int rseqopcnt,
		struct page ***pinned_pages_ptr, size_t *nr_pinned)
{
	int ret, i;

	/* Check access, pin pages. */
	for (i = 0; i < rseqopcnt; i++) {
		struct rseq_op *op = &rseqop[i];

		switch (op->op) {
		case RSEQ_COMPARE_EQ_OP:
			if (!access_ok(VERIFY_READ, op->u.compare_op.a, op->len))
				goto error;
			ret = rseq_op_pin_pages((unsigned long)op->u.compare_op.a,
					op->len, pinned_pages_ptr, nr_pinned);
			if (ret)
				goto error;
			if (!access_ok(VERIFY_READ, op->u.compare_op.b, op->len))
				goto error;
			ret = rseq_op_pin_pages((unsigned long)op->u.compare_op.b,
					op->len, pinned_pages_ptr, nr_pinned);
			if (ret)
				goto error;
			break;
		case RSEQ_MEMCPY_OP:
			if (!access_ok(VERIFY_WRITE, op->u.memcpy_op.src, op->len))
				goto error;
			ret = rseq_op_pin_pages((unsigned long)op->u.memcpy_op.dst,
					op->len, pinned_pages_ptr, nr_pinned);
			if (ret)
				goto error;
			if (!access_ok(VERIFY_READ, op->u.memcpy_op.src, op->len))
				goto error;
			ret = rseq_op_pin_pages((unsigned long)op->u.memcpy_op.src,
					op->len, pinned_pages_ptr, nr_pinned);
			if (ret)
				goto error;
			break;
		case RSEQ_ADD_OP:
			if (!access_ok(VERIFY_WRITE, op->u.arithmetic_op.p, op->len))
				goto error;
			ret = rseq_op_pin_pages((unsigned long)op->u.arithmetic_op.p,
					op->len, pinned_pages_ptr, nr_pinned);
			if (ret)
				goto error;
			break;
		case RSEQ_OR_OP:
		case RSEQ_AND_OP:
		case RSEQ_XOR_OP:
			if (!access_ok(VERIFY_WRITE, op->u.bitwise_op.p, op->len))
				goto error;
			ret = rseq_op_pin_pages((unsigned long)op->u.bitwise_op.p,
					op->len, pinned_pages_ptr, nr_pinned);
			if (ret)
				goto error;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;

error:
	for (i = 0; i < *nr_pinned; i++)
		put_page((*pinned_pages_ptr)[i]);
	*nr_pinned = 0;
	return ret;
}

/* Return 0 if same, > 0 if different, < 0 on error. */
static int __rseq_do_op_compare_iter(void __user *a, void __user *b, uint32_t len)
{
	char bufa[TMP_BUFLEN], bufb[TMP_BUFLEN];
	uint32_t compared = 0;

	for (;;) {
		unsigned long to_compare;

		if (compared == len)
			break;
		to_compare = min_t(uint32_t, TMP_BUFLEN, len - compared);
		if (__copy_from_user_inatomic(bufa, a + compared, to_compare))
			return -EFAULT;
		if (__copy_from_user_inatomic(bufb, b + compared, to_compare))
			return -EFAULT;
		if (memcmp(bufa, bufb, to_compare))
			return 1;	/* different */
		compared += to_compare;
	}
	return 0;	/* same */
}

/* Return 0 if same, > 0 if different, < 0 on error. */
static int __rseq_do_op_compare(void __user *a, void __user *b, uint32_t len)
{
	int ret = -EFAULT;
	union {
		uint8_t _u8;
		uint16_t _u16;
		uint32_t _u32;
		uint64_t _u64;
	} tmp[2];

	pagefault_disable();
	switch (len) {
	case 1:
		if (__get_user(tmp[0]._u8, (uint8_t __user *)a))
			goto end;
		if (__get_user(tmp[1]._u8, (uint8_t __user *)b))
			goto end;
		ret = !!(tmp[0]._u8 != tmp[1]._u8);
		break;
	case 2:
		if (__get_user(tmp[0]._u16, (uint16_t __user *)a))
			goto end;
		if (__get_user(tmp[1]._u16, (uint16_t __user *)b))
			goto end;
		ret = !!(tmp[0]._u16 != tmp[1]._u16);
		break;
	case 4:
		if (__get_user(tmp[0]._u32, (uint32_t __user *)a))
			goto end;
		if (__get_user(tmp[1]._u32, (uint32_t __user *)b))
			goto end;
		ret = !!(tmp[0]._u32 != tmp[1]._u32);
		break;
	case 8:
		if (__get_user(tmp[0]._u64, (uint64_t __user *)a))
			goto end;
		if (__get_user(tmp[1]._u64, (uint64_t __user *)b))
			goto end;
		ret = !!(tmp[0]._u64 != tmp[1]._u64);
		break;
	default:
		pagefault_enable();
		return __rseq_do_op_compare_iter(a, b, len);
	}
end:
	pagefault_enable();
	return ret;
}

/* Return 0 on success, < 0 on error. */
static int __rseq_do_op_memcpy_iter(void __user *dst, void __user *src, uint32_t len)
{
	char buf[TMP_BUFLEN];
	uint32_t copied = 0;

	for (;;) {
		unsigned long to_copy;

		if (copied == len)
			break;
		to_copy = min_t(uint32_t, TMP_BUFLEN, len - copied);
		if (__copy_from_user_inatomic(buf, src + copied, to_copy))
			return -EFAULT;
		if (__copy_to_user_inatomic(dst + copied, buf, to_copy))
			return -EFAULT;
		copied += to_copy;
	}
	return 0;
}

/* Return 0 on success, < 0 on error. */
static int __rseq_do_op_memcpy(void __user *dst, void __user *src, uint32_t len)
{
	int ret = -EFAULT;
	union {
		uint8_t _u8;
		uint16_t _u16;
		uint32_t _u32;
		uint64_t _u64;
	} tmp;

	pagefault_disable();
	switch (len) {
	case 1:
		if (__get_user(tmp._u8, (uint8_t __user *)src))
			goto end;
		if (__put_user(tmp._u8, (uint8_t __user *)dst))
			goto end;
		break;
	case 2:
		if (__get_user(tmp._u16, (uint16_t __user *)src))
			goto end;
		if (__put_user(tmp._u16, (uint16_t __user *)dst))
			goto end;
		break;
	case 4:
		if (__get_user(tmp._u32, (uint32_t __user *)src))
			goto end;
		if (__put_user(tmp._u32, (uint32_t __user *)dst))
			goto end;
		break;
	case 8:
		if (__get_user(tmp._u64, (uint64_t __user *)src))
			goto end;
		if (__put_user(tmp._u64, (uint64_t __user *)dst))
			goto end;
		break;
	default:
		pagefault_enable();
		return __rseq_do_op_memcpy_iter(dst, src, len);
	}
	ret = 0;
end:
	pagefault_enable();
	return ret;
}

/* Return 0 on success, < 0 on error. */
static int __rseq_do_op_add(void __user *p, int64_t count, uint32_t len)
{
	int ret = -EFAULT;
	union {
		uint8_t _u8;
		uint16_t _u16;
		uint32_t _u32;
		uint64_t _u64;
	} tmp;

	pagefault_disable();
	switch (len) {
	case 1:
		if (__get_user(tmp._u8, (uint8_t __user *)p))
			goto end;
		tmp._u8 += (uint8_t)count;
		if (__put_user(tmp._u8, (uint8_t __user *)p))
			goto end;
		break;
	case 2:
		if (__get_user(tmp._u16, (uint16_t __user *)p))
			goto end;
		tmp._u16 += (uint16_t)count;
		if (__put_user(tmp._u16, (uint16_t __user *)p))
			goto end;
		break;
	case 4:
		if (__get_user(tmp._u32, (uint32_t __user *)p))
			goto end;
		tmp._u32 += (uint32_t)count;
		if (__put_user(tmp._u32, (uint32_t __user *)p))
			goto end;
		break;
	case 8:
		if (__get_user(tmp._u64, (uint64_t __user *)p))
			goto end;
		tmp._u64 += (uint64_t)count;
		if (__put_user(tmp._u64, (uint64_t __user *)p))
			goto end;
		break;
	default:
		ret = -EINVAL;
		goto end;
	}
	ret = 0;
end:
	pagefault_enable();
	return ret;
}

/* Return 0 on success, < 0 on error. */
static int __rseq_do_op_or(void __user *p, uint64_t mask, uint32_t len)
{
	int ret = -EFAULT;
	union {
		uint8_t _u8;
		uint16_t _u16;
		uint32_t _u32;
		uint64_t _u64;
	} tmp;

	pagefault_disable();
	switch (len) {
	case 1:
		if (__get_user(tmp._u8, (uint8_t __user *)p))
			goto end;
		tmp._u8 |= (uint8_t)mask;
		if (__put_user(tmp._u8, (uint8_t __user *)p))
			goto end;
		break;
	case 2:
		if (__get_user(tmp._u16, (uint16_t __user *)p))
			goto end;
		tmp._u16 |= (uint16_t)mask;
		if (__put_user(tmp._u16, (uint16_t __user *)p))
			goto end;
		break;
	case 4:
		if (__get_user(tmp._u32, (uint32_t __user *)p))
			goto end;
		tmp._u32 |= (uint32_t)mask;
		if (__put_user(tmp._u32, (uint32_t __user *)p))
			goto end;
		break;
	case 8:
		if (__get_user(tmp._u64, (uint64_t __user *)p))
			goto end;
		tmp._u64 |= (uint64_t)mask;
		if (__put_user(tmp._u64, (uint64_t __user *)p))
			goto end;
		break;
	default:
		ret = -EINVAL;
		goto end;
	}
	ret = 0;
end:
	pagefault_enable();
	return ret;
}

/* Return 0 on success, < 0 on error. */
static int __rseq_do_op_and(void __user *p, uint64_t mask, uint32_t len)
{
	int ret = -EFAULT;
	union {
		uint8_t _u8;
		uint16_t _u16;
		uint32_t _u32;
		uint64_t _u64;
	} tmp;

	pagefault_disable();
	switch (len) {
	case 1:
		if (__get_user(tmp._u8, (uint8_t __user *)p))
			goto end;
		tmp._u8 &= (uint8_t)mask;
		if (__put_user(tmp._u8, (uint8_t __user *)p))
			goto end;
		break;
	case 2:
		if (__get_user(tmp._u16, (uint16_t __user *)p))
			goto end;
		tmp._u16 &= (uint16_t)mask;
		if (__put_user(tmp._u16, (uint16_t __user *)p))
			goto end;
		break;
	case 4:
		if (__get_user(tmp._u32, (uint32_t __user *)p))
			goto end;
		tmp._u32 &= (uint32_t)mask;
		if (__put_user(tmp._u32, (uint32_t __user *)p))
			goto end;
		break;
	case 8:
		if (__get_user(tmp._u64, (uint64_t __user *)p))
			goto end;
		tmp._u64 &= (uint64_t)mask;
		if (__put_user(tmp._u64, (uint64_t __user *)p))
			goto end;
		break;
	default:
		ret = -EINVAL;
		goto end;
	}
	ret = 0;
end:
	pagefault_enable();
	return ret;
}

/* Return 0 on success, < 0 on error. */
static int __rseq_do_op_xor(void __user *p, uint64_t mask, uint32_t len)
{
	int ret = -EFAULT;
	union {
		uint8_t _u8;
		uint16_t _u16;
		uint32_t _u32;
		uint64_t _u64;
	} tmp;

	pagefault_disable();
	switch (len) {
	case 1:
		if (__get_user(tmp._u8, (uint8_t __user *)p))
			goto end;
		tmp._u8 ^= (uint8_t)mask;
		if (__put_user(tmp._u8, (uint8_t __user *)p))
			goto end;
		break;
	case 2:
		if (__get_user(tmp._u16, (uint16_t __user *)p))
			goto end;
		tmp._u16 ^= (uint16_t)mask;
		if (__put_user(tmp._u16, (uint16_t __user *)p))
			goto end;
		break;
	case 4:
		if (__get_user(tmp._u32, (uint32_t __user *)p))
			goto end;
		tmp._u32 ^= (uint32_t)mask;
		if (__put_user(tmp._u32, (uint32_t __user *)p))
			goto end;
		break;
	case 8:
		if (__get_user(tmp._u64, (uint64_t __user *)p))
			goto end;
		tmp._u64 ^= (uint64_t)mask;
		if (__put_user(tmp._u64, (uint64_t __user *)p))
			goto end;
		break;
	default:
		ret = -EINVAL;
		goto end;
	}
	ret = 0;
end:
	pagefault_enable();
	return ret;
}

/* Return 0 on success, < 0 on error. */
static int __rseq_do_op_lshift(void __user *p, uint32_t bits, uint32_t len)
{
	int ret = -EFAULT;
	union {
		uint8_t _u8;
		uint16_t _u16;
		uint32_t _u32;
		uint64_t _u64;
	} tmp;

	pagefault_disable();
	switch (len) {
	case 1:
		if (__get_user(tmp._u8, (uint8_t __user *)p))
			goto end;
		tmp._u8 <<= (uint8_t)bits;
		if (__put_user(tmp._u8, (uint8_t __user *)p))
			goto end;
		break;
	case 2:
		if (__get_user(tmp._u16, (uint16_t __user *)p))
			goto end;
		tmp._u16 <<= (uint16_t)bits;
		if (__put_user(tmp._u16, (uint16_t __user *)p))
			goto end;
		break;
	case 4:
		if (__get_user(tmp._u32, (uint32_t __user *)p))
			goto end;
		tmp._u32 <<= (uint32_t)bits;
		if (__put_user(tmp._u32, (uint32_t __user *)p))
			goto end;
		break;
	case 8:
		if (__get_user(tmp._u64, (uint64_t __user *)p))
			goto end;
		tmp._u64 <<= (uint64_t)bits;
		if (__put_user(tmp._u64, (uint64_t __user *)p))
			goto end;
		break;
	default:
		ret = -EINVAL;
		goto end;
	}
	ret = 0;
end:
	pagefault_enable();
	return ret;
}

/* Return 0 on success, < 0 on error. */
static int __rseq_do_op_rshift(void __user *p, uint32_t bits, uint32_t len)
{
	int ret = -EFAULT;
	union {
		uint8_t _u8;
		uint16_t _u16;
		uint32_t _u32;
		uint64_t _u64;
	} tmp;

	pagefault_disable();
	switch (len) {
	case 1:
		if (__get_user(tmp._u8, (uint8_t __user *)p))
			goto end;
		tmp._u8 >>= (uint8_t)bits;
		if (__put_user(tmp._u8, (uint8_t __user *)p))
			goto end;
		break;
	case 2:
		if (__get_user(tmp._u16, (uint16_t __user *)p))
			goto end;
		tmp._u16 >>= (uint16_t)bits;
		if (__put_user(tmp._u16, (uint16_t __user *)p))
			goto end;
		break;
	case 4:
		if (__get_user(tmp._u32, (uint32_t __user *)p))
			goto end;
		tmp._u32 >>= (uint32_t)bits;
		if (__put_user(tmp._u32, (uint32_t __user *)p))
			goto end;
		break;
	case 8:
		if (__get_user(tmp._u64, (uint64_t __user *)p))
			goto end;
		tmp._u64 >>= (uint64_t)bits;
		if (__put_user(tmp._u64, (uint64_t __user *)p))
			goto end;
		break;
	default:
		ret = -EINVAL;
		goto end;
	}
	ret = 0;
end:
	pagefault_enable();
	return ret;
}

static int __rseq_do_op_vec(struct rseq_op *rseqop, int rseqopcnt)
{
	int i, ret;

	for (i = 0; i < rseqopcnt; i++) {
		struct rseq_op *op = &rseqop[i];

		switch (op->op) {
		case RSEQ_COMPARE_EQ_OP:
			ret = __rseq_do_op_compare(
					(void __user *)op->u.compare_op.a,
					(void __user *)op->u.compare_op.b,
					op->len);
			/* Stop execution if error or comparison differs. */
			if (ret)
				return ret;
			break;
		case RSEQ_MEMCPY_OP:
			ret = __rseq_do_op_memcpy(
					(void __user *)op->u.memcpy_op.dst,
					(void __user *)op->u.memcpy_op.src,
					op->len);
			/* Stop execution on error. */
			if (ret)
				return ret;
			break;
		case RSEQ_ADD_OP:
			ret = __rseq_do_op_add((void __user *)op->u.arithmetic_op.p,
					op->u.arithmetic_op.count, op->len);
			/* Stop execution on error. */
			if (ret)
				return ret;
			break;
		case RSEQ_OR_OP:
			ret = __rseq_do_op_or((void __user *)op->u.bitwise_op.p,
					op->u.bitwise_op.mask, op->len);
			/* Stop execution on error. */
			if (ret)
				return ret;
			break;
		case RSEQ_AND_OP:
			ret = __rseq_do_op_and((void __user *)op->u.bitwise_op.p,
					op->u.bitwise_op.mask, op->len);
			/* Stop execution on error. */
			if (ret)
				return ret;
			break;
		case RSEQ_XOR_OP:
			ret = __rseq_do_op_xor((void __user *)op->u.bitwise_op.p,
					op->u.bitwise_op.mask, op->len);
			/* Stop execution on error. */
			if (ret)
				return ret;
			break;
		case RSEQ_LSHIFT_OP:
			ret = __rseq_do_op_lshift((void __user *)op->u.shift_op.p,
					op->u.shift_op.bits, op->len);
			/* Stop execution on error. */
			if (ret)
				return ret;
			break;
		case RSEQ_RSHIFT_OP:
			ret = __rseq_do_op_rshift((void __user *)op->u.shift_op.p,
					op->u.shift_op.bits, op->len);
			/* Stop execution on error. */
			if (ret)
				return ret;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static int rseq_do_op_vec(struct rseq_op *rseqop, int rseqopcnt, int cpu)
{
	int ret;

	preempt_disable();
	if (cpu != smp_processor_id()) {
		ret = -EAGAIN;
		goto end;
	}
	ret = __rseq_do_op_vec(rseqop, rseqopcnt);
end:
	preempt_enable();
	return ret;
}

/*
 * sys_rseq_op - copy atomically user-space data on a given CPU.
 *
 * Userspace should pass current CPU number as parameter. May fail with
 * -EAGAIN if currently executing on the wrong CPU.
 */
SYSCALL_DEFINE4(rseq_op, struct rseq_op __user *, urseqop, int, rseqopcnt,
		int, cpu, int, flags)
{
	struct rseq_op rseqop[RSEQ_OP_VEC_LEN_MAX];
	struct page *pinned_pages_on_stack[NR_PINNED_PAGES_ON_STACK];
	struct page **pinned_pages = pinned_pages_on_stack;
	int ret, i;
	size_t nr_pinned = 0;

	if (unlikely(flags))
		return -EINVAL;
	if (rseqopcnt < 0 || rseqopcnt > RSEQ_OP_VEC_LEN_MAX)
		return -EINVAL;
	if (copy_from_user(rseqop, urseqop, rseqopcnt * sizeof(struct rseq_op)))
		return -EFAULT;
	ret = rseq_op_vec_check(rseqop, rseqopcnt);
	if (ret)
		return ret;
	ret = rseq_op_vec_pin_pages(rseqop, rseqopcnt,
				&pinned_pages, &nr_pinned);
	if (ret)
		goto end;
	ret = rseq_do_op_vec(rseqop, rseqopcnt, cpu);
	for (i = 0; i < nr_pinned; i++)
		put_page(pinned_pages[i]);
end:
	if (pinned_pages != pinned_pages_on_stack)
		kfree(pinned_pages);
	return ret;
}
