/*
 * CPU preempt-off operation vector system call
 *
 * It allows user-space to perform a sequence of operations on per-cpu
 * data with preemption disabled. Useful as single-stepping fall-back
 * for restartable sequences, and for performing more complex operations
 * on per-cpu data that would not be otherwise possible to do with
 * restartable sequences.
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
 * Copyright (C) 2017, EfficiOS Inc.,
 * Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/cpu_opv.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <asm/ptrace.h>
#include <asm/byteorder.h>
#include <asm/cacheflush.h>

#include "sched/sched.h"

/*
 * Typical invocation of cpu_opv need few virtual address pointers. Keep
 * those in an array on the stack of the cpu_opv system call up to
 * this limit, beyond which the array is dynamically allocated.
 */
#define NR_VADDR_ON_STACK		8

/* Maximum pages per op. */
#define CPU_OP_MAX_PAGES		4

/* Maximum number of virtual addresses per op. */
#define CPU_OP_VEC_MAX_ADDR		(2 * CPU_OP_VEC_LEN_MAX)

union op_fn_data {
	uint8_t _u8;
	uint16_t _u16;
	uint32_t _u32;
	uint64_t _u64;
#if (BITS_PER_LONG < 64)
	uint32_t _u64_split[2];
#endif
};

struct vaddr {
	unsigned long mem;
	unsigned long uaddr;
	struct page *pages[2];
	unsigned int nr_pages;
	int write;
};

struct cpu_opv_vaddr {
	struct vaddr *addr;
	size_t nr_vaddr;
	bool is_kmalloc;
};

typedef int (*op_fn_t)(union op_fn_data *data, uint64_t v, uint32_t len);

/*
 * Provide mutual exclution for threads executing a cpu_opv against an
 * offline CPU.
 */
static DEFINE_MUTEX(cpu_opv_offline_lock);

/*
 * The cpu_opv system call executes a vector of operations on behalf of
 * user-space on a specific CPU with preemption disabled. It is inspired
 * by readv() and writev() system calls which take a "struct iovec"
 * array as argument.
 *
 * The operations available are: comparison, memcpy, add, or, and, xor,
 * left shift, right shift, and memory barrier. The system call receives
 * a CPU number from user-space as argument, which is the CPU on which
 * those operations need to be performed.  All pointers in the ops must
 * have been set up to point to the per CPU memory of the CPU on which
 * the operations should be executed. The "comparison" operation can be
 * used to check that the data used in the preparation step did not
 * change between preparation of system call inputs and operation
 * execution within the preempt-off critical section.
 *
 * The reason why we require all pointer offsets to be calculated by
 * user-space beforehand is because we need to use get_user_pages()
 * to first pin all pages touched by each operation. This takes care of
 * faulting-in the pages. Then, preemption is disabled, and the
 * operations are performed atomically with respect to other thread
 * execution on that CPU, without generating any page fault.
 *
 * An overall maximum of 4216 bytes in enforced on the sum of operation
 * length within an operation vector, so user-space cannot generate a
 * too long preempt-off critical section (cache cold critical section
 * duration measured as 4.7µs on x86-64). Each operation is also limited
 * a length of 4096 bytes, meaning that an operation can touch a
 * maximum of 4 pages (memcpy: 2 pages for source, 2 pages for
 * destination if addresses are not aligned on page boundaries).
 *
 * If the thread is not running on the requested CPU, it is migrated to
 * it.
 */

static unsigned long cpu_op_range_nr_pages(unsigned long addr,
					   unsigned long len)
{
	return ((addr + len - 1) >> PAGE_SHIFT) - (addr >> PAGE_SHIFT) + 1;
}

static int cpu_op_count_pages(unsigned long addr, unsigned long len)
{
	unsigned long nr_pages;

	if (!len)
		return 0;
	nr_pages = cpu_op_range_nr_pages(addr, len);
	if (nr_pages > 2) {
		WARN_ON(1);
		return -EINVAL;
	}
	return nr_pages;
}

static struct vaddr *cpu_op_alloc_vaddr_vector(int nr_vaddr)
{
	return kzalloc(nr_vaddr * sizeof(struct vaddr), GFP_KERNEL);
}

/*
 * Check operation types and length parameters. Count number of pages.
 */
static int cpu_opv_check_op(struct cpu_op *op, int *nr_vaddr, uint32_t *sum)
{
	int ret;

	switch (op->op) {
	case CPU_MB_OP:
		break;
	default:
		*sum += op->len;
	}

	/* Validate inputs. */
	switch (op->op) {
	case CPU_COMPARE_EQ_OP:
	case CPU_COMPARE_NE_OP:
	case CPU_MEMCPY_OP:
		if (op->len > CPU_OP_DATA_LEN_MAX)
			return -EINVAL;
		break;
	case CPU_ADD_OP:
	case CPU_OR_OP:
	case CPU_AND_OP:
	case CPU_XOR_OP:
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
	case CPU_LSHIFT_OP:
	case CPU_RSHIFT_OP:
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
	case CPU_MB_OP:
		break;
	default:
		return -EINVAL;
	}

	/* Count pages and virtual addresses. */
	switch (op->op) {
	case CPU_COMPARE_EQ_OP:
	case CPU_COMPARE_NE_OP:
		ret = cpu_op_count_pages(op->u.compare_op.a, op->len);
		if (ret < 0)
			return ret;
		ret = cpu_op_count_pages(op->u.compare_op.b, op->len);
		if (ret < 0)
			return ret;
		*nr_vaddr += 2;
		break;
	case CPU_MEMCPY_OP:
		ret = cpu_op_count_pages(op->u.memcpy_op.dst, op->len);
		if (ret < 0)
			return ret;
		ret = cpu_op_count_pages(op->u.memcpy_op.src, op->len);
		if (ret < 0)
			return ret;
		*nr_vaddr += 2;
		break;
	case CPU_ADD_OP:
		ret = cpu_op_count_pages(op->u.arithmetic_op.p, op->len);
		if (ret < 0)
			return ret;
		(*nr_vaddr)++;
		break;
	case CPU_OR_OP:
	case CPU_AND_OP:
	case CPU_XOR_OP:
		ret = cpu_op_count_pages(op->u.bitwise_op.p, op->len);
		if (ret < 0)
			return ret;
		(*nr_vaddr)++;
		break;
	case CPU_LSHIFT_OP:
	case CPU_RSHIFT_OP:
		ret = cpu_op_count_pages(op->u.shift_op.p, op->len);
		if (ret < 0)
			return ret;
		(*nr_vaddr)++;
		break;
	case CPU_MB_OP:
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/*
 * Check operation types and length parameters. Count number of pages.
 */
static int cpu_opv_check(struct cpu_op *cpuopv, int cpuopcnt, int *nr_vaddr)
{
	uint32_t sum = 0;
	int i, ret;

	for (i = 0; i < cpuopcnt; i++) {
		ret = cpu_opv_check_op(&cpuopv[i], nr_vaddr, &sum);
		if (ret)
			return ret;
	}
	if (sum > CPU_OP_VEC_DATA_LEN_MAX)
		return -EINVAL;
	return 0;
}

static int cpu_op_check_page(struct page *page, int write)
{
	struct address_space *mapping;

	if (is_zone_device_page(page))
		return -EFAULT;

	/*
	 * The page lock protects many things but in this context the page
	 * lock stabilizes mapping, prevents inode freeing in the shared
	 * file-backed region case and guards against movement to swap
	 * cache.
	 *
	 * Strictly speaking the page lock is not needed in all cases being
	 * considered here and page lock forces unnecessarily serialization
	 * From this point on, mapping will be re-verified if necessary and
	 * page lock will be acquired only if it is unavoidable
	 *
	 * Mapping checks require the head page for any compound page so the
	 * head page and mapping is looked up now.
	 */
	page = compound_head(page);
	mapping = READ_ONCE(page->mapping);

	/*
	 * If page->mapping is NULL, then it cannot be a PageAnon page;
	 * but it might be the ZERO_PAGE (which is OK to read from), or
	 * in the gate area or in a special mapping (for which this
	 * check should fail); or it may have been a good file page when
	 * get_user_pages found it, but truncated or holepunched or
	 * subjected to invalidate_complete_page2 before the page lock
	 * is acquired (also cases which should fail). Given that a
	 * reference to the page is currently held, refcount care in
	 * invalidate_complete_page's remove_mapping prevents
	 * drop_caches from setting mapping to NULL concurrently.
	 *
	 * The case to guard against is when memory pressure cause
	 * shmem_writepage to move the page from filecache to swapcache
	 * concurrently: an unlikely race, but a retry for page->mapping
	 * is required in that situation.
	 */
	if (!mapping) {
		int shmem_swizzled;

		/*
		 * Check again with page lock held to guard against
		 * memory pressure making shmem_writepage move the page
		 * from filecache to swapcache.
		 */
		lock_page(page);
		shmem_swizzled = PageSwapCache(page) || page->mapping;
		unlock_page(page);
		if (shmem_swizzled)
			return -EAGAIN;
		/*
		 * It is valid to read from, but invalid to write to the
		 * ZERO_PAGE.
		 */
		if (!(is_zero_pfn(page_to_pfn(page)) ||
		      is_huge_zero_page(page)) || write)
			return -EFAULT;
	}
	return 0;
}

static int cpu_op_check_pages(struct page **pages,
			      unsigned long nr_pages,
			      int write)
{
	unsigned long i;

	for (i = 0; i < nr_pages; i++) {
		int ret;

		ret = cpu_op_check_page(pages[i], write);
		if (ret)
			return ret;
	}
	return 0;
}

static int cpu_op_pin_pages(unsigned long addr, unsigned long len,
			    struct cpu_opv_vaddr *vaddr_ptrs,
			    unsigned long *vaddr, int write)
{
	struct page *pages[2];
	struct vm_area_struct *vmas[2];
	int ret, nr_pages, nr_put_pages, n;
	unsigned long _vaddr;
	struct vaddr *va;
	struct mm_struct *mm = current->mm;

	nr_pages = cpu_op_count_pages(addr, len);
	if (!nr_pages)
		return 0;
again:
	down_read(&mm->mmap_sem);
	ret = get_user_pages(addr, nr_pages, write ? FOLL_WRITE : 0, pages,
			     vmas);
	if (ret < nr_pages) {
		if (ret >= 0) {
			nr_put_pages = ret;
			ret = -EFAULT;
		} else {
			nr_put_pages = 0;
		}
		up_read(&mm->mmap_sem);
		goto error;
	}
	/*
	 * cpu_opv() accesses its own cached mapping of the userspace pages.
	 * Considering that concurrent noncached and cached accesses may yield
	 * to unexpected results in terms of memory consistency, explicitly
	 * disallow cpu_opv on noncached memory.
	 */
	for (n = 0; n < nr_pages; n++) {
		if (is_vma_noncached(vmas[n])) {
			nr_put_pages = nr_pages;
			ret = -EFAULT;
			up_read(&mm->mmap_sem);
			goto error;
		}
	}
	up_read(&mm->mmap_sem);
	ret = cpu_op_check_pages(pages, nr_pages, write);
	if (ret) {
		nr_put_pages = nr_pages;
		goto error;
	}
	_vaddr = (unsigned long)vm_map_user_ram(pages, nr_pages, addr,
						numa_node_id(), PAGE_KERNEL);
	if (!_vaddr) {
		nr_put_pages = nr_pages;
		ret = -ENOMEM;
		goto error;
	}
	va = &vaddr_ptrs->addr[vaddr_ptrs->nr_vaddr++];
	va->mem = _vaddr;
	va->uaddr = addr;
	for (n = 0; n < nr_pages; n++)
		va->pages[n] = pages[n];
	va->nr_pages = nr_pages;
	va->write = write;
	*vaddr = _vaddr + (addr & ~PAGE_MASK);
	return 0;

error:
	for (n = 0; n < nr_put_pages; n++)
		put_page(pages[n]);
	/*
	 * Retry if a page has been faulted in, or is being swapped in.
	 */
	if (ret == -EAGAIN)
		goto again;
	return ret;
}

static int cpu_opv_pin_pages_op(struct cpu_op *op,
				struct cpu_opv_vaddr *vaddr_ptrs,
				bool *expect_fault)
{
	int ret;
	unsigned long vaddr = 0;

	switch (op->op) {
	case CPU_COMPARE_EQ_OP:
	case CPU_COMPARE_NE_OP:
		ret = -EFAULT;
		*expect_fault = op->u.compare_op.expect_fault_a;
		if (!access_ok(VERIFY_READ,
			       (void __user *)op->u.compare_op.a,
			       op->len))
			return ret;
		ret = cpu_op_pin_pages(op->u.compare_op.a, op->len,
				       vaddr_ptrs, &vaddr, 0);
		if (ret)
			return ret;
		op->u.compare_op.a = vaddr;
		ret = -EFAULT;
		*expect_fault = op->u.compare_op.expect_fault_b;
		if (!access_ok(VERIFY_READ,
			       (void __user *)op->u.compare_op.b,
			       op->len))
			return ret;
		ret = cpu_op_pin_pages(op->u.compare_op.b, op->len,
				       vaddr_ptrs, &vaddr, 0);
		if (ret)
			return ret;
		op->u.compare_op.b = vaddr;
		break;
	case CPU_MEMCPY_OP:
		ret = -EFAULT;
		*expect_fault = op->u.memcpy_op.expect_fault_dst;
		if (!access_ok(VERIFY_WRITE,
			       (void __user *)op->u.memcpy_op.dst,
			       op->len))
			return ret;
		ret = cpu_op_pin_pages(op->u.memcpy_op.dst, op->len,
				       vaddr_ptrs, &vaddr, 1);
		if (ret)
			return ret;
		op->u.memcpy_op.dst = vaddr;
		ret = -EFAULT;
		*expect_fault = op->u.memcpy_op.expect_fault_src;
		if (!access_ok(VERIFY_READ,
			       (void __user *)op->u.memcpy_op.src,
			       op->len))
			return ret;
		ret = cpu_op_pin_pages(op->u.memcpy_op.src, op->len,
				       vaddr_ptrs, &vaddr, 0);
		if (ret)
			return ret;
		op->u.memcpy_op.src = vaddr;
		break;
	case CPU_ADD_OP:
		ret = -EFAULT;
		*expect_fault = op->u.arithmetic_op.expect_fault_p;
		if (!access_ok(VERIFY_WRITE,
			       (void __user *)op->u.arithmetic_op.p,
			       op->len))
			return ret;
		ret = cpu_op_pin_pages(op->u.arithmetic_op.p, op->len,
				       vaddr_ptrs, &vaddr, 1);
		if (ret)
			return ret;
		op->u.arithmetic_op.p = vaddr;
		break;
	case CPU_OR_OP:
	case CPU_AND_OP:
	case CPU_XOR_OP:
		ret = -EFAULT;
		*expect_fault = op->u.bitwise_op.expect_fault_p;
		if (!access_ok(VERIFY_WRITE,
			       (void __user *)op->u.bitwise_op.p,
			       op->len))
			return ret;
		ret = cpu_op_pin_pages(op->u.bitwise_op.p, op->len,
				       vaddr_ptrs, &vaddr, 1);
		if (ret)
			return ret;
		op->u.bitwise_op.p = vaddr;
		break;
	case CPU_LSHIFT_OP:
	case CPU_RSHIFT_OP:
		ret = -EFAULT;
		*expect_fault = op->u.shift_op.expect_fault_p;
		if (!access_ok(VERIFY_WRITE,
			       (void __user *)op->u.shift_op.p,
			       op->len))
			return ret;
		ret = cpu_op_pin_pages(op->u.shift_op.p, op->len,
				       vaddr_ptrs, &vaddr, 1);
		if (ret)
			return ret;
		op->u.shift_op.p = vaddr;
		break;
	case CPU_MB_OP:
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int cpu_opv_pin_pages(struct cpu_op *cpuop, int cpuopcnt,
			     struct cpu_opv_vaddr *vaddr_ptrs)
{
	int ret, i;
	bool expect_fault = false;

	/* Check access, pin pages. */
	for (i = 0; i < cpuopcnt; i++) {
		ret = cpu_opv_pin_pages_op(&cpuop[i], vaddr_ptrs,
					   &expect_fault);
		if (ret)
			goto error;
	}
	return 0;

error:
	/*
	 * If faulting access is expected, return EAGAIN to user-space.
	 * It allows user-space to distinguish between a fault caused by
	 * an access which is expect to fault (e.g. due to concurrent
	 * unmapping of underlying memory) from an unexpected fault from
	 * which a retry would not recover.
	 */
	if (ret == -EFAULT && expect_fault)
		return -EAGAIN;
	return ret;
}

static int __op_get(union op_fn_data *data, void *p, size_t len)
{
	switch (len) {
	case 1:
		data->_u8 = READ_ONCE(*(uint8_t *)p);
		break;
	case 2:
		data->_u16 = READ_ONCE(*(uint16_t *)p);
		break;
	case 4:
		data->_u32 = READ_ONCE(*(uint32_t *)p);
		break;
	case 8:
#if (BITS_PER_LONG == 64)
		data->_u64 = READ_ONCE(*(uint64_t *)p);
#else
	{
		data->_u64_split[0] = READ_ONCE(*(uint32_t *)p);
		data->_u64_split[1] = READ_ONCE(*((uint32_t *)p + 1));
	}
#endif
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int __op_put(union op_fn_data *data, void *p, size_t len)
{
	switch (len) {
	case 1:
		WRITE_ONCE(*(uint8_t *)p, data->_u8);
		break;
	case 2:
		WRITE_ONCE(*(uint16_t *)p, data->_u16);
		break;
	case 4:
		WRITE_ONCE(*(uint32_t *)p, data->_u32);
		break;
	case 8:
#if (BITS_PER_LONG == 64)
		WRITE_ONCE(*(uint64_t *)p, data->_u64);
#else
	{
		WRITE_ONCE(*(uint32_t *)p, data->_u64_split[0]);
		WRITE_ONCE(*((uint32_t *)p + 1), data->_u64_split[1]);
	}
#endif
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/* Return 0 if same, > 0 if different, < 0 on error. */
static int do_cpu_op_compare(unsigned long _a, unsigned long _b, uint32_t len)
{
	void *a = (void *)_a;
	void *b = (void *)_b;
	union op_fn_data tmp[2];
	int ret;

	switch (len) {
	case 1:
	case 2:
	case 4:
	case 8:
		if (!IS_ALIGNED(_a, len) || !IS_ALIGNED(_b, len))
			goto memcmp;
		break;
	default:
		goto memcmp;
	}

	ret = __op_get(&tmp[0], a, len);
	if (ret)
		return ret;
	ret = __op_get(&tmp[1], b, len);
	if (ret)
		return ret;

	switch (len) {
	case 1:
		ret = !!(tmp[0]._u8 != tmp[1]._u8);
		break;
	case 2:
		ret = !!(tmp[0]._u16 != tmp[1]._u16);
		break;
	case 4:
		ret = !!(tmp[0]._u32 != tmp[1]._u32);
		break;
	case 8:
		ret = !!(tmp[0]._u64 != tmp[1]._u64);
		break;
	default:
		return -EINVAL;
	}
	return ret;

memcmp:
	if (memcmp(a, b, len))
		return 1;
	return 0;
}

/* Return 0 on success, < 0 on error. */
static int do_cpu_op_memcpy(unsigned long _dst, unsigned long _src,
			    uint32_t len)
{
	void *dst = (void *)_dst;
	void *src = (void *)_src;
	union op_fn_data tmp;
	int ret;

	switch (len) {
	case 1:
	case 2:
	case 4:
	case 8:
		if (!IS_ALIGNED(_dst, len) || !IS_ALIGNED(_src, len))
			goto memcpy;
		break;
	default:
		goto memcpy;
	}

	ret = __op_get(&tmp, src, len);
	if (ret)
		return ret;
	return __op_put(&tmp, dst, len);

memcpy:
	memcpy(dst, src, len);
	return 0;
}

static int op_add_fn(union op_fn_data *data, uint64_t count, uint32_t len)
{
	switch (len) {
	case 1:
		data->_u8 += (uint8_t)count;
		break;
	case 2:
		data->_u16 += (uint16_t)count;
		break;
	case 4:
		data->_u32 += (uint32_t)count;
		break;
	case 8:
		data->_u64 += (uint64_t)count;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int op_or_fn(union op_fn_data *data, uint64_t mask, uint32_t len)
{
	switch (len) {
	case 1:
		data->_u8 |= (uint8_t)mask;
		break;
	case 2:
		data->_u16 |= (uint16_t)mask;
		break;
	case 4:
		data->_u32 |= (uint32_t)mask;
		break;
	case 8:
		data->_u64 |= (uint64_t)mask;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int op_and_fn(union op_fn_data *data, uint64_t mask, uint32_t len)
{
	switch (len) {
	case 1:
		data->_u8 &= (uint8_t)mask;
		break;
	case 2:
		data->_u16 &= (uint16_t)mask;
		break;
	case 4:
		data->_u32 &= (uint32_t)mask;
		break;
	case 8:
		data->_u64 &= (uint64_t)mask;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int op_xor_fn(union op_fn_data *data, uint64_t mask, uint32_t len)
{
	switch (len) {
	case 1:
		data->_u8 ^= (uint8_t)mask;
		break;
	case 2:
		data->_u16 ^= (uint16_t)mask;
		break;
	case 4:
		data->_u32 ^= (uint32_t)mask;
		break;
	case 8:
		data->_u64 ^= (uint64_t)mask;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int op_lshift_fn(union op_fn_data *data, uint64_t bits, uint32_t len)
{
	switch (len) {
	case 1:
		data->_u8 <<= (uint8_t)bits;
		break;
	case 2:
		data->_u16 <<= (uint16_t)bits;
		break;
	case 4:
		data->_u32 <<= (uint32_t)bits;
		break;
	case 8:
		data->_u64 <<= (uint64_t)bits;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int op_rshift_fn(union op_fn_data *data, uint64_t bits, uint32_t len)
{
	switch (len) {
	case 1:
		data->_u8 >>= (uint8_t)bits;
		break;
	case 2:
		data->_u16 >>= (uint16_t)bits;
		break;
	case 4:
		data->_u32 >>= (uint32_t)bits;
		break;
	case 8:
		data->_u64 >>= (uint64_t)bits;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/* Return 0 on success, < 0 on error. */
static int do_cpu_op_fn(op_fn_t op_fn, unsigned long _p, uint64_t v,
			uint32_t len)
{
	union op_fn_data tmp;
	void *p = (void *)_p;
	int ret;

	ret = __op_get(&tmp, p, len);
	if (ret)
		return ret;
	ret = op_fn(&tmp, v, len);
	if (ret)
		return ret;
	ret = __op_put(&tmp, p, len);
	if (ret)
		return ret;
	return 0;
}

/*
 * Return negative value on error, positive value if comparison
 * fails, 0 on success.
 */
static int __do_cpu_opv_op(struct cpu_op *op)
{
	/* Guarantee a compiler barrier between each operation. */
	barrier();

	switch (op->op) {
	case CPU_COMPARE_EQ_OP:
		return do_cpu_op_compare(op->u.compare_op.a,
					 op->u.compare_op.b,
					 op->len);
	case CPU_COMPARE_NE_OP:
	{
		int ret;

		ret = do_cpu_op_compare(op->u.compare_op.a,
					op->u.compare_op.b,
					op->len);
		if (ret < 0)
			return ret;
		/*
		 * Stop execution, return positive value if comparison
		 * is identical.
		 */
		if (ret == 0)
			return 1;
		return 0;
	}
	case CPU_MEMCPY_OP:
		return do_cpu_op_memcpy(op->u.memcpy_op.dst,
					op->u.memcpy_op.src,
					op->len);
	case CPU_ADD_OP:
		return do_cpu_op_fn(op_add_fn, op->u.arithmetic_op.p,
				    op->u.arithmetic_op.count, op->len);
	case CPU_OR_OP:
		return do_cpu_op_fn(op_or_fn, op->u.bitwise_op.p,
				    op->u.bitwise_op.mask, op->len);
	case CPU_AND_OP:
		return do_cpu_op_fn(op_and_fn, op->u.bitwise_op.p,
				    op->u.bitwise_op.mask, op->len);
	case CPU_XOR_OP:
		return do_cpu_op_fn(op_xor_fn, op->u.bitwise_op.p,
				    op->u.bitwise_op.mask, op->len);
	case CPU_LSHIFT_OP:
		return do_cpu_op_fn(op_lshift_fn, op->u.shift_op.p,
				    op->u.shift_op.bits, op->len);
	case CPU_RSHIFT_OP:
		return do_cpu_op_fn(op_rshift_fn, op->u.shift_op.p,
				    op->u.shift_op.bits, op->len);
	case CPU_MB_OP:
		/* Memory barrier provided by this operation. */
		smp_mb();
		return 0;
	default:
		return -EINVAL;
	}
}

static int __do_cpu_opv(struct cpu_op *cpuop, int cpuopcnt)
{
	int i, ret;

	for (i = 0; i < cpuopcnt; i++) {
		ret = __do_cpu_opv_op(&cpuop[i]);
		/* If comparison fails, stop execution and return index + 1. */
		if (ret > 0)
			return i + 1;
		/* On error, stop execution. */
		if (ret < 0)
			return ret;
	}
	return 0;
}

/*
 * Check that the page pointers pinned by get_user_pages()
 * are still in the page table. Invoked with mmap_sem held.
 * Return 0 if pointers match, -EAGAIN if they don't.
 */
static int vaddr_check(struct vaddr *vaddr)
{
	struct page *pages[2];
	int ret, n;

	ret = __get_user_pages_fast(vaddr->uaddr, vaddr->nr_pages,
				    vaddr->write, pages);
	for (n = 0; n < ret; n++)
		put_page(pages[n]);
	if (ret < vaddr->nr_pages) {
		ret = get_user_pages(vaddr->uaddr, vaddr->nr_pages,
				     vaddr->write ? FOLL_WRITE : 0,
				     pages, NULL);
		if (ret < 0)
			return -EAGAIN;
		for (n = 0; n < ret; n++)
			put_page(pages[n]);
		if (ret < vaddr->nr_pages)
			return -EAGAIN;
	}
	for (n = 0; n < vaddr->nr_pages; n++) {
		if (pages[n] != vaddr->pages[n])
			return -EAGAIN;
	}
	return 0;
}

static int vaddr_ptrs_check(struct cpu_opv_vaddr *vaddr_ptrs)
{
	int i;

	for (i = 0; i < vaddr_ptrs->nr_vaddr; i++) {
		int ret;

		ret = vaddr_check(&vaddr_ptrs->addr[i]);
		if (ret)
			return ret;
	}
	return 0;
}

static int do_cpu_opv(struct cpu_op *cpuop, int cpuopcnt,
		      struct cpu_opv_vaddr *vaddr_ptrs, int cpu)
{
	struct mm_struct *mm = current->mm;
	int ret;

retry:
	if (cpu != raw_smp_processor_id()) {
		ret = push_task_to_cpu(current, cpu);
		if (ret)
			goto check_online;
	}
	down_read(&mm->mmap_sem);
	ret = vaddr_ptrs_check(vaddr_ptrs);
	if (ret)
		goto end;
	preempt_disable();
	if (cpu != smp_processor_id()) {
		preempt_enable();
		up_read(&mm->mmap_sem);
		goto retry;
	}
	ret = __do_cpu_opv(cpuop, cpuopcnt);
	preempt_enable();
end:
	up_read(&mm->mmap_sem);
	return ret;

check_online:
	/*
	 * push_task_to_cpu() returns -EINVAL if the requested cpu is not part
	 * of the current thread's cpus_allowed mask.
	 */
	if (ret == -EINVAL)
		return ret;
	get_online_cpus();
	if (cpu_online(cpu)) {
		put_online_cpus();
		goto retry;
	}
	/*
	 * CPU is offline. Perform operation from the current CPU with
	 * cpu_online read lock held, preventing that CPU from coming online,
	 * and with mutex held, providing mutual exclusion against other
	 * CPUs also finding out about an offline CPU.
	 */
	down_read(&mm->mmap_sem);
	ret = vaddr_ptrs_check(vaddr_ptrs);
	if (ret)
		goto offline_end;
	mutex_lock(&cpu_opv_offline_lock);
	ret = __do_cpu_opv(cpuop, cpuopcnt);
	mutex_unlock(&cpu_opv_offline_lock);
offline_end:
	up_read(&mm->mmap_sem);
	put_online_cpus();
	return ret;
}

/*
 * cpu_opv - execute operation vector on a given CPU with preempt off.
 *
 * Userspace should pass current CPU number as parameter.
 */
SYSCALL_DEFINE4(cpu_opv, struct cpu_op __user *, ucpuopv, int, cpuopcnt,
		int, cpu, int, flags)
{
	struct vaddr vaddr_on_stack[NR_VADDR_ON_STACK];
	struct cpu_op cpuopv[CPU_OP_VEC_LEN_MAX];
	struct cpu_opv_vaddr vaddr_ptrs = {
		.addr = vaddr_on_stack,
		.nr_vaddr = 0,
		.is_kmalloc = false,
	};
	int ret, i, nr_vaddr = 0;
	bool retry = false;

	if (unlikely(flags & ~CPU_OP_NR_FLAG))
		return -EINVAL;
	if (flags & CPU_OP_NR_FLAG)
		return NR_CPU_OPS;
	if (unlikely(cpu < 0))
		return -EINVAL;
	if (cpuopcnt < 0 || cpuopcnt > CPU_OP_VEC_LEN_MAX)
		return -EINVAL;
	if (copy_from_user(cpuopv, ucpuopv, cpuopcnt * sizeof(struct cpu_op)))
		return -EFAULT;
	ret = cpu_opv_check(cpuopv, cpuopcnt, &nr_vaddr);
	if (ret)
		return ret;
	if (nr_vaddr > NR_VADDR_ON_STACK) {
		vaddr_ptrs.addr = cpu_op_alloc_vaddr_vector(nr_vaddr);
		if (!vaddr_ptrs.addr) {
			ret = -ENOMEM;
			goto end;
		}
		vaddr_ptrs.is_kmalloc = true;
	}
again:
	ret = cpu_opv_pin_pages(cpuopv, cpuopcnt, &vaddr_ptrs);
	if (ret)
		goto end;
	ret = do_cpu_opv(cpuopv, cpuopcnt, &vaddr_ptrs, cpu);
	if (ret == -EAGAIN)
		retry = true;
end:
	for (i = 0; i < vaddr_ptrs.nr_vaddr; i++) {
		struct vaddr *vaddr = &vaddr_ptrs.addr[i];
		int j;

		vm_unmap_user_ram((void *)vaddr->mem, vaddr->nr_pages);
		for (j = 0; j < vaddr->nr_pages; j++) {
			if (vaddr->write)
				set_page_dirty(vaddr->pages[j]);
			put_page(vaddr->pages[j]);
		}
	}
	/*
	 * Force vm_map flush to ensure we don't exhaust available vmalloc
	 * address space.
	 */
	if (vaddr_ptrs.nr_vaddr)
		vm_unmap_aliases();
	if (retry) {
		retry = false;
		vaddr_ptrs.nr_vaddr = 0;
		goto again;
	}
	if (vaddr_ptrs.is_kmalloc)
		kfree(vaddr_ptrs.addr);
	return ret;
}
