/*
 * Basic test coverage for cpu_opv system call.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sched.h>

#include "../kselftest.h"

#include "cpu-op.h"

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

#define TESTBUFLEN	4096
#define TESTBUFLEN_CMP	16

#define TESTBUFLEN_PAGE_MAX	65536

#define NR_PF_ARRAY	16384
#define PF_ARRAY_LEN	4096

#define NR_HUGE_ARRAY	512
#define HUGEMAPLEN	(NR_HUGE_ARRAY * PF_ARRAY_LEN)

/* 64 MB arrays for page fault testing. */
char pf_array_dst[NR_PF_ARRAY][PF_ARRAY_LEN];
char pf_array_src[NR_PF_ARRAY][PF_ARRAY_LEN];

static int test_ops_supported(void)
{
	const char *test_name = "test_ops_supported";
	int ret;

	ret = cpu_opv(NULL, 0, -1, CPU_OP_NR_FLAG);
	if (ret < 0) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (ret < NR_CPU_OPS) {
		ksft_test_result_fail("%s test: only %d operations supported, expecting at least %d\n",
				      test_name, ret, NR_CPU_OPS);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_compare_eq_op(char *a, char *b, size_t len)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = len,
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.a, a),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.b, b),
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_compare_eq_same(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_compare_eq same";

	/* Test compare_eq */
	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i;
	for (i = 0; i < TESTBUFLEN; i++)
		buf2[i] = (char)i;
	ret = test_compare_eq_op(buf2, buf1, TESTBUFLEN);
	if (ret < 0) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (ret > 0) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, ret, 0);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_compare_eq_diff(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_compare_eq different";

	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i;
	memset(buf2, 0, TESTBUFLEN);
	ret = test_compare_eq_op(buf2, buf1, TESTBUFLEN);
	if (ret < 0) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (ret == 0) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, ret, 1);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_compare_ne_op(char *a, char *b, size_t len)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_NE_OP,
			.len = len,
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.a, a),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.b, b),
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_compare_ne_same(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_compare_ne same";

	/* Test compare_ne */
	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i;
	for (i = 0; i < TESTBUFLEN; i++)
		buf2[i] = (char)i;
	ret = test_compare_ne_op(buf2, buf1, TESTBUFLEN);
	if (ret < 0) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (ret == 0) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, ret, 1);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_compare_ne_diff(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_compare_ne different";

	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i;
	memset(buf2, 0, TESTBUFLEN);
	ret = test_compare_ne_op(buf2, buf1, TESTBUFLEN);
	if (ret < 0) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (ret != 0) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, ret, 0);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_2compare_eq_op(char *a, char *b, char *c, char *d,
		size_t len)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = len,
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.a, a),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.b, b),
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
		[1] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = len,
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.a, c),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.b, d),
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_2compare_eq_index(void)
{
	int i, ret;
	char buf1[TESTBUFLEN_CMP];
	char buf2[TESTBUFLEN_CMP];
	char buf3[TESTBUFLEN_CMP];
	char buf4[TESTBUFLEN_CMP];
	const char *test_name = "test_2compare_eq index";

	for (i = 0; i < TESTBUFLEN_CMP; i++)
		buf1[i] = (char)i;
	memset(buf2, 0, TESTBUFLEN_CMP);
	memset(buf3, 0, TESTBUFLEN_CMP);
	memset(buf4, 0, TESTBUFLEN_CMP);

	/* First compare failure is op[0], expect 1. */
	ret = test_2compare_eq_op(buf2, buf1, buf4, buf3, TESTBUFLEN_CMP);
	if (ret < 0) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (ret != 1) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, ret, 1);
		return -1;
	}

	/* All compares succeed. */
	for (i = 0; i < TESTBUFLEN_CMP; i++)
		buf2[i] = (char)i;
	ret = test_2compare_eq_op(buf2, buf1, buf4, buf3, TESTBUFLEN_CMP);
	if (ret < 0) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (ret != 0) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, ret, 0);
		return -1;
	}

	/* First compare failure is op[1], expect 2. */
	for (i = 0; i < TESTBUFLEN_CMP; i++)
		buf3[i] = (char)i;
	ret = test_2compare_eq_op(buf2, buf1, buf4, buf3, TESTBUFLEN_CMP);
	if (ret < 0) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (ret != 2) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, ret, 2);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_2compare_ne_op(char *a, char *b, char *c, char *d,
		size_t len)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_NE_OP,
			.len = len,
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.a, a),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.b, b),
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
		[1] = {
			.op = CPU_COMPARE_NE_OP,
			.len = len,
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.a, c),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.b, d),
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_2compare_ne_index(void)
{
	int i, ret;
	char buf1[TESTBUFLEN_CMP];
	char buf2[TESTBUFLEN_CMP];
	char buf3[TESTBUFLEN_CMP];
	char buf4[TESTBUFLEN_CMP];
	const char *test_name = "test_2compare_ne index";

	memset(buf1, 0, TESTBUFLEN_CMP);
	memset(buf2, 0, TESTBUFLEN_CMP);
	memset(buf3, 0, TESTBUFLEN_CMP);
	memset(buf4, 0, TESTBUFLEN_CMP);

	/* First compare ne failure is op[0], expect 1. */
	ret = test_2compare_ne_op(buf2, buf1, buf4, buf3, TESTBUFLEN_CMP);
	if (ret < 0) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (ret != 1) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, ret, 1);
		return -1;
	}

	/* All compare ne succeed. */
	for (i = 0; i < TESTBUFLEN_CMP; i++)
		buf1[i] = (char)i;
	for (i = 0; i < TESTBUFLEN_CMP; i++)
		buf3[i] = (char)i;
	ret = test_2compare_ne_op(buf2, buf1, buf4, buf3, TESTBUFLEN_CMP);
	if (ret < 0) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (ret != 0) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, ret, 0);
		return -1;
	}

	/* First compare failure is op[1], expect 2. */
	for (i = 0; i < TESTBUFLEN_CMP; i++)
		buf4[i] = (char)i;
	ret = test_2compare_ne_op(buf2, buf1, buf4, buf3, TESTBUFLEN_CMP);
	if (ret < 0) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (ret != 2) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, ret, 2);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_memcpy_op(void *dst, void *src, size_t len)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.dst, dst),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.src, src),
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_memcpy(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_memcpy";

	/* Test memcpy */
	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i;
	memset(buf2, 0, TESTBUFLEN);
	ret = test_memcpy_op(buf2, buf1, TESTBUFLEN);
	if (ret) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	for (i = 0; i < TESTBUFLEN; i++) {
		if (buf2[i] != (char)i) {
			ksft_test_result_fail("%s test: unexpected value at offset %d. Found %d. Should be %d.\n",
					      test_name, i, buf2[i], (char)i);
			return -1;
		}
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_memcpy_u32(void)
{
	int ret;
	uint32_t v1, v2;
	const char *test_name = "test_memcpy_u32";

	/* Test memcpy_u32 */
	v1 = 42;
	v2 = 0;
	ret = test_memcpy_op(&v2, &v1, sizeof(v1));
	if (ret) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (v1 != v2) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, v2, v1);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_memcpy_mb_memcpy_op(void *dst1, void *src1,
		void *dst2, void *src2, size_t len)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.dst, dst1),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.src, src1),
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
		[1] = {
			.op = CPU_MB_OP,
		},
		[2] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.dst, dst2),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.src, src2),
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_memcpy_mb_memcpy(void)
{
	int ret;
	int v1, v2, v3;
	const char *test_name = "test_memcpy_mb_memcpy";

	/* Test memcpy */
	v1 = 42;
	v2 = v3 = 0;
	ret = test_memcpy_mb_memcpy_op(&v2, &v1, &v3, &v2, sizeof(int));
	if (ret) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (v3 != v1) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, v3, v1);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_add_op(int *v, int64_t increment)
{
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_op_add(v, increment, sizeof(*v), cpu);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_add(void)
{
	int orig_v = 42, v, ret;
	int increment = 1;
	const char *test_name = "test_add";

	v = orig_v;
	ret = test_add_op(&v, increment);
	if (ret) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (v != orig_v + increment) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, v,
				      orig_v + increment);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_two_add_op(int *v, int64_t *increments)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_ADD_OP,
			.len = sizeof(*v),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(
				.u.arithmetic_op.p, v),
			.u.arithmetic_op.count = increments[0],
			.u.arithmetic_op.expect_fault_p = 0,
		},
		[1] = {
			.op = CPU_ADD_OP,
			.len = sizeof(*v),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(
				.u.arithmetic_op.p, v),
			.u.arithmetic_op.count = increments[1],
			.u.arithmetic_op.expect_fault_p = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_two_add(void)
{
	int orig_v = 42, v, ret;
	int64_t increments[2] = { 99, 123 };
	const char *test_name = "test_two_add";

	v = orig_v;
	ret = test_two_add_op(&v, increments);
	if (ret) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (v != orig_v + increments[0] + increments[1]) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, v,
				      orig_v + increments[0] + increments[1]);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_or_op(int *v, uint64_t mask)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_OR_OP,
			.len = sizeof(*v),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(
				.u.bitwise_op.p, v),
			.u.bitwise_op.mask = mask,
			.u.bitwise_op.expect_fault_p = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_or(void)
{
	int orig_v = 0xFF00000, v, ret;
	uint32_t mask = 0xFFF;
	const char *test_name = "test_or";

	v = orig_v;
	ret = test_or_op(&v, mask);
	if (ret) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (v != (orig_v | mask)) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, v, orig_v | mask);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_and_op(int *v, uint64_t mask)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_AND_OP,
			.len = sizeof(*v),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(
				.u.bitwise_op.p, v),
			.u.bitwise_op.mask = mask,
			.u.bitwise_op.expect_fault_p = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_and(void)
{
	int orig_v = 0xF00, v, ret;
	uint32_t mask = 0xFFF;
	const char *test_name = "test_and";

	v = orig_v;
	ret = test_and_op(&v, mask);
	if (ret) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (v != (orig_v & mask)) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, v, orig_v & mask);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_xor_op(int *v, uint64_t mask)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_XOR_OP,
			.len = sizeof(*v),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(
				.u.bitwise_op.p, v),
			.u.bitwise_op.mask = mask,
			.u.bitwise_op.expect_fault_p = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_xor(void)
{
	int orig_v = 0xF00, v, ret;
	uint32_t mask = 0xFFF;
	const char *test_name = "test_xor";

	v = orig_v;
	ret = test_xor_op(&v, mask);
	if (ret) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (v != (orig_v ^ mask)) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, v, orig_v ^ mask);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_lshift_op(int *v, uint32_t bits)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_LSHIFT_OP,
			.len = sizeof(*v),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(
				.u.shift_op.p, v),
			.u.shift_op.bits = bits,
			.u.shift_op.expect_fault_p = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_lshift(void)
{
	int orig_v = 0xF00, v, ret;
	uint32_t bits = 5;
	const char *test_name = "test_lshift";

	v = orig_v;
	ret = test_lshift_op(&v, bits);
	if (ret) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (v != (orig_v << bits)) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, v, orig_v << bits);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_rshift_op(int *v, uint32_t bits)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_RSHIFT_OP,
			.len = sizeof(*v),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(
				.u.shift_op.p, v),
			.u.shift_op.bits = bits,
			.u.shift_op.expect_fault_p = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_rshift(void)
{
	int orig_v = 0xF00, v, ret;
	uint32_t bits = 5;
	const char *test_name = "test_rshift";

	v = orig_v;
	ret = test_rshift_op(&v, bits);
	if (ret) {
		ksft_test_result_fail("%s test: returned with %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (v != (orig_v >> bits)) {
		ksft_test_result_fail("%s test: unexpected value %d. Should be %d.\n",
				      test_name, v, orig_v >> bits);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_cmpxchg_op(void *v, void *expect, void *old, void *n,
		size_t len)
{
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_op_cmpxchg(v, expect, old, n, len, cpu);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_cmpxchg_success(void)
{
	int ret;
	uint64_t orig_v = 1, v, expect = 1, old = 0, n = 3;
	const char *test_name = "test_cmpxchg success";

	v = orig_v;
	ret = test_cmpxchg_op(&v, &expect, &old, &n, sizeof(uint64_t));
	if (ret < 0) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (ret) {
		ksft_test_result_fail("%s returned %d, expecting %d\n",
				      test_name, ret, 0);
		return -1;
	}
	if (v != n) {
		ksft_test_result_fail("%s v is %lld, expecting %lld\n",
				      test_name, (long long)v, (long long)n);
		return -1;
	}
	if (old != orig_v) {
		ksft_test_result_fail("%s old is %lld, expecting %lld\n",
				      test_name, (long long)old,
				      (long long)orig_v);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_cmpxchg_fail(void)
{
	int ret;
	uint64_t orig_v = 1, v, expect = 123, old = 0, n = 3;
	const char *test_name = "test_cmpxchg fail";

	v = orig_v;
	ret = test_cmpxchg_op(&v, &expect, &old, &n, sizeof(uint64_t));
	if (ret < 0) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (ret == 0) {
		ksft_test_result_fail("%s returned %d, expecting %d\n",
				      test_name, ret, 1);
		return -1;
	}
	if (v == n) {
		ksft_test_result_fail("%s returned %lld, expecting %lld\n",
				      test_name, (long long)v,
				      (long long)orig_v);
		return -1;
	}
	if (old != orig_v) {
		ksft_test_result_fail("%s old is %lld, expecting %lld\n",
				      test_name, (long long)old,
				      (long long)orig_v);
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_memcpy_expect_fault_op(void *dst, void *src, size_t len)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.dst, dst),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.src, src),
			.u.memcpy_op.expect_fault_dst = 0,
			/* Return EAGAIN on fault. */
			.u.memcpy_op.expect_fault_src = 1,
		},
	};
	int cpu;

	cpu = cpu_op_get_current_cpu();
	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

static int test_memcpy_fault(void)
{
	int ret;
	char buf1[TESTBUFLEN];
	const char *test_name = "test_memcpy_fault";

	/* Test memcpy */
	ret = test_memcpy_op(buf1, NULL, TESTBUFLEN);
	if (!ret || (ret < 0 && errno != EFAULT)) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	/* Test memcpy expect fault */
	ret = test_memcpy_expect_fault_op(buf1, NULL, TESTBUFLEN);
	if (!ret || (ret < 0 && errno != EAGAIN)) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int do_test_unknown_op(void)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = -1,	/* Unknown */
			.len = 0,
		},
	};
	int cpu;

	cpu = cpu_op_get_current_cpu();
	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

static int test_unknown_op(void)
{
	int ret;
	const char *test_name = "test_unknown_op";

	ret = do_test_unknown_op();
	if (!ret || (ret < 0 && errno != EINVAL)) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int do_test_max_ops(void)
{
	struct cpu_op opvec[] = {
		[0] = { .op = CPU_MB_OP, },
		[1] = { .op = CPU_MB_OP, },
		[2] = { .op = CPU_MB_OP, },
		[3] = { .op = CPU_MB_OP, },
		[4] = { .op = CPU_MB_OP, },
		[5] = { .op = CPU_MB_OP, },
		[6] = { .op = CPU_MB_OP, },
		[7] = { .op = CPU_MB_OP, },
		[8] = { .op = CPU_MB_OP, },
		[9] = { .op = CPU_MB_OP, },
		[10] = { .op = CPU_MB_OP, },
		[11] = { .op = CPU_MB_OP, },
		[12] = { .op = CPU_MB_OP, },
		[13] = { .op = CPU_MB_OP, },
		[14] = { .op = CPU_MB_OP, },
		[15] = { .op = CPU_MB_OP, },
	};
	int cpu;

	cpu = cpu_op_get_current_cpu();
	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

static int test_max_ops(void)
{
	int ret;
	const char *test_name = "test_max_ops";

	ret = do_test_max_ops();
	if (ret < 0) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int do_test_too_many_ops(void)
{
	struct cpu_op opvec[] = {
		[0] = { .op = CPU_MB_OP, },
		[1] = { .op = CPU_MB_OP, },
		[2] = { .op = CPU_MB_OP, },
		[3] = { .op = CPU_MB_OP, },
		[4] = { .op = CPU_MB_OP, },
		[5] = { .op = CPU_MB_OP, },
		[6] = { .op = CPU_MB_OP, },
		[7] = { .op = CPU_MB_OP, },
		[8] = { .op = CPU_MB_OP, },
		[9] = { .op = CPU_MB_OP, },
		[10] = { .op = CPU_MB_OP, },
		[11] = { .op = CPU_MB_OP, },
		[12] = { .op = CPU_MB_OP, },
		[13] = { .op = CPU_MB_OP, },
		[14] = { .op = CPU_MB_OP, },
		[15] = { .op = CPU_MB_OP, },
		[16] = { .op = CPU_MB_OP, },
	};
	int cpu;

	cpu = cpu_op_get_current_cpu();
	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

static int test_too_many_ops(void)
{
	int ret;
	const char *test_name = "test_too_many_ops";

	ret = do_test_too_many_ops();
	if (!ret || (ret < 0 && errno != EINVAL)) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

/* Use 64kB len, largest page size known on Linux. */
static int test_memcpy_single_too_large(void)
{
	int i, ret;
	char buf1[TESTBUFLEN_PAGE_MAX + 1];
	char buf2[TESTBUFLEN_PAGE_MAX + 1];
	const char *test_name = "test_memcpy_single_too_large";

	/* Test memcpy */
	for (i = 0; i < TESTBUFLEN_PAGE_MAX + 1; i++)
		buf1[i] = (char)i;
	memset(buf2, 0, TESTBUFLEN_PAGE_MAX + 1);
	ret = test_memcpy_op(buf2, buf1, TESTBUFLEN_PAGE_MAX + 1);
	if (!ret || (ret < 0 && errno != EINVAL)) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

static int test_memcpy_single_ok_sum_too_large_op(void *dst, void *src,
						  size_t len)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.dst, dst),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.src, src),
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
		[1] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.dst, dst),
			LINUX_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.src, src),
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_memcpy_single_ok_sum_too_large(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_memcpy_single_ok_sum_too_large";

	/* Test memcpy */
	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i;
	memset(buf2, 0, TESTBUFLEN);
	ret = test_memcpy_single_ok_sum_too_large_op(buf2, buf1, TESTBUFLEN);
	if (!ret || (ret < 0 && errno != EINVAL)) {
		ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

/*
 * Iterate over large uninitialized arrays to trigger page faults.
 * This includes reading from zero pages.
 */
int test_page_fault(void)
{
	int ret = 0;
	uint64_t i;
	const char *test_name = "test_page_fault";

	for (i = 0; i < NR_PF_ARRAY; i++) {
		ret = test_memcpy_op(pf_array_dst[i],
				     pf_array_src[i],
				     PF_ARRAY_LEN);
		if (ret) {
			ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
					      test_name, ret, strerror(errno));
			return ret;
		}
	}
	ksft_test_result_pass("%s test\n", test_name);
	return 0;
}

/*
 * Try to use 2MB huge pages.
 */
int test_hugetlb(void)
{
	int ret = 0;
	uint64_t i;
	const char *test_name = "test_hugetlb";
	int *dst, *src;

	dst = mmap(NULL, HUGEMAPLEN, PROT_READ | PROT_WRITE,
		   MAP_HUGETLB | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (dst == MAP_FAILED) {
		switch (errno) {
		case ENOMEM:
		case ENOENT:
		case EINVAL:
			ksft_test_result_skip("%s test.\n", test_name);
			goto end;
		default:
			break;
		}
		perror("mmap");
		abort();
	}
	src = mmap(NULL, HUGEMAPLEN, PROT_READ | PROT_WRITE,
		   MAP_HUGETLB | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (src == MAP_FAILED) {
		if (errno == ENOMEM) {
			ksft_test_result_skip("%s test.\n", test_name);
			goto unmap_dst;
		}
		perror("mmap");
		abort();
	}

	/* Read/write from/to huge zero pages. */
	for (i = 0; i < NR_HUGE_ARRAY; i++) {
		ret = test_memcpy_op(dst + (i * PF_ARRAY_LEN / sizeof(int)),
				     src + (i * PF_ARRAY_LEN / sizeof(int)),
				     PF_ARRAY_LEN);
		if (ret) {
			ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
					      test_name, ret, strerror(errno));
			return ret;
		}
	}
	for (i = 0; i < NR_HUGE_ARRAY * (PF_ARRAY_LEN / sizeof(int)); i++)
		src[i] = i;

	for (i = 0; i < NR_HUGE_ARRAY; i++) {
		ret = test_memcpy_op(dst + (i * PF_ARRAY_LEN / sizeof(int)),
				     src + (i * PF_ARRAY_LEN / sizeof(int)),
				     PF_ARRAY_LEN);
		if (ret) {
			ksft_test_result_fail("%s test: ret = %d, errno = %s\n",
					      test_name, ret, strerror(errno));
			return ret;
		}
	}

	for (i = 0; i < NR_HUGE_ARRAY * (PF_ARRAY_LEN / sizeof(int)); i++) {
		if (dst[i] != i) {
			ksft_test_result_fail("%s mismatch, expect %d, got %d\n",
					      test_name, i, dst[i]);
			return ret;
		}
	}

	ksft_test_result_pass("%s test\n", test_name);

	if (munmap(src, HUGEMAPLEN)) {
		perror("munmap");
		abort();
	}
unmap_dst:
	if (munmap(dst, HUGEMAPLEN)) {
		perror("munmap");
		abort();
	}
end:
	return 0;
}

static int test_cmpxchg_op_cpu(void *v, void *expect, void *old, void *n,
		size_t len, int cpu)
{
	int ret;

	do {
		ret = cpu_op_cmpxchg(v, expect, old, n, len, cpu);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_over_possible_cpu(void)
{
	int ret;
	uint64_t orig_v = 1, v, expect = 1, old = 0, n = 3;
	const char *test_name = "test_over_possible_cpu";

	v = orig_v;
	ret = test_cmpxchg_op_cpu(&v, &expect, &old, &n, sizeof(uint64_t),
				  0xFFFFFFFF);
	if (ret == 0) {
		ksft_test_result_fail("%s test: ret = %d\n",
				      test_name, ret);
		return -1;
	}
	if (ret < 0 && errno == EINVAL) {
		ksft_test_result_pass("%s test\n", test_name);
		return 0;
	}
	ksft_test_result_fail("%s returned %d, errno %s, expecting %d, errno %s\n",
			      test_name, ret, strerror(errno),
			      0, strerror(EINVAL));
	return -1;
}

static int test_allowed_affinity(void)
{
	int ret;
	uint64_t orig_v = 1, v, expect = 1, old = 0, n = 3;
	const char *test_name = "test_allowed_affinity";
	cpu_set_t allowed_cpus, cpuset;

	ret = sched_getaffinity(0, sizeof(allowed_cpus), &allowed_cpus);
	if (ret) {
		ksft_test_result_fail("%s returned %d, errno %s\n",
				      test_name, ret, strerror(errno));
		return -1;
	}
	if (!(CPU_ISSET(0, &allowed_cpus) && CPU_ISSET(1, &allowed_cpus))) {
		ksft_test_result_skip("%s test. Requiring allowed CPUs 0 and 1.\n",
				      test_name);
		return 0;
	}
	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);
	if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
		ksft_test_result_fail("%s test. Unable to set affinity. errno = %s\n",
				      test_name, strerror(errno));
		return -1;
	}
	v = orig_v;
	ret = test_cmpxchg_op_cpu(&v, &expect, &old, &n, sizeof(uint64_t),
				  1);
	if (sched_setaffinity(0, sizeof(allowed_cpus), &allowed_cpus) != 0) {
		ksft_test_result_fail("%s test. Unable to set affinity. errno = %s\n",
				      test_name, strerror(errno));
		return -1;
	}
	if (ret == 0) {
		ksft_test_result_fail("%s test: ret = %d\n",
				      test_name, ret);
		return -1;
	}

	if (ret < 0 && errno == EINVAL) {
		ksft_test_result_pass("%s test\n", test_name);
		return 0;
	}
	ksft_test_result_fail("%s returned %d, errno %s, expecting %d, errno %s\n",
			      test_name, ret, strerror(errno),
			      0, strerror(EINVAL));
	return -1;
}

int main(int argc, char **argv)
{
	ksft_print_header();

	test_ops_supported();
	test_compare_eq_same();
	test_compare_eq_diff();
	test_compare_ne_same();
	test_compare_ne_diff();
	test_2compare_eq_index();
	test_2compare_ne_index();
	test_memcpy();
	test_memcpy_u32();
	test_memcpy_mb_memcpy();
	test_add();
	test_two_add();
	test_or();
	test_and();
	test_xor();
	test_lshift();
	test_rshift();
	test_cmpxchg_success();
	test_cmpxchg_fail();
	test_memcpy_fault();
	test_unknown_op();
	test_max_ops();
	test_too_many_ops();
	test_memcpy_single_too_large();
	test_memcpy_single_ok_sum_too_large();
	test_page_fault();
	test_hugetlb();
	test_over_possible_cpu();
	test_allowed_affinity();

	return ksft_exit_pass();
}
