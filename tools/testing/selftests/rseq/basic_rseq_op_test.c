/*
 * Basic test coverage for rseq_op system call.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include <rseq.h>

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

#define TESTBUFLEN	4096

static int test_compare_eq_op(char *a, char *b, size_t len)
{
	struct rseq_op opvec[] = {
		[0] = {
			.op = RSEQ_COMPARE_EQ_OP,
			.len = len,
			.u.compare_op.a = (unsigned long)a,
			.u.compare_op.b = (unsigned long)b,
		},
	};
	int ret, cpu;

	do {
		cpu = rseq_fallback_current_cpu();
		ret = rseq_op(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_compare_eq_same(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_compare_eq same";

	printf("Testing %s\n", test_name);

	/* Test compare_eq */
	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i;
	for (i = 0; i < TESTBUFLEN; i++)
		buf2[i] = (char)i;
	ret = test_compare_eq_op(buf2, buf1, TESTBUFLEN);
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (ret > 0) {
		printf("%s returned %d, expecting %d\n",
			test_name, ret, 0);
		return -1;
	}
	return 0;
}

static int test_compare_eq_diff(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_compare_eq different";

	printf("Testing %s\n", test_name);

	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i;
	memset(buf2, 0, TESTBUFLEN);
	ret = test_compare_eq_op(buf2, buf1, TESTBUFLEN);
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (ret == 0) {
		printf("%s returned %d, expecting %d\n",
			test_name, ret, 1);
		return -1;
	}
	return 0;
}

static int test_memcpy_op(char *dst, char *src, size_t len)
{
	struct rseq_op opvec[] = {
		[0] = {
			.op = RSEQ_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)dst,
			.u.memcpy_op.src = (unsigned long)src,
		},
	};
	int ret, cpu;

	do {
		cpu = rseq_fallback_current_cpu();
		ret = rseq_op(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_memcpy(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_memcpy";

	printf("Testing %s\n", test_name);

	/* Test memcpy */
	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i;
	memset(buf2, 0, TESTBUFLEN);
	ret = test_memcpy_op(buf2, buf1, TESTBUFLEN);
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	for (i = 0; i < TESTBUFLEN; i++) {
		if (buf2[i] != (char)i) {
			printf("%s failed. Expecting '%d', found '%d' at offset %d\n",
				test_name, (char)i, buf2[i], i);
			return -1;
		}
	}
	return 0;
}

static int test_memcpy_u32(void)
{
	int ret;
	uint32_t v1, v2;
	const char *test_name = "test_memcpy_u32";

	printf("Testing %s\n", test_name);

	/* Test memcpy_u32 */
	v1 = 42;
	v2 = 0;
	ret = test_memcpy_op(&v2, &v1, sizeof(v1));
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (v1 != v2) {
		printf("%s failed. Expecting '%d', found '%d'\n",
			test_name, v1, v2);
		return -1;
	}
	return 0;
}

static int test_add_op(int *v, int64_t increment)
{
	struct rseq_op opvec[] = {
		[0] = {
			.op = RSEQ_ADD_OP,
			.len = sizeof(*v),
			.u.arithmetic_op.p = (unsigned long)v,
			.u.arithmetic_op.count = increment,
		},
	};
	int ret, cpu;

	do {
		cpu = rseq_fallback_current_cpu();
		ret = rseq_op(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_add(void)
{
	int orig_v = 42, v, ret;
	int increment = 1;
	const char *test_name = "test_add";

	printf("Testing %s\n", test_name);

	v = orig_v;
	ret = test_add_op(&v, increment);
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		return -1;
	}
	if (v != orig_v + increment) {
		printf("%s unexpected value: %d. Should be %d.\n",
			test_name, v, orig_v);
		return -1;
	}
	return 0;
}

static int test_two_add_op(int *v, int64_t *increments)
{
	struct rseq_op opvec[] = {
		[0] = {
			.op = RSEQ_ADD_OP,
			.len = sizeof(*v),
			.u.arithmetic_op.p = (unsigned long)v,
			.u.arithmetic_op.count = increments[0],
		},
		[1] = {
			.op = RSEQ_ADD_OP,
			.len = sizeof(*v),
			.u.arithmetic_op.p = (unsigned long)v,
			.u.arithmetic_op.count = increments[1],
		},
	};
	int ret, cpu;

	do {
		cpu = rseq_fallback_current_cpu();
		ret = rseq_op(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_two_add(void)
{
	int orig_v = 42, v, ret;
	int64_t increments[2] = { 99, 123 };
	const char *test_name = "test_two_add";

	printf("Testing %s\n", test_name);

	v = orig_v;
	ret = test_two_add_op(&v, increments);
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		return -1;
	}
	if (v != orig_v + increments[0] + increments[1]) {
		printf("%s unexpected value: %d. Should be %d.\n",
			test_name, v, orig_v);
		return -1;
	}
	return 0;
}

static int test_or_op(int *v, uint64_t mask)
{
	struct rseq_op opvec[] = {
		[0] = {
			.op = RSEQ_OR_OP,
			.len = sizeof(*v),
			.u.bitwise_op.p = (unsigned long)v,
			.u.bitwise_op.mask = mask,
		},
	};
	int ret, cpu;

	do {
		cpu = rseq_fallback_current_cpu();
		ret = rseq_op(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_or(void)
{
	int orig_v = 0xFF00000, v, ret;
	uint32_t mask = 0xFFF;
	const char *test_name = "test_or";

	printf("Testing %s\n", test_name);

	v = orig_v;
	ret = test_or_op(&v, mask);
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		return -1;
	}
	if (v != (orig_v | mask)) {
		printf("%s unexpected value: %d. Should be %d.\n",
			test_name, v, orig_v | mask);
		return -1;
	}
	return 0;
}

static int test_and_op(int *v, uint64_t mask)
{
	struct rseq_op opvec[] = {
		[0] = {
			.op = RSEQ_AND_OP,
			.len = sizeof(*v),
			.u.bitwise_op.p = (unsigned long)v,
			.u.bitwise_op.mask = mask,
		},
	};
	int ret, cpu;

	do {
		cpu = rseq_fallback_current_cpu();
		ret = rseq_op(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_and(void)
{
	int orig_v = 0xF00, v, ret;
	uint32_t mask = 0xFFF;
	const char *test_name = "test_and";

	printf("Testing %s\n", test_name);

	v = orig_v;
	ret = test_and_op(&v, mask);
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		return -1;
	}
	if (v != (orig_v & mask)) {
		printf("%s unexpected value: %d. Should be %d.\n",
			test_name, v, orig_v & mask);
		return -1;
	}
	return 0;
}

static int test_xor_op(int *v, uint64_t mask)
{
	struct rseq_op opvec[] = {
		[0] = {
			.op = RSEQ_XOR_OP,
			.len = sizeof(*v),
			.u.bitwise_op.p = (unsigned long)v,
			.u.bitwise_op.mask = mask,
		},
	};
	int ret, cpu;

	do {
		cpu = rseq_fallback_current_cpu();
		ret = rseq_op(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_xor(void)
{
	int orig_v = 0xF00, v, ret;
	uint32_t mask = 0xFFF;
	const char *test_name = "test_xor";

	printf("Testing %s\n", test_name);

	v = orig_v;
	ret = test_xor_op(&v, mask);
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		return -1;
	}
	if (v != (orig_v ^ mask)) {
		printf("%s unexpected value: %d. Should be %d.\n",
			test_name, v, orig_v ^ mask);
		return -1;
	}
	return 0;
}

static int test_cmpxchg_op(void *v, void *expect, void *old, void *n,
		size_t len)
{
	struct rseq_op opvec[] = {
		[0] = {
			.op = RSEQ_COMPARE_EQ_OP,
			.len = len,
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)expect,
		},
		[1] = {
			.op = RSEQ_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)old,
			.u.memcpy_op.src = (unsigned long)v,
		},
		[2] = {
			.op = RSEQ_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)n,
		},
	};
	int ret, cpu;

	do {
		cpu = rseq_fallback_current_cpu();
		ret = rseq_op(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}


static int test_cmpxchg_success(void)
{
	int ret;
	uint64_t orig_v = 1, v, expect = 1, old = 0, n = 3;
	const char *test_name = "test_cmpxchg success";

	printf("Testing %s\n", test_name);

	v = orig_v;
	ret = test_cmpxchg_op(&v, &expect, &old, &n, sizeof(uint64_t));
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (ret) {
		printf("%s returned %d, expecting %d\n",
			test_name, ret, 0);
		return -1;
	}
	if (v != n) {
		printf("%s v is %lld, expecting %lld\n",
			test_name, (long long)v, (long long)n);
		return -1;
	}
	if (old != orig_v) {
		printf("%s old is %lld, expecting %lld\n",
			test_name, (long long)old, (long long)orig_v);
		return -1;
	}
	return 0;
}

static int test_cmpxchg_fail(void)
{
	int ret;
	uint64_t orig_v = 1, v, expect = 123, orig_old = 0, old = 0, n = 3;
	const char *test_name = "test_cmpxchg fail";

	printf("Testing %s\n", test_name);

	v = orig_v;
	ret = test_cmpxchg_op(&v, &expect, &old, &n, sizeof(uint64_t));
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (ret == 0) {
		printf("%s returned %d, expecting %d\n",
			test_name, ret, 1);
		return -1;
	}
	if (v == n) {
		printf("%s v is %lld, expecting %lld\n",
			test_name, (long long)v, (long long)orig_v);
		return -1;
	}
	if (old) {
		printf("%s old is %lld, expecting %lld\n",
			test_name, (long long)old, (long long)orig_old);
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int ret = 0;

	ret |= test_compare_eq_same();
	ret |= test_compare_eq_diff();
	ret |= test_memcpy();
	ret |= test_memcpy_u32();
	ret |= test_add();
	ret |= test_two_add();
	ret |= test_or();
	ret |= test_and();
	ret |= test_xor();
	ret |= test_cmpxchg_success();
	ret |= test_cmpxchg_fail();

	return ret;
}
