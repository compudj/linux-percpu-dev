// SPDX-License-Identifier: LGPL-2.1-only
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "percpu-op.h"

static int opt_threads = 200;
static long long opt_reps = 1000;

static inline pid_t test_gettid(void)
{
	return syscall(__NR_gettid);
}

struct percpu_lock_entry {
	intptr_t v;
} __attribute__((aligned(128)));

struct percpu_lock {
	struct percpu_lock_entry c[CPU_SETSIZE];
};

struct test_data_entry {
	intptr_t count;
} __attribute__((aligned(128)));

struct thread_data {
	int cpu_affinity;
};

static struct percpu_lock lock;
volatile struct test_data_entry c[CPU_SETSIZE];

volatile int stop;

int trace_fd;

void trace_write(const char *fmt, ...)
{
	va_list ap;
	char buf[256];
	int n;

	if (trace_fd < 0)
		return;
	va_start(ap, fmt);
	n = vsnprintf(buf, 256, fmt, ap);
	va_end(ap);
	if (write(trace_fd, buf, n) < 0)
		abort();
}

/* A simple percpu spinlock. */
static void rseq_percpu_lock(struct percpu_lock *lock, int cpu, int t)
{
	for (;;) {
		int ret;

		ret = percpu_cmpeqv_storev(&lock->c[cpu].v,
					   0, t, cpu);
		if (rseq_likely(!ret))
			break;
		if (rseq_unlikely(ret < 0)) {
			perror("sched_pair_cpu");
			abort();
		}
		/* Retry if comparison fails. */
	}
	/*
	 * Acquire semantic when taking lock after control dependency.
	 * Matches rseq_smp_store_release().
	 */
	rseq_smp_acquire__after_ctrl_dep();
}

static void rseq_percpu_unlock(struct percpu_lock *lock, int cpu, int t)
{
	int v = lock->c[cpu].v;

	if (v != t) {
		trace_write("Unexpected lock value=%d on cpu %d thread %d/%d\n",
			v, sched_getcpu(), getpid(), t);
		fprintf(stderr, "Unexpected lock value=%d on cpu %d thread %d/%d\n",
			v, sched_getcpu(), getpid(), t);
		abort();
	}
	/*
	 * Release lock, with release semantic. Matches
	 * rseq_smp_acquire__after_ctrl_dep().
	 */
	rseq_smp_store_release(&lock->c[cpu].v, 0);
}

static void set_affinity(int cpu)
{
        cpu_set_t mask;

        CPU_ZERO(&mask);
        CPU_SET(cpu, &mask);
        if (sched_setaffinity(0, sizeof(mask), &mask)) {
                perror("sched_setaffinity");
                abort();
        }
}

static void *test_thread(void *arg)
{
	long long reps, i;
	struct thread_data *td = arg;
	int t = test_gettid();

	if (td->cpu_affinity >= 0)
		set_affinity(td->cpu_affinity);
	if (rseq_register_current_thread())
		abort();
	reps = opt_reps;
	if (td->cpu_affinity == 0) {
		while (!stop) {
			int cpu = 0; /* work on cpu 0's data. */
			int v;

			rseq_percpu_lock(&lock, cpu, t);
			v = c[cpu].count;
			if (v != 0) {
				trace_write("Unexpected value=%d on cpu %d thread %d/%d\n",
					v, sched_getcpu(), getpid(), t);
				fprintf(stderr, "Unexpected value=%d on cpu %d thread %d/%d\n",
					v, sched_getcpu(), getpid(), t);
				abort();
			}
			c[cpu].count = t;
			c[cpu].count = 0;
			rseq_percpu_unlock(&lock, cpu, t);
		}
	} else {
		for (i = 0; i < reps; i++) {
			int cpu = 0; /* work on cpu 0's data. */
			int v;

			rseq_percpu_lock(&lock, cpu, t);
			v = c[cpu].count;
			if (v != 0) {
				trace_write("Unexpected value=%d on cpu %d thread %d/%d\n",
					v, sched_getcpu(), getpid(), t);
				fprintf(stderr, "Unexpected value=%d on cpu %d thread %d/%d\n",
					v, sched_getcpu(), getpid(), t);
				abort();
			}
			c[cpu].count = t;
			c[cpu].count = 0;
			rseq_percpu_unlock(&lock, cpu, t);
		}
		stop = 1;
	}
	if (rseq_unregister_current_thread())
		abort();
	return NULL;
}

int main(int argc, char **argv)
{
	const int num_threads = opt_threads;
	pthread_t test_threads[num_threads];
	struct thread_data td[num_threads];
	int ret, i;

	trace_fd = open("/sys/kernel/debug/tracing/trace_marker", O_WRONLY);
	if (trace_fd < 0)
		abort();

	trace_write("test start");

	for (i = 0; i < num_threads; i++) {
		if (i == 0)
			td[i].cpu_affinity = 0;
		else
			td[i].cpu_affinity = -1;
		ret = pthread_create(&test_threads[i], NULL,
				     test_thread,
				     &td[i]);
		if (ret) {
			errno = ret;
			perror("pthread_create");
			abort();
		}
	}

	for (i = 0; i < num_threads; i++) {
		ret = pthread_join(test_threads[i], NULL);
		if (ret) {
			errno = ret;
			perror("pthread_join");
			abort();
		}
	}
	trace_write("test end");

	return 0;
}
