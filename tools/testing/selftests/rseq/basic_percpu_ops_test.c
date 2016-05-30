#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rseq.h"
#include "cpu-op.h"

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

struct percpu_lock_entry {
	intptr_t v;
} __attribute__((aligned(128)));

struct percpu_lock {
	struct percpu_lock_entry c[CPU_SETSIZE];
};

struct test_data_entry {
	intptr_t count;
} __attribute__((aligned(128)));

struct spinlock_test_data {
	struct percpu_lock lock;
	struct test_data_entry c[CPU_SETSIZE];
	int reps;
};

struct percpu_list_node {
	intptr_t data;
	struct percpu_list_node *next;
};

struct percpu_list_entry {
	struct percpu_list_node *head;
} __attribute__((aligned(128)));

struct percpu_list {
	struct percpu_list_entry c[CPU_SETSIZE];
};

/* A simple percpu spinlock.  Returns the cpu lock was acquired on. */
int rseq_percpu_lock(struct percpu_lock *lock)
{
	int cpu;

	for (;;) {
		struct rseq_state rseq_state;
		intptr_t expect = 0, n = 1;
		int ret;

		/* Try fast path. */
		rseq_state = rseq_start();
		cpu = rseq_cpu_at_start(rseq_state);
		if (unlikely(lock->c[cpu].v != 0))
			continue;	/* Retry.*/
		if (likely(rseq_finish(&lock->c[cpu].v, 1, rseq_state)))
			break;
		/* Fallback on cpu_opv system call. */
		cpu = rseq_current_cpu_raw();
		ret = cpu_op_cmpstore(&lock->c[cpu].v, &expect, &n,
			sizeof(intptr_t), cpu);
		if (likely(!ret))
			break;
		assert(ret >= 0 || errno == EAGAIN);
	}
	/*
	 * Acquire semantic when taking lock after control dependency.
	 * Matches smp_store_release().
	 */
	smp_acquire__after_ctrl_dep();
	return cpu;
}

void rseq_percpu_unlock(struct percpu_lock *lock, int cpu)
{
	assert(lock->c[cpu].v == 1);
	/*
	 * Release lock, with release semantic. Matches
	 * smp_acquire__after_ctrl_dep().
	 */
	smp_store_release(&lock->c[cpu].v, 0);
}

void *test_percpu_spinlock_thread(void *arg)
{
	struct spinlock_test_data *data = arg;
	int i, cpu;

	if (rseq_register_current_thread())
		abort();
	for (i = 0; i < data->reps; i++) {
		cpu = rseq_percpu_lock(&data->lock);
		data->c[cpu].count++;
		rseq_percpu_unlock(&data->lock, cpu);
	}
	if (rseq_unregister_current_thread())
		abort();

	return NULL;
}

/*
 * A simple test which implements a sharded counter using a per-cpu
 * lock.  Obviously real applications might prefer to simply use a
 * per-cpu increment; however, this is reasonable for a test and the
 * lock can be extended to synchronize more complicated operations.
 */
void test_percpu_spinlock(void)
{
	const int num_threads = 200;
	int i;
	uint64_t sum;
	pthread_t test_threads[num_threads];
	struct spinlock_test_data data;

	memset(&data, 0, sizeof(data));
	data.reps = 5000;

	for (i = 0; i < num_threads; i++)
		pthread_create(&test_threads[i], NULL,
			test_percpu_spinlock_thread, &data);

	for (i = 0; i < num_threads; i++)
		pthread_join(test_threads[i], NULL);

	sum = 0;
	for (i = 0; i < CPU_SETSIZE; i++)
		sum += data.c[i].count;

	assert(sum == (uint64_t)data.reps * num_threads);
}

int percpu_list_push(struct percpu_list *list, struct percpu_list_node *node)
{
	struct rseq_state rseq_state;
	intptr_t *targetptr, newval, expect;
	int cpu;

	/* Try fast path. */
	rseq_state = rseq_start();
	cpu = rseq_cpu_at_start(rseq_state);
	newval = (intptr_t)node;
	targetptr = (intptr_t *)&list->c[cpu].head;
	node->next = list->c[cpu].head;
	if (unlikely(!rseq_finish(targetptr, newval, rseq_state))) {
		/* Fallback on cpu_opv system call. */
		for (;;) {
			int ret;

			cpu = rseq_current_cpu_raw();
			/* Load list->c[cpu].head with single-copy atomicity. */
			expect = (intptr_t)READ_ONCE(list->c[cpu].head);
			newval = (intptr_t)node;
			targetptr = (intptr_t *)&list->c[cpu].head;
			node->next = (struct percpu_list_node *)expect;
			ret = cpu_op_cmpstore(targetptr, &expect, &newval,
				sizeof(intptr_t), cpu);
			if (likely(!ret))
				break;
			assert(ret >= 0 || errno == EAGAIN);
		}
	}
	return cpu;
}

/*
 * Unlike a traditional lock-less linked list; the availability of a
 * rseq primitive allows us to implement pop without concerns over
 * ABA-type races.
 */
struct percpu_list_node *percpu_list_pop(struct percpu_list *list)
{
	struct percpu_list_node *head, *next;
	struct rseq_state rseq_state;
	intptr_t *targetptr, newval, expect;
	int cpu;

	/* Try fast path. */
	rseq_state = rseq_start();
	cpu = rseq_cpu_at_start(rseq_state);
	/* Load head with single-copy atomicity. */
	head = READ_ONCE(list->c[cpu].head);
	if (!head)
		return NULL;
	/* Load head->next with single-copy atomicity. */
	next = READ_ONCE(head->next);
	newval = (intptr_t)next;
	targetptr = (intptr_t *)&list->c[cpu].head;
	if (unlikely(!rseq_finish(targetptr, newval, rseq_state))) {
		/* Fallback on cpu_opv system call. */
		for (;;) {
			int ret;

			cpu = rseq_current_cpu_raw();
			/* Load head with single-copy atomicity. */
			head = READ_ONCE(list->c[cpu].head);
			if (!head)
				return NULL;
			expect = (intptr_t)head;
			/* Load head->next with single-copy atomicity. */
			next = READ_ONCE(head->next);
			newval = (intptr_t)next;
			targetptr = (intptr_t *)&list->c[cpu].head;
			ret = cpu_op_2cmp1store(targetptr, &expect, &newval,
				&head->next, &next,
				sizeof(intptr_t), cpu);
			if (likely(!ret))
				break;
			assert(ret >= 0 || errno == EAGAIN);
		}
	}

	return head;
}

void *test_percpu_list_thread(void *arg)
{
	int i;
	struct percpu_list *list = (struct percpu_list *)arg;

	if (rseq_register_current_thread())
		abort();

	for (i = 0; i < 100000; i++) {
		struct percpu_list_node *node = percpu_list_pop(list);

		sched_yield();  /* encourage shuffling */
		if (node)
			percpu_list_push(list, node);
	}

	if (rseq_unregister_current_thread())
		abort();

	return NULL;
}

/* Simultaneous modification to a per-cpu linked list from many threads.  */
void test_percpu_list(void)
{
	int i, j;
	uint64_t sum = 0, expected_sum = 0;
	struct percpu_list list;
	pthread_t test_threads[200];
	cpu_set_t allowed_cpus;

	memset(&list, 0, sizeof(list));

	/* Generate list entries for every usable cpu. */
	sched_getaffinity(0, sizeof(allowed_cpus), &allowed_cpus);
	for (i = 0; i < CPU_SETSIZE; i++) {
		if (!CPU_ISSET(i, &allowed_cpus))
			continue;
		for (j = 1; j <= 100; j++) {
			struct percpu_list_node *node;

			expected_sum += j;

			node = malloc(sizeof(*node));
			assert(node);
			node->data = j;
			node->next = list.c[i].head;
			list.c[i].head = node;
		}
	}

	for (i = 0; i < 200; i++)
		assert(pthread_create(&test_threads[i], NULL,
			test_percpu_list_thread, &list) == 0);

	for (i = 0; i < 200; i++)
		pthread_join(test_threads[i], NULL);

	for (i = 0; i < CPU_SETSIZE; i++) {
		cpu_set_t pin_mask;
		struct percpu_list_node *node;

		if (!CPU_ISSET(i, &allowed_cpus))
			continue;

		CPU_ZERO(&pin_mask);
		CPU_SET(i, &pin_mask);
		sched_setaffinity(0, sizeof(pin_mask), &pin_mask);

		while ((node = percpu_list_pop(&list))) {
			sum += node->data;
			free(node);
		}
	}

	/*
	 * All entries should now be accounted for (unless some external
	 * actor is interfering with our allowed affinity while this
	 * test is running).
	 */
	assert(sum == expected_sum);
}

int main(int argc, char **argv)
{
	if (rseq_register_current_thread())
		goto error;
	printf("spinlock\n");
	test_percpu_spinlock();
	printf("percpu_list\n");
	test_percpu_list();
	if (rseq_unregister_current_thread())
		goto error;
	return 0;

error:
	return -1;
}

