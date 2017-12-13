CFLAGS += -O2 -Wall -g -I./ -I../cpu-opv/ -I../../../../usr/include/ -L./ -Wl,-rpath=./
LDLIBS += -lpthread

# Own dependencies because we only want to build against 1st prerequisite, but
# still track changes to header files and depend on shared object.
OVERRIDE_TARGETS = 1

TEST_GEN_PROGS = basic_test basic_percpu_ops_test \
		param_test param_test_skip_fastpath \
		param_test_benchmark param_test_compare_twice

TEST_GEN_PROGS_EXTENDED = librseq.so libcpu-op.so

TEST_PROGS = run_param_test.sh

include ../lib.mk

$(OUTPUT)/librseq.so: rseq.c rseq.h rseq-*.h
	$(CC) $(CFLAGS) -shared -fPIC $< $(LDLIBS) -o $@

$(OUTPUT)/libcpu-op.so: ../cpu-opv/cpu-op.c ../cpu-opv/cpu-op.h
	$(CC) $(CFLAGS) -shared -fPIC $< $(LDLIBS) -o $@

$(OUTPUT)/%: %.c $(TEST_GEN_PROGS_EXTENDED) rseq.h rseq-*.h ../cpu-opv/cpu-op.h percpu-op.h
	$(CC) $(CFLAGS) $< $(LDLIBS) -lrseq -lcpu-op -o $@

$(OUTPUT)/param_test_skip_fastpath: param_test.c $(TEST_GEN_PROGS_EXTENDED) \
					rseq.h rseq-*.h ../cpu-opv/cpu-op.h percpu-op.h
	$(CC) $(CFLAGS) -DRSEQ_SKIP_FASTPATH $< $(LDLIBS) -lrseq -lcpu-op -o $@

$(OUTPUT)/param_test_benchmark: param_test.c $(TEST_GEN_PROGS_EXTENDED) \
					rseq.h rseq-*.h ../cpu-opv/cpu-op.h percpu-op.h
	$(CC) $(CFLAGS) -DBENCHMARK $< $(LDLIBS) -lrseq -lcpu-op -o $@

$(OUTPUT)/param_test_compare_twice: param_test.c $(TEST_GEN_PROGS_EXTENDED) \
					rseq.h rseq-*.h ../cpu-opv/cpu-op.h percpu-op.h
	$(CC) $(CFLAGS) -DRSEQ_COMPARE_TWICE $< $(LDLIBS) -lrseq -lcpu-op -o $@
