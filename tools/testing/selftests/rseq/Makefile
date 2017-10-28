CFLAGS += -O2 -Wall -g -I./ -I../cpu-opv/ -I../../../../usr/include/
LDLIBS += -lpthread

TEST_GEN_PROGS = basic_test basic_percpu_ops_test param_test

#TEST_PROGS = run_param_test_check.sh

include ../lib.mk

$(TEST_GEN_PROGS): rseq.h rseq-*.h rseq.c ../cpu-opv/cpu-op.c ../cpu-opv/cpu-op.h
