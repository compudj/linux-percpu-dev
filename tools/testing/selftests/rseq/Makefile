CFLAGS += -O2 -Wall -g -I./ -I../cpu-opv/ -I../../../../usr/include/
LDFLAGS += -lpthread

TESTS = basic_test basic_percpu_ops_test param_test

all: $(TESTS)
%: %.c rseq.h rseq-*.h rseq.c ../cpu-opv/cpu-op.c ../cpu-opv/cpu-op.h
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

include ../lib.mk

clean:
	$(RM) $(TESTS)
