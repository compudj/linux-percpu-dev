CFLAGS += -O2 -Wall -g -I./ -I../../../../usr/include/
LDFLAGS += -lpthread

TESTS = basic_cpu_opv_test

all: $(TESTS)
%: %.c cpu-op.c cpu-op.h
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

include ../lib.mk

clean:
	$(RM) $(TESTS)
