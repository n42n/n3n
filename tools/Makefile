#
# This is not a standalone makefile, it must be called from the toplevel
# makefile to inherit the correct environment

DEBUG?=-g3

CFLAGS+=$(DEBUG)

CFLAGS+=-I../include
LDFLAGS+=-L..
LDLIBS+=-ln3n
LDLIBS+=$(LDLIBS_EXTRA)

TOOLS+=n3n-benchmark
TOOLS+=n3n-keygen
TOOLS+=n3n-route
TOOLS+=n3n-portfwd
TOOLS+=n3n-decode

TESTS=tests-compress
TESTS+=tests-elliptic
TESTS+=tests-hashing
TESTS+=tests-transform
TESTS+=tests-wire
TESTS+=tests-auth

.PHONY: all clean install
all: $(TOOLS) $(TESTS)

# See comments in the topdir Makefile about how to generate coverage
# data.
gcov:
	gcov $(TOOLS) $(TESTS)

clean:
	rm -rf $(TOOLS) *.o *.dSYM *~
	rm -f $(TESTS) *.gcno *.gcda

install: $(TOOLS)
	$(INSTALL_PROG) $(addsuffix $(EXE),$(TOOLS)) $(SBINDIR)/
