#
# This is not a standalone makefile, it must be called from the toplevel
# makefile to inherit the correct environment

DEBUG?=-g3

CFLAGS+=$(DEBUG)

CFLAGS+=-I../include
LDFLAGS+=-L../src
LDLIBS+=-ln3n
LDLIBS+=$(LDLIBS_EXTRA)

TOOLS+=n3n-benchmark
TOOLS+=n3n-route
TOOLS+=n3n-portfwd
TOOLS+=n3n-decode

TESTS=tests-compress
TESTS+=tests-elliptic
TESTS+=tests-transform
TESTS+=tests-wire
TESTS+=tests-auth

.PHONY: all clean install
all: $(TOOLS) $(TESTS)

# Remember to keep the two CC lines in sync
$(info CC is: $(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $$^ $(LDLIBS) -o $$@)
%: %.c
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

# See comments in the topdir Makefile about how to generate coverage
# data.
gcov:
	gcov $(TOOLS) $(TESTS)

clean:
	rm -rf $(TOOLS) *.o *.dSYM *~
	rm -f $(TESTS) *.gcno *.gcda

install: $(TOOLS)
	$(INSTALL_PROG) $(addsuffix $(EXE),$(TOOLS)) $(SBINDIR)/
