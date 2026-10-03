#
# This is not a standalone makefile, it must be called from the toplevel
# makefile to inherit the correct environment

LDLIBS+=-ln3n
LDLIBS+=$(LDLIBS_LOCAL)
LDLIBS+=$(LDLIBS_EXTRA)

TOOLS_OPTIONAL+=n3n-benchmark

TOOLS+=n3n-route
TOOLS+=n3n-portfwd
TOOLS+=n3n-decode
TOOLS+=crypto_helper

TESTS=tests-compress
TESTS+=tests-elliptic
TESTS+=tests-transform
TESTS+=tests-wire
TESTS+=tests-auth

.PHONY: all clean install
all: $(TOOLS) $(TESTS)

optional: $(TOOLS_OPTIONAL)

# As in apps/Makefile: without this, a changed library does not relink
# the tools, and "make test" runs the old test binaries
$(TOOLS) $(TOOLS_OPTIONAL) $(TESTS): ../src/libn3n.a

%: %.c
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

# See comments in the topdir Makefile about how to generate coverage
# data.  Compiled and linked with the library in one step, gcc names the
# notes of x.c x-x.gcno: take whichever notes there are.
gcov:
	gcov $(basename $(wildcard *.gcno))

clean:
	rm -rf $(TOOLS) *.o *.dSYM *~
	rm -f $(TESTS) *.gcno *.gcda

install: $(TOOLS)
	$(INSTALL) -d $(CONFIG_SBINDIR)
	$(INSTALL_PROG) $(addsuffix $(EXE),$(TOOLS)) $(CONFIG_SBINDIR)/
