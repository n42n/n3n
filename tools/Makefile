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

# TODO: a better path for this lib, as it would need to change to use this
# makefile outside the build environment
$(TOOLS) $(TOOLS_OPTIONAL) $(TESTS): ../src/libn3n.a

# Compiled to an object, then linked: the coverage notes of x.c are x.gcno
# then, which "gcov x" looks for (compiled and linked in one step, gcc
# names them x-x.gcno).  Make's own rule from x.c to x is cancelled, so
# that this one is taken.
%: %.c

%.o: %.c
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

%: %.o
	@echo "  LINK    $@"
	@$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

# kept, not removed as intermediate files: "make clean" does that
.SECONDARY: $(addsuffix .o,$(TOOLS) $(TOOLS_OPTIONAL) $(TESTS))

# See comments in the topdir Makefile about how to generate coverage
# data.
gcov:
	gcov $(TOOLS) $(TESTS)

clean:
	rm -rf $(TOOLS) *.o *.dSYM *~
	rm -f $(TESTS) *.gcno *.gcda

install: $(TOOLS)
	$(INSTALL) -d $(CONFIG_SBINDIR)
	$(INSTALL_PROG) $(addsuffix $(EXE),$(TOOLS)) $(CONFIG_SBINDIR)/
