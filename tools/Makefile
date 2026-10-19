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
TESTS+=tests-mss

.PHONY: all clean install
all: $(TOOLS) $(TESTS)

optional: $(TOOLS_OPTIONAL)

# TODO: a better path for this lib, as it would need to change to use this
# makefile outside the build environment
$(TOOLS) $(TOOLS_OPTIONAL) $(TESTS): ../src/libn3n.a

# Deletes the default rule, forcing tools to be built with CC and then LD
%: %.c

%.o: %.c
	@echo "  CC      $@ $(CFLAGS_$<)"
	@$(CC) $(CFLAGS) $(CFLAGS_$<) $(CPPFLAGS) -c -o $@ $< -MT$@ -MT$(<:.c=.d)

# TODO:
# make the output quieter
# - add in a matching LD ruleset for %: %.o
# - remember the pattern established in root Makefile to echo what "LD" means

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
