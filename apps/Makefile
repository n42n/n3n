#
# Copyright (C) Hamish Coleman
#
# This makefile shows how to build applications using the libn3n library.
#
# The examples programs are intended to show how to use the libn3n as an
# embedded service within other software.
#

# If using this makefile outside of the n3n build environment, you will
# need to setup the correct include paths.
#
# eg:
# CFLAGS+=-I../include
# LDFLAGS+=-L../src
#
# CFLAGS+=-I../libs
# LDFLAGS+=-L../libs/connslot
# LDLIBS_LOCAL+=-lconnslot

APPS+=n3n-edge
APPS+=n3n-supernode

EXAMPLES+=example_edge_embed_quick_edge_init
EXAMPLES+=example_edge_embed
EXAMPLES+=example_sn_embed

LDLIBS+=-ln3n
LDLIBS+=$(LDLIBS_LOCAL)
LDLIBS+=$(LDLIBS_EXTRA)

all: $(APPS)

examples: $(EXAMPLES)

# TODO: a better path for this lib, as it would need to change to use this
# makefile outside the build environment
$(APPS) $(EXAMPLES): ../src/libn3n.a

.PHONY: install
install: $(addsuffix $(EXE),$(APPS))
	$(INSTALL) -d $(CONFIG_SBINDIR)
	$(INSTALL_PROG) n3n-supernode$(EXE) $(CONFIG_SBINDIR)/
	$(INSTALL_PROG) n3n-edge$(EXE) $(CONFIG_SBINDIR)/

# See comments in the topdir Makefile about how to generate coverage data.
# TODO: why are these apps detected with strange names by coverage?
gcov:
	gcov n3n-edge-n3n-edge n3n-supernode-n3n-supernode

clean:
	rm -f $(APPS) $(EXAMPLES)
