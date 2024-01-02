#
# Copyright (C) 2023 Hamish Coleman
#
# This makefile shows how to build applications using the libn3n library.
#
# The examples programs are intended to show how to use the libn3n as an
# embedded service within other software.
#

# These two vars should be set to the location of the n3n compiled setup
# (EG: With a system installed libn3n, these would point to that installation)
LIBDIR?=..
INCDIR?=../include

APPS+=edge
APPS+=supernode

EXAMPLES+=example_edge_embed_quick_edge_init
EXAMPLES+=example_edge_embed
EXAMPLES+=example_sn_embed

CFLAGS+=-I$(INCDIR)
LDFLAGS+=-L$(LIBDIR)
LDLIBS+=-ln3n
LDLIBS+=$(LDLIBS_EXTRA)

all: $(APPS) $(EXAMPLES)

$(APPS) $(EXAMPLES): ../libn3n.a

.PHONY: install
install: $(addsuffix $(EXE),$(APPS))
	$(INSTALL_PROG) supernode$(EXE) $(SBINDIR)/
	$(INSTALL_PROG) edge$(EXE) $(SBINDIR)/

# See comments in the topdir Makefile about how to generate coverage data.
gcov:
	gcov $(APPS)

clean:
	rm -f $(APPS) $(EXAMPLES)
