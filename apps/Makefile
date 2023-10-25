#
# Copyright (C) 2023 Hamish Coleman
#
# These examples are intended to show how to use the libn3n as an embedded
# service within other software.
#

APPS+=edge
APPS+=supernode

EXAMPLES+=example_edge_embed_quick_edge_init
EXAMPLES+=example_edge_embed
EXAMPLES+=example_sn_embed

all: $(APPS) $(EXAMPLES)

CFLAGS+=-I../include
LDFLAGS+=-L../

$(APPS) $(EXAMPLES): ../libn3n.a

clean:
	rm -f $(APPS) $(EXAMPLES)
