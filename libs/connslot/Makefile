#
# Copyright (C) Hamish Coleman
# SPDX-License-Identifier: GPL-2.0-only
#

all: libconnslot.a

CFLAGS+=-Wall -Wextra -Werror -g

COVERAGEDIR?=coverage
ifdef COVERAGE
CFLAGS+=-fprofile-arcs
CFLAGS+=-ftest-coverage
LDFLAGS+=--coverage
endif

ifneq ($(NOANALYZER),1)
CFLAGS+=-fanalyzer
endif

ifdef SANITISE
CFLAGS+=-fsanitize=leak
LDFLAGS+=-fsanitize=leak
endif

LINT_CCODE+=strbuf.c strbuf.h strbuf-tests.c
LINT_CCODE+=connslot.c connslot.h connslot-tests.c
LINT_CCODE+=httpd-test.c
LINT_CCODE+=jsonrpc.c jsonrpc.h

BUILD_DEP+=uncrustify
BUILD_DEP+=gcovr

CLEAN+=strbuf-tests
CLEAN+=connslot-tests
CLEAN+=*.o

strbuf.o: strbuf.h
strbuf-tests: strbuf.o
connslot.o: connslot.h
connslot-tests: connslot.o strbuf.o
httpd-test: connslot.o strbuf.o jsonrpc.o

libconnslot.a: strbuf.o connslot.o
	$(AR) rcs $@ $^
CLEAN+=libconnslot.a

.PHONY: build-dep
build-dep:
	sudo apt-get -y install $(BUILD_DEP)

.PHONY: lint
lint: lint.ccode

.PHONY: lint.ccode
lint.ccode:
	uncrustify -c uncrustify.cfg --check ${LINT_CCODE}

.PHONY: test
test: test.strbuf
test: test.connslot

.PHONY: test.strbuf
test.strbuf: strbuf-tests
	./strbuf-tests

.PHONY: test.connslot
test.connslot: connslot-tests
	./connslot-tests

.PHONY: cover
cover:
	mkdir -p $(COVERAGEDIR)
	gcovr -s --html --html-details --output=$(COVERAGEDIR)/index.html

.PHONY: clean
clean:
	rm -f ${CLEAN}
