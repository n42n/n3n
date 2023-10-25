#
# This is not a standalone makefile, it must be called from the toplevel
# makefile to inherit the correct environment

DEBUG?=-g3

HEADERS=$(wildcard include/*.h)
CFLAGS+=-I../include

CFLAGS+=$(DEBUG)
LDFLAGS+=-L..

N2N_LIB=../libn3n.a

TOOLS+=n3n-benchmark$(EXE)
TOOLS+=n3n-keygen$(EXE)
TOOLS+=n3n-route$(EXE)
TOOLS+=n3n-portfwd$(EXE)
TOOLS+=n3n-decode$(EXE)

TESTS=tests-compress$(EXE)
TESTS+=tests-elliptic$(EXE)
TESTS+=tests-hashing$(EXE)
TESTS+=tests-transform$(EXE)
TESTS+=tests-wire$(EXE)
TESTS+=tests-auth$(EXE)

.PHONY: all clean install
all: $(TOOLS) $(TESTS)

n3n-benchmark.o: $(N2N_LIB) $(HEADERS) ../config.mak
n3n-keygen.o: $(N2N_LIB) $(HEADERS) ../config.mak
n3n-route.o: $(N2N_LIB) $(HEADERS) ../config.mak
n3n-portfwd.o: $(N2N_LIB) $(HEADERS) ../config.mak
n3n-decode.o: $(N2N_LIB) $(HEADERS) ../config.mak

ifneq (,$(findstring mingw,$(CONFIG_HOST_OS)))
# HACK for windows.
n3n-benchmark.exe: n3n-benchmark
n3n-keygen.exe: n3n-keygen
n3n-route.exe: n3n-route
n3n-portfwd.exe: n3n-portfwd
n3n-decode.exe: n3n-decode
tests-compress.exe: tests-compress
tests-elliptic.exe: tests-elliptic
tests-hashing.exe: tests-hashing
tests-transform.exe: tests-transform
tests-wire.exe: tests-wire
tests-auth.exe: tests-auth
endif

# See comments in the topdir Makefile about how to generate coverage
# data.
gcov:
	gcov $(TOOLS) $(TESTS)

clean:
	rm -rf $(TOOLS) *.o *.dSYM *~
	rm -f $(TESTS) *.gcno *.gcda

install: $(TOOLS)
	$(INSTALL_PROG) $(TOOLS) $(SBINDIR)/
