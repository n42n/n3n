#
# Change it according to your setup
#
# Prerequisite: apt-get install devscripts
#
#
N3N_HOME=$(PWD)/../..
N3N_BUILD=$(N3N_HOME)/packages/debian/n3n

include ${N3N_HOME}/config.mak

VERSION := $(shell ${N3N_HOME}/scripts/version.sh)

all: clean pkg

pkg:
	if test -e "${N3N_BUILD}"; then /bin/rm -fr ${N3N_BUILD}; fi
	make -C $(N3N_HOME)
	make -C $(N3N_HOME) DESTDIR=$(N3N_BUILD) install
	@/bin/rm -f ../n3n*.deb
	DEBEMAIL=builder@example.com dch -v ${VERSION} --no-auto-nmu Auto Build
	dpkg-buildpackage -rfakeroot -d -us -uc --host-type ${CONFIG_HOST}
	-dpkg-sig --sign builder -k D1EB60BE ../n3n_*deb
	@\rm -f ../n3n_*dsc ../n3n_*.gz ../n3n_*changes
	@/bin/mv ../n3n_*deb .
	@echo
	@echo "Package built."
	@/bin/ls n3n_*deb
	@echo "-------------------------------"
	-dpkg -I n3n_*deb
	-dpkg --contents n3n_*deb
	@echo "-------------------------------"

distclean:
	echo "dummy distclean"

install:
	echo "dummy install"

clean:
	rm -rf *~ *deb
