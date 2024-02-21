#
# Change it according to your setup
#
N3N_HOME=$(PWD)/../..

VERSION:=$(shell $(N3N_HOME)/scripts/version.sh |tr - _)
ARCH:=$(shell rpmbuild -E '%_arch')

RPM_PATH=$(HOME)/rpmbuild/RPMS/$(ARCH)/n3n-$(VERSION)-1.$(ARCH).rpm

# Older RPMs might not prompt for a passphrase
# (Centos8 was mentioned in the old autotooling)
#RPM_SIGN_CMD=rpm --addsign

# Note: this needs expect installed to work
RPM_SIGN_CMD=./rpm-sign.exp

all: clean pkg

pkg:
	rpmbuild --define='VERSION ${VERSION}' --define='TOPDIR ${N3N_HOME}' -bb ./n3n.spec
	-@$(RPM_SIGN_CMD) $(RPM_PATH)
	@echo ""
	@echo "Package contents:"
	@rpm -qpl $(RPM_PATH)
	@echo "The package is now available in $(RPM_PATH)"

distclean:
	echo "dummy distclean"

install:
	echo "dummy install"

clean:
	rm -rf *~ *rpm
