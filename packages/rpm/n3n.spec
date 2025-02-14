Summary: n3n peer-to-peer VPN
Name: n3n
Version: %{VERSION}
Release: 1
License: GPL
Group: Networking/Utilities
URL: http://github.com/n42n
Source: n3n-%{version}.tgz
Packager: Hamish Coleman <hamish@zot.org>
# Temporary location where the RPM will be built
BuildRoot:  %{_tmppath}/%{name}-%{version}-root
Requires: libzstd

# Make sure .build-id is not part of the package
%define _build_id_links none

%description
n3n peer-to-peer VPN

%prep

# This is expecting to build from the checked-out source, so there is no prep

%build

cd %TOPDIR
./autogen.sh
./configure --prefix=/usr
make

%install

cd %TOPDIR
make install DESTDIR=$RPM_BUILD_ROOT
chmod u+w $RPM_BUILD_ROOT/usr/sbin/*

#find $RPM_BUILD_ROOT -name ".git" | xargs /bin/rm -rf
#find $RPM_BUILD_ROOT -name ".svn" | xargs /bin/rm -rf
#find $RPM_BUILD_ROOT -name "*~"   | xargs /bin/rm -f

%clean
# Clean out our build directory
rm -fr $RPM_BUILD_ROOT

%files
/usr/bin/n3nctl
/usr/lib/systemd/system/n3n-edge.service
/usr/lib/systemd/system/n3n-edge@.service
/usr/lib/systemd/system/n3n-supernode.service
/usr/sbin/n3n-edge
/usr/sbin/n3n-supernode
/usr/share/doc/n3n/Advanced.md
/usr/share/doc/n3n/Authentication.md
/usr/share/doc/n3n/Bridging.md
/usr/share/doc/n3n/BuildConfig.md
/usr/share/doc/n3n/Building.md
/usr/share/doc/n3n/Communities.md
/usr/share/doc/n3n/ConfigurationFiles.md
/usr/share/doc/n3n/Crypto.md
/usr/share/doc/n3n/Faq.md
/usr/share/doc/n3n/Federation.md
/usr/share/doc/n3n/Hacking.md
/usr/share/doc/n3n/ManagementAPI.md
/usr/share/doc/n3n/ReleaseProcess.md
/usr/share/doc/n3n/Routing.md
/usr/share/doc/n3n/Scratchpad.md
/usr/share/doc/n3n/Scripts.md
/usr/share/doc/n3n/Security.md
/usr/share/doc/n3n/Supernode.md
/usr/share/doc/n3n/TapConfiguration.md
/usr/share/doc/n3n/Tools.md
/usr/share/doc/n3n/TrafficRestrictions.md
/usr/share/doc/n3n/community.list.sample
/usr/share/doc/n3n/edge.conf.sample
/usr/share/doc/n3n/supernode.conf.sample
/usr/share/man/man7/n3n.7.gz
/usr/share/man/man8/n3n-edge.8.gz
/usr/share/man/man8/n3n-supernode.8.gz

# Set the default attributes of all of the files specified to have an
# owner and group of root and to inherit the permissions of the file
# itself.
%defattr(-, root, root)

%changelog
* Sun Oct 31 2021 Hamish Coleman <hamish@zot.org> 3.1.0
- Last stable release

# Execution order:
# install:    pre -> (copy) -> post
# upgrade:    pre -> (copy) -> post -> preun (old) -> (delete old) -> postun (old)
# un-install:                          preun       -> (delete)     -> postun

%pre

if ! grep -q n3n /etc/group; then
  echo 'Creating n3n group'
  /usr/sbin/groupadd -r n3n
fi

if ! /usr/bin/id -u n3n > /dev/null 2>&1; then
  echo 'Creating n3n user'
  /usr/sbin/useradd -M -N -g n3n -r -s /bin/false n3n
fi

%post
if [ -f /bin/systemctl ]; then
  if [ ! -f /.dockerenv ]; then
      /bin/systemctl daemon-reload
      # NOTE: do not enable any services during first installation
  fi
fi

%preun
if [ -f /bin/systemctl ]; then
  if [ ! -f /.dockerenv ]; then
      # possibly remove the installed services
      %systemd_preun supernode.service n3n-edge.service 'edge@*.service'
  fi
fi

%postun
if [ -f /bin/systemctl ]; then
  if [ ! -f /.dockerenv ]; then
      # possibly restart the running services
      %systemd_postun_with_restart n3n-supernode.service n3n-edge.service 'n3n-edge@*.service'
  fi
fi
