Copyright (C) 2023 Hamish Coleman and other contributors
SPDX-License-Identifier: GPL-3.0-only

This document describes the process for compiling n3n in several different
scenarios.

There are some configuration options available during the build process,
which are documented in the [Build time Configuration](BuildConfig.md) page.

Also of use are the steps used for the automated Continuous Integration
process, which can be found in the [Github actions config file](../.github/workflows/tests.yml)

# Git submodules

If you are compiling with the UPnP features enabled, it is possible that your
operating system or your build system do not include binaries for the required
libraries.

Using these libraries can cause issues with some build systems, so be
aware that not all combinations are supportable.

To make this scenario simpler, the required source code has been added
to this repository as git `submodules` which require one extra step to
complete their checkout.

This is only required if you have run configure with the options to enable
either of the UPnP libraries and are also building for a system that does not
have a feature to provide these libraries with a binary package.

This is most often the case on Windows, however the build system doesnt
currently auto-detect this and enable the right features to include these
libraries.  Additionally, upstream changes are needed to libpmp to allow
it to build properly with GCC on Windows at all.  These are issues that
should be fixed in a future release.

So the very first time after cloning the n3n git repo, you should run
this command in the n3n directory to fetch the submodules:

```bash
git submodule update --init --recursive
```

# Build on macOS

In order to use n3n on macOS, you first need to install support for TUN/TAP interfaces:

```bash
brew tap homebrew/cask
brew cask install tuntap
```

If you are on a modern version of macOS (i.e. Catalina), the commands above will ask you to enable the TUN/TAP kernel extension in System Preferences → Security & Privacy → General.

For more information refer to vendor documentation or the [Apple Technical Note](https://developer.apple.com/library/content/technotes/tn2459/_index.html).

Note that on the newest MacOS versions and on Apple Silicon, there may be
increasing security restrictions in the OS that make installing the TUN/TAP
kernel extension difficult.  Alternative software implementations to avoid
these difficulties are being discussed for future n3n versions.

# Build on Windows

The following document one possible windows compile recipe.  The reason
a MinGW build process is used is it is more friendly to open source
development.

## MinGW

These steps were tested on a fresh install of Windows 10 Pro with all patches
applied as of 2021-09-29.

- Install Chocolatey (Following instructions on https://chocolatey.org/install)
- from an admin cmd prompt
    - `choco install git mingw make`
- Once the git package is installed, you will have a new start menu item
  called "Git Bash".  All the remaining commands must be run from inside the
  shell started by that menu item:
    - `git clone $THIS_REPO`
    - `cd n3n`
    - `./scripts/hack_fakeautoconf.sh`
    - `make`
    - `make test`

Due to limitations in the Windows environment, the normal autotools steps have
been emulated by the `hack_fakeautoconf`

Note that building with the UPnP libraries on Windows requires a bit of manual
work at the moment.

## Run on Windows

In order to run n3n on Windows, you will need the following:

- The TAP drivers should be installed into the system. They can be installed from
  http://build.openvpn.net/downloads/releases, search for "tap-windows".

- If OpenSSL has been linked dynamically, the corresponding `.dll` file should be available
  onto the target computer.

The `edge.exe` program reads the `%USERPROFILE%\n3n\edge.conf` file if no
session name option is provided.

The `supernode.exe` program reads the `%UERPROFILE%\n3n\supernode.conf` file if
no session name option is provided.

Example [edge.conf](edge.conf.sample)
and [supernode.conf](supernode.conf.sample) are available.

See `edge.exe --help` and `supernode.exe --help` for a full list of supported options.

# Cross compiling on Linux

## Using the Makefiles and Autoconf

The Makefiles are all setup to allow cross compiling of this code.  You
will need to have the cross compiler, binutils and any additional libraries
desired installed for the target architecture.  Then you can run the `./configure`
with the appropriate `--host` option.

If compiling on Debian or Ubuntu, this can be as simple as the following example:

```
HOST_TRIPLET=arm-linux-gnueabi
sudo apt-get install binutils-$HOST_TRIPLET gcc-$HOST_TRIPLET
./autogen.sh
./configure --host $HOST_TRIPLET
make
```

A good starting point to determine the host triplet for your destination
platform can be found by copying the `./scripts/config.guess` script to it and
running it on the destination.

This is not a good way to produce binaries for embedded environments (like OpenWRT)
as they will often use a different libc environment.

# N2N Packages

There are also some example package build recipes included with the source.

- Debian: `make dpkg`
- [RPM](../packages/rpm)
- [OpenWRT](../packages/openwrt/README.md)
