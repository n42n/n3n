SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2020 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman

# Build from Source

If you wish to contribute to the development of the n3n project, you will
almost certainly need to build from source.  You may also just wish to compile
for a new OS or Architecture, customise for your needs or change some build
time settings.

# Generic build instructions

On a system with standard posix tools and development libraries (like Linux),
the compilation from source is straight forward:

```sh
./autogen.sh
./configure
make

# optionally install
make install
```

# Further details

The following pages provide more in-depth information:

- [Overview](Overview.md)
- [Build time Configuration](BuildConfig.md)
- [Build on macOS](macos.md)
- [Build on BSD](bsd.md)
- [Build on Windows](windows.md)
- [Cross compile on Linux](linux_crosscompile.md)

# Building n3n packages

There are also some package build recipes included with the source.
 
- Debian: `make dpkg`
  (This detects missing packages and outputs an error. If so, try `make build-dep`)
- [RPM](../../packages/rpm)
- [OpenWRT](openwrt.md)
