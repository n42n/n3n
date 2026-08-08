SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Hamish Coleman

# Build on Linux

As the Linux environment is a very standard posix system, it can simply use
the generic build instructions.

# Required minimum kernel API

This project intends to remain buildable with the oldest kernel that is still
receiving bugfixes and support from the kernel community.  In practice, this
means the the oldest Longterm release kernel - generally, any kernel older
than six years is not supported.

The intent is to control the support burden of the maintainers.

Most of the n3n code does not rely on kernel interfaces that are new or
changing, but this policy will influence the acceptance of patches for
supporting older kernels.

When some code is determined to not work on older kernel APIs, the preference
is for the entire feature to be disabled - with a message returned to the user
informing them of the lack of support before exiting with an errorcode when it
is detected that a unsupported feature has been requested.

# Building n3n packages

There are also some package build recipes included with the source.

- Debian: `make dpkg`
  (This detects missing packages and outputs an error. If so, try `make build-dep`)
- [RPM](../../packages/rpm)
- [OpenWRT](openwrt.md)
