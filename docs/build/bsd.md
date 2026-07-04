SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2020 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman

# Build on BSD
 
## FreeBSD
 
This essentially is using the generic build instructions, with a
couple of required packages installed:
 
```bash
sudo pkg install -y \
  autoconf \
  automake \
  git-tiny \
  gmake \
  python3 \
  jq \
  bash
./autogen.sh
./configure CC=clang
gmake all
```
 
## OpenBSD
 
Again, this is basically the generic build instructions, with some extra
OS packages:
 
```bash
sudo pkg_add \
  autoconf-2.71 \
  automake-1.16.5 \
  git \
  gmake \
  python3 \
  jq \
  bash
AUTOCONF_VERSION=2.71 AUTOMAKE_VERSION=1.16 ./autogen.sh
./configure CC=clang
gmake all
```
 

