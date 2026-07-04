SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2020 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman

# Cross compiling on Linux
 
## Using the Makefiles and Autoconf
 
The Makefiles are all setup to allow cross compiling of this code.  You
will need to have the cross compiler, binutils and any additional libraries
desired installed for the target architecture.  Then you can run the
`./configure` with the appropriate `--host` option.
 
If compiling on Debian or Ubuntu, this can be as simple as the following
example:
 
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
 
This is not a good way to produce binaries for embedded environments (like
OpenWRT) as they will often use a different libc environment.
