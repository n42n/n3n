SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2020 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman

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
 
- The TAP drivers should be installed into the system. They can be installed
  from
  http://build.openvpn.net/downloads/releases, search for "tap-windows".
 
- If OpenSSL has been linked dynamically, the corresponding `.dll` file should
  be available onto the target computer.
 
The `edge.exe` program reads the `%USERPROFILE%\n3n\edge.conf` file if no
session name option is provided.
 
The `supernode.exe` program reads the `%USERPROFILE%\n3n\supernode.conf` file
if no session name option is provided.
 
Example [edge.conf](../edge.conf.sample)
and [supernode.conf](../supernode.conf.sample) are available.
 
See `edge.exe --help` and `supernode.exe --help` for a full list of supported
options.
