SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2020 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman

# Branches

The project _main_ branch is used for development work and reflects the code
that is expected to go into the next release - it is thus possible that it
has not been fully tested and may contain bugs or partially implemented
features.  If you wish to help with testing or to implement a new feature, you
are encouraged to compile from _main_.  Feedback in the _issues_ tracker is
appreciated.

# Tags
 
Once a release is stable, it will be tagged - and if a bug fix needs to be
backported to a stable release a branch will be created for the patch releases
containing these backported patches.

# Submodules

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
 
If you will be using these features, the simplest thing to do is the very first
time after cloning the n3n git repo, you should run this command in the n3n
directory to fetch the submodules:
 
```bash
git submodule update --init --recursive
```

# Github Actions

The CI system that is built on top of github actions also provides a set of
fully automated steps for each of those jobs.

A good starting point would be the [tests.yml](../../.github/workflows/tests.yml)
