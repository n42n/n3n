SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2020 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman

# Build on macOS
 
The macOS build essentially can use the generic build instructions,
but first needs a couple of other packages installed:
 
```bash
brew install automake
```
 
Then install support for TUN/TAP interfaces:
 
```bash
brew tap homebrew/cask
brew cask install tuntap
```
 
If you are on a modern version of macOS (i.e. Catalina), the commands above
will ask you to enable the TUN/TAP kernel extension in System Preferences →
Security & Privacy → General.
 
For more information refer to vendor documentation or the [Apple Technical Note](https://developer.apple.com/library/content/technotes/tn2459/_index.html).
 
Note that on the newest MacOS versions and on Apple Silicon, there may be
increasing security restrictions in the OS that make installing the TUN/TAP
kernel extension difficult.  Alternative software implementations to avoid
these difficulties are being discussed for future n3n versions.
