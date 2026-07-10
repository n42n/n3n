SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2020 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman

# Quick Start Guide to creating a config file

The fastest and easiest way to setup your n3n edge is by creating a config
file.

## Example edge config

Place the following config file into `myfirstnetwork.conf` in the correct
directory for your OS (See the Quick Start page for your OS for this
directory location)

```
[community]
name=mynetwork
key=mypassword
supernode=supernode.n3n.dev:7654
```

**IMPORTANT:** It is strongly advised to choose a custom community name (the
`community.name` option) and a secret encryption key (the `community.key`
option) in order to prevent unexpected users from connecting to your computer.

The n3n project runs the public supernode in the above config for testing
purposes - is it suggested that you setup your own
[supernode](../configure/Supernode.md) for longer term use.
