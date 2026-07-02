SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2020 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman

# Debian, Ubuntu or similar

These instructions will work on Debian, Ubuntu or similar dpkg based systems.

For these, use the `/etc/n3n/` directory as the location for any config files.

- Download the [latest stable release](https://github.com/n42n/n3n/releases/latest)
  deb package file matching your computer architecture (eg: `amd64`).

- Install the package (eg: `apt install ./n3n_3.3.4-1_amd64.deb`)

- Start the service: `sudo systemctl start n3n-edge@myfirstnetwork`

- Use `n3nctl` (the n3n management CLI) to inspect the running daemon:

  - Check the connection: `sudo n3nctl -s myfirstnetwork supernodes`

  - List other nodes found: `sudo n3nctl -s myfirstnetwork edges`
