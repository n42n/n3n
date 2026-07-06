SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2020 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman

# Debian, Ubuntu or similar

These instructions will work on Debian, Ubuntu or similar `dpkg`-based
systems.

For these systems, use the `/etc/n3n/` directory as the location for any
config files.

## Modern systems

For Debian 11(bullseye) or newer, and Ubuntu 23.10 or newer.

```
wget https://pkg.n3n.dev/stable/signing_key.asc
sudo cp signing_key.asc /etc/apt/keyrings/n3n_stable.asc
sudo tee /etc/apt/sources.list.d/n3n.sources <<EOF
Types: deb
URIs: https://pkg.n3n.dev/apt
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/n3n_stable.asc
EOF

sudo apt update
sudo apt install n3n
```

## Older systems

- Download the [latest stable
  release](https://github.com/n42n/n3n/releases/latest)
  deb package file matching your computer architecture (e.g.: `amd64`).
- Install the package (eg: `apt install ./n3n_3.3.4-1_amd64.deb`)

## After installing

- Ensure you have the example config file shown in the [Config quick
  start](Config.md)
- Start the service: `sudo systemctl start n3n-edge@myfirstnetwork`
- Use `n3nctl` (the n3n management CLI) to inspect the running daemon:
  - Check the connection: `sudo n3nctl -s myfirstnetwork supernodes`
  - List other nodes found: `sudo n3nctl -s myfirstnetwork edges`
