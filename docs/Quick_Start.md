# Quick Start

There are two main steps to quickly get started:
- Create a config file
- Install the binaries

## Create a config file

**IMPORTANT:** It is strongly advised to choose a custom community name (the
`community.name` option) and a secret encryption key (the `community.key`
option) in order to prevent other users from connecting to your computer.

The n3n project runs a public supernode for testing purposes - is it suggested
that you setup your own [supernode](../doc/Supernode.md) for longer term use.

### Debian, Ubuntu or similar

- Create the config file `/etc/n3n/mynetwork.conf` containing:
  ```
  [community]
  name=mynetwork
  key=mypassword
  supernode=supernode.n3n.dev
  ```


## Install the binaries

### Debian, Ubuntu or similar

For Debian, Ubuntu or similar dpkg based systems:

- Download the [latest stable release](https://github.com/n42n/n3n/releases/latest)
  deb package file matching your computer architecture (eg: `amd64`).

- Install the package (eg: `apt install ./n3n_3.3.4-1_amd64.deb`)

- Start the service: `sudo systemctl start n3n-edge@mynetwork`

- Use `n3nctl` (the n3n management CLI) to inspect the running daemon:

  - Check the connection: `sudo n3nctl -s mynetwork supernodes`

  - List other nodes found: `sudo n3nctl -s mynetwork edges`

