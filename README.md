
# n3n

n3n is a lightweight Peer-to-Peer VPN that creates virtual networks.

In order to start using n3n, two elements are required:

- A _supernode_: it allows edge nodes to announce and discover other nodes. It
  must have a port publicly accessible on internet.
- _edge_ nodes: the nodes which will be a part of the virtual networks

A virtual network shared between multiple edge nodes in n3n is called a
_community_. A single supernode can relay multiple communities and a single
computer can be part of multiple communities at the same time (by running
multiple _edge_ daemons). An encryption key can be used by the edge nodes to
encrypt the packets within their community.

n3n tries to establish a direct peer-to-peer connection via udp between the
edge nodes when possible. When this is not possible (usually due to special NAT
devices), the supernode is also used to relay the packets.

n3n was originally based on an older n2n project and hopes to keep protocol
compatiblilty with that.

Note that some distributions have very old versions of n2n packaged that are
incompatible with the protocol used by n3n.  At the least, Debian has a n2n
version 1.3.1 which uses a protocol from 2008 and has not been compatible with
the stable releases of n2n for many years - thus will definitely not
interoperate with n3n)

## License

- Any new self-contained tools or modules are licensed GPL-2.0-only.
- Existing code is licensed GPL-3-only.
- There are multiple distinct copyright holders throughout the codebase.
- There is no Contributor Licence Agreement and thus there is no single body
  that can take ownership of the code and/or change the licensing.

## Quick Start

For Debian, Ubuntu or similar dpkg based systems:

- Download the package from the [latest stable release](https://github.com/n42n/n3n/releases/latest).

- Install the package

- Create a config file - `/etc/n3n/mynetwork.conf` containing
  ```
  [community]
  name=mynetwork
  key=mypassword
  supernode=supernode.ntop.org:7777
  ```

- Start the service: `sudo systemctl start n3n-edge@mynetwork`

- Check the connection: `sudo n3nctl -s mynetwork supernodes`

- List other nodes found: `sudo n3nctl -s mynetwork edges`

**IMPORTANT:** It is strongly advised to choose a custom community name (the
`community.name` option) and a secret encryption key (the `community.key`
option) in order to prevent other users from connecting to your computer.

It is also suggested that you setup your own [supernode](doc/Supernode.md)

# See Also

- [Build from Source](doc/Building.md) document.
- [Security Considerations](doc/Security.md) document.
- [Advanced Configuration](doc/Advanced.md) document.
- Answers to [frequently asked questions](doc/Faq.md) (FAQ).
- Details about the internals in the [Hacking guide](doc/Hacking.md).

## Contribution

You can contribute to n3n in various ways:

- Update an [open issue](https://github.com/n42n/n3n/issues) or create a new
  one with detailed information
- Propose new features
- Improve the documentation
- Provide pull requests with enhancements


---

(C) 2007-22 - ntop.org and contributors
Copyright (C) 2023-25 Hamish Coleman
