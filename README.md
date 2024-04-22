
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

## Manual Compilation

On Linux, compilation from source is straight forward:

```sh
./autogen.sh
./configure
make

# optionally install
make install
```

For compiling under Windows or MacOS, enabling various optimizations and
generally other options available to build, please check the [Building
documentation](doc/Building.md)

The project _main_ branch is used for development work and reflects the code
that is expected to go into the next release - it is thus possible that it
has not been fully tested and may contain bugs or partially implemented
features.  If you wish to help with testing or to implement a new feature, you
are encouraged to compile from _main_.  Feedback in the _issues_ tracker is
appreciated.

Once a release is stable, it will be tagged - and if a bug fix needs to be
backported to a stable release a branch will be created for the patch releases
containing these backported patches.


## Security Considerations

When payload encryption is enabled (provide a key using `community.key`), the
supernode will not be able to decrypt the traffic exchanged between two edge
nodes but it will know that edge A is talking with edge B.

There are multiple encryption options to choose from. Please have a look at
[Crypto description](doc/Crypto.md) for a quick comparison chart to help make a
choice. n3n edge nodes use AES encryption by default. Other ciphers can be
chosen using the `community.cipher` option.

A benchmark of the encryption methods is available when compiled from source
with `tools/n3n-benchmark`.

The header which contains some metadata like the virtual MAC address of the
edge nodes, their IP address, their real hostname and the community name
optionally can be encrypted applying the `community.header_encryption=true`
option to the edges.


## Advanced Configuration

More information about communities, support for multiple supernodes, routing,
traffic restrictions and on how to run an edge as a service is available in the
[more detailed documentation](doc/Advanced.md).


## Contribution

You can contribute to n3n in various ways:

- Update an [open issue](https://github.com/n42n/n3n/issues) or create a new
  one with detailed information
- Propose new features
- Improve the documentation
- Provide pull requests with enhancements

For details about the internals of n3n check out the [Hacking
guide](doc/Hacking.md).


## Further Readings and Related Projects

Answers to frequently asked questions can be found in our [FAQ
document](doc/Faq.md).

---

(C) 2007-22 - ntop.org and contributors
Copyright (C) 2023-24 Hamish Coleman
