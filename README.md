
# n3n

n3n is a light VPN software which makes it easy to create virtual networks
bypassing intermediate firewalls.

In order to start using n3n, two elements are required:

- A _supernode_: it allows edge nodes to announce and discover other nodes. It
  must have a port publicly accessible on internet.
- _edge_ nodes: the nodes which will be a part of the virtual networks

A virtual network shared between multiple edge nodes in n3n is called a
_community_. A single supernode can relay multiple communities and a single
computer can be part of multiple communities at the same time. An encryption
key can be used by the edge nodes to encrypt the packets within their
community.

n3n tries to establish a direct peer-to-peer connection via udp between the
edge nodes when possible. When this is not possible (usually due to special NAT
devices), the supernode is also used to relay the packets.

n3n was originally based on an older n2n project and hopes to keep protocol
compatiblilty with that.

## License

- Any new self-contained tools or modules are licensed GPL-2.0-only.
- Existing code is licensed GPL-3-only.
- There are multiple distinct copyright holders throughout the codebase.
- There is no Contributor Licence Agreement and thus there is no single body
  that can take ownership of the code and/or change the licensing.

## Quick Setup

Up-to-date binaries and packages for most distributions are available as
part of the [latest stable release](https://github.com/n42n/n3n/releases/latest).

(Since the n3n is protocol compatible with the older n2n, you might be tempted
to try and install a package provided by your distribution.  At the least
Debian has a package called `n2n`, however it is based on the antique 1.2
version from 2008 and that has not been compatible with n2n for many years, and
thus is also not able to interoperate with n3n.)

On host1 run:

```sh
$ sudo edge start \
    -c mynetwork \
    -k mysecretpass \
    -a 192.168.100.1 \
    -l supernode.ntop.org:7777
```

On host2 run:

```sh
$ sudo edge start \
    -c mynetwork \
    -k mysecretpass \
    -a 192.168.100.2 \
    -l supernode.ntop.org:7777
```

Now the two hosts can ping each other.  For a longer-term setup, we suggest
you use a config file with the settings.

**IMPORTANT** It is strongly advised to choose a custom community name (the
`community.name` option) and a secret encryption key (the `community.key`
option) in order to prevent other users from connecting to your computer. For
the privacy of your data sent and to reduce the server load of
`supernode.ntop.org`, it is also suggested to set up a custom supernode as
explained below.


## Setting up a Custom Supernode

You can create your own infrastructure by setting up a supernode on a public
server (e.g. a VPS). You just need to open a single port (1234 in the example
below) on your firewall (usually `iptables`).

1. Install the n3n package
2. Edit `/etc/n3n/supernode.conf` and add the following:
   ```
   [connection]
   bind=1234
   ```
3. Start the supernode service with `sudo systemctl start supernode`
4. Optionally enable supernode start on boot: `sudo systemctl enable supernode`

Now the supernode service should be up and running on port 1234. On your edge
nodes you can now specify `-l your_supernode_ip:1234` to use it. All the edge
nodes must use the same supernode (or be part of the same
[supernode federation](doc/Federation.md))


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
