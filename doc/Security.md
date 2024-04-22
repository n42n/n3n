# Security Considerations

When payload encryption is enabled (provide a key using `community.key`), the
supernode will not be able to decrypt the traffic exchanged between two edge
nodes but it will know that edge A is talking with edge B.

There are multiple encryption options to choose from. Please have a look at
[Crypto description](Crypto.md) for a quick comparison chart to help make a
choice. n3n edge nodes use AES encryption by default. Other ciphers can be
chosen using the `community.cipher` option.

A benchmark of the encryption methods is available when compiled from source
with `tools/n3n-benchmark`.

The header which contains some metadata like the virtual MAC address of the
edge nodes, their IP address, their real hostname and the community name
optionally can be encrypted applying the `community.header_encryption=true`
option to the edges.


