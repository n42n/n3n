# Advanced Configuration


## Configuration Files

Read about [Configuration Files](ConfigurationFiles.md) as they might come in handy – especially, but not limited to, if edges or supernodes shall be run as a service (see below) or in case of bulk automated parameter generation for mass deployment.

## Running edge as a Service

edge can also be run as a service instead of cli:

1. Edit `/etc/n3n/edge.conf` with your custom options. See [a sample](edge.conf.sample).
2. Start the service: `sudo systemctl start edge`
3. Optionally enable edge start on boot: `sudo systemctl enable edge`

You can run multiple edge service instances by creating `/etc/n3n/instance1.conf` and
starting it with `sudo systemctl start edge@instance1`.


## Communities

You might be interested to learn some [details about Communities](Communities.md) and understand how to limit supernodes' services to only a specified set of communities.


## Federation

It is available a special community which provides interconnection between supernodes. Details about how it works and how you can use it are available in [Federation](Federation.md).

## Virtual Network Device Configuration

The [TAP Configuration Guide](TapConfiguration.md) contains hints on various settings that can be applied to the virtual network device, including IPv6 addresses as well as notes on MTU and on how to draw IP addresses from DHCP servers.


## Bridging and Routing the Traffic

Reaching a remote network or tunneling all the internet traffic via n3n are two common tasks which require a proper routing setup. n3n supports routing needs by temporarily modifying the routing table (`tools/n3n-route`). Details can be found in the [Routing document](Routing.md).

Also, n3n supports [Bridging](Bridging.md) of LANs, e.g. to connect otherwise un-connected LANs by an encrypted n3n tunnel on level 2.


## Traffic Restrictions

It is possible to drop or accept specific packet transmit over edge network
interface by rules. Rules can be specified in the config with the `filter.rule`
option - multiple times if needed. Details can be found in the [Traffic
Restrictions](TrafficRestrictions.md).
