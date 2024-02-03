# n3n Frequently Asked Questions


## Releases

### Where can I find binaries for Windows?

We do not explicitly release Windows binaries, but the automated test workflow creates them. You can find the the most current binaries at the _Actions_ tab, at the _Testing_ workflow, select the newest run, scroll down to the _Artifacts_ sections where the _binaries_ file contains the Windows binaries in its `/x86_64-pc-mingw64/usr/sbin/` folder.

## Supernode


### I want to setup a supernode that only I can use. Perhaps even password protected?

Please think of the community-name as password and start the supernode with the `-c <community file>` parameter where the `<community file>` is the path to a simple text file containing a single line with the name of your secret community. It will be the only community allowed. Only edge nodes from that community can join (`-c <community name>` at the edge).

If you additionally want to prevent open transmission of your secret community
name via the network, **all** edge nodes should use
`community.header_encryption=true` config option for header encryption.

Also, please see the `community.list` file coming with n3n for advanced use of that file.

Beyond this access barrier you may want to use payload encryption `-A_` at the edges. Only the edges – not the supernode – are able to decipher the payload data. So, even if anyone would be able to break the access barrier to the supernode, the payload remains protected by the payload crypto, see [this document](Crypto.md) for details.


### Can I get a list of connected edge nodes and their community and source IP address from the supernode?

How to get this information is described in [the management
API](ManagementAPI.md) doc.

If enabled (by giving a `management.port` option), it can be simply seen with
any web browser:

eg.
- with `-Omanagement.port=5645`
- navigate to http://localhost:5645

### Is there support for multiple supernodes?

Yes, there is. Please [read](Federation.md) about how several supernodes can form a Federation to increase network resilience.


### Can a supernode listen on multiple ports?

The supernode itself can only listen on one port. However, your firewall might be able to map additional UDP ports to the supernode's regular port:

`sudo iptables -t nat -A PREROUTING -i <network interface name> -d <supernode's ip address> -p udp --dport <additional port number> -j REDIRECT --to-ports <regular supernode port number>`

This command line can be put down as additional `ExecStartPost=` line (without `sudo`) in the supernode's `.service` file which can hold several such lines if required.


### How to handle the error message "process_udp dropped a packet with seemingly encrypted header for which no matching community which uses encrypted headers was found"?

This error message means that the supernode is not able to identify a packet as unencrypted. It does check for a sane packet format. If it fails the header is assumed encrypted (thus, "_seemingly_ encrypted header") and the supernode tries all communities that would make a key (some have already been ruled out as they definitely are unenecrypted). If no matching community is found, the error occurs.

If all edges use the same `community.header_encryption` setting (all edges
either with it or without it) and restarting the supernode does not help, most
probably one of the components (an edge or the supernode) is outdated, i.e.
uses a different packet format – from time to time, a lot of changes happen to
the packet format in a very short period of time, especially in branches or
main for unreleased versions.

So, please make sure that all edges **and** the supernode have the exact same
built version.


## Edge


### How can I know if peer-to-peer connection has successfully been established?

How to get this information is described in [the management
API](ManagementAPI.md) doc.

`n3nctl edges`

Since the `n3nctl` tool needs python, it may not always be possible to use.
It is also possible to use a suitable `curl` command with the `--unix-socket`
option.

Alternatively, the edge can be started with a `management.port` config option
to specify a TCP port, and any web browser can be used to inspect the status.
(from localhost only)


### The edge repeatedly throws an "Authentication error. MAC or IP address already in use or not released yet by supernode" message. What is wrong?

The edge encountered n3n's protection against spoofing. It prevents that one edge's identity, MAC and IP address, can be impersonated by some other while the original one is still online, see some [details](Authentication.md). Mostly, there are two situations which can trigger this:

If you use a MAC or IP address that already is in use, just change those parameters.

If the edge prematurely has ended in a non-regular way, i.e. by killing it using `kill -9 ...` or `kill -SIGKILL ...`, it did not have a chance to un-register with the supernode which still counts the edge for online. A re-registration with the same MAC or IP address will be unsuccessful then. After two minutes or so the supernode will have forgotten. A new registration with the same parameters will be possible then. So, either wait two minutes or chose different parameters to restart with.

And, as a matter of principal, always end an edge by either pressing `CTRL` + `C` or by sending SIGTERM or SIGINT by using `kill -SIGTERM ...` or `kill -SIGINT ...`! A plain `kill ...` without `-9` will do, too. And finally, a `stop` command to the management port peacefully ends the edge as well.
