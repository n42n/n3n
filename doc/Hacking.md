# Hacking

--------

This program and document is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not see see [<http://www.gnu.org/licenses/>](http://www.gnu.org/licenses/)

--------

This file describes the internals of n3n. Read this before starting to modify
the code. Because coding examples may be present in this document it is licensed
under the GPL rather than FDL.

## Symmetric NAT

Symmetric NAT is a form of firewall NAT in which an UDP packets are only passed
back to an inside host socket when the return packets originate from the outside
socket to which the initiating UDP packets were sent. This means that when an
inside host sends UDP to some outside socket; other hosts cannot piggyback on
this opening in the firewall to send data to the inside host.

For example, an asymmetric NAT would keep the mapping:

   `<UDP,ExtPort> -> <IntIP, IntPort>`

and would redirect all the packets on external port ExtPort to the internal host
regardless of the remote IP.

Whereas a symmetric NAT would keep the mapping:

   `<UDP,RemoteIP,ExtPort> -> <IntIP, IntPort>`

so only RemoteIP can send packets to the internal host. RemoteIP is the supernode
IP in case of n3n, to which the internal host has registered.

In n3n, P2P can work monodirectionally if only one of the two peers is behind a symmetric
NAT. For example, if A is behind symmetric NAT and B is behind asymmetric NAT
   - A->B packets are P2P (will have the B public IP as destination)
   - B->A packets must go through the supernode

If both the peers are behind symmetric NAT, then no P2P communication is possible.

## ARP Cache

n3n makes use of the host operating system's own ARP cache. Each edge node
allocates a random MAC address to itself. This MAC is constant for the life of
the edge process. ARP packets are passed around as broadcast ethernet packets
over n3n and these packets cause the native ARP cache to be updated.

Edge nodes send gratuitous ARP packets on startup. See section on gratuitous ARP below.


## Registration and Peer-to-Peer Communication Setup

A and B are edge nodes with public sockets Apub and Bpub; and private network
addresses A and B respectively.  S is the supernode.

A sends {REGISTER,Amac} to S. S registers {Amac->Apub}.

B sends {REGISTER,Bmac} to S. S registers {Bmac->Bpub}.

Now ping from A to B.

A sends broadcast "arp who-has B" to S. S relays the packet to all known edge
nodes. B replies "B at Bmac" to supernode which forwards this to A. So now ping
A->B is known to be ping Amac(A)->Bmac(B).  Note: gratuitous arp also requires
discussion.

In response to receiving the arp reply, Apub sends {REGISTER,Amac} to Bpub. If
Bpub receives the request it sends back {REGISTER_ACK,Amac} and also sends its
own {REGISTER,Bmac} request.

In response to receiving the "arp who-has", Bpub sends {REGISTER,Bmac} to Apub.

Now the OS has received the arp reply and sends ICMP to Bmac(B) via the tunnel
on A. A looks up Bmac in the peers list and encapsulates the packet to Bpub or
the supernode if the MAC is not found.

We assume that between two edge nodes, if Bpub receives a packet from Apub then
Apub can receive a packet from Bpub. This is the symmetric NAT case.  Note: In
the symmetric NAT case, the public socket for a MAC address will be different
for direct contact when compared to information from the supernode.

When two edge nodes are both behind symmetric NAT they cannot establish direct
communication.

If A receives {REGISTER,Bmac} from B, A adds {Bmac->Bpub} to its peers list
knowing that Bmac is now reachable via that public socket. Similarly if B
receives {REGISTER,Amac} from A.

The supernode never forwards REGISTER messages because the public socket seen by
the supervisor for some edge (eg. A) may be different to the socket seen by
another edge due to the actions of symmetric NAT (allocating a new public socket
for the new outbound UDP "connection").

## Edge Resgitration Design Ammendments (starting from 2008-04-10)

 * Send REGISTER on rx of PACKET or REGISTER only when dest_mac == device MAC
(do not send REGISTER on Rx of broadcast packets).
 * After sending REGISTER add the new peer to pending_peers list; but
 * Don't send REGISTER to a peer in pending_peers list
 * Remove old entries from pending_peers at regular intervals
 * On rx of REGISTER_ACK, move peer from pending_peers to known_peers for direct
comms and set last_seen=now
 * On rx of any packet set last_seen=now in the known_peers entry (if it
exists); but do not add a new entry.
 * If the public socket address for a known_peers entry changes, deleted it and
restart registration to the new peer.
 * Peer sockets provided by the supernode are ignored unless no other entry
exists. Direct peer-to-peer sockets are always given more priority as the
supernode socket will not be usable for direct contact if the peer is behind
symmetric NAT.

The pending_peers list concept is to prevent massive registration traffic when
supernode relay is in force - this would occur if REGISTER was sent for every
incident packet sent via supernode. Periodic REGISTER attempts will still occur;
not for every received packet. In the case where the peer cannot be contacted
(eg. both peers behind symmetric NAT), then there will still be periodic
attempts. Suggest a pending timeout of about 60 sec.

A peer is only considered operational for peer-to-peer sending when a
REGISTER_ACK is returned. Once operational the peer is kept operational while
any direct packet communications are occurring. REGISTER is not required to
keep the path open through any firewalls; just some activity in one direction.

After an idle period; the peer should be deleted from the known_peers list. We
should not try to re-register when this time expires. If there is no data to
send then forget the peer. This helps scalability.

If a peer wants to be remembered it can send gratuitous ARP traffic which will
keep its entry in the known_peers list of any peers which already have the
entry.

```
peer = find_by_src_mac( hdr, known_peers ); /* return NULL or entry */

if ( peer )
{
    peer_last_seen = time(NULL);
}
else
{
    if ( ! is_broadcast( hdr ) ) /* ignore broadcasts */
    {
        if ( IS_REGISTER_ACK( hdr ) )
        {
            /* move from pending to known_peers */
            set_peer_operational( hdr );
        }
        else
        {
            /* add to pending and send REGISTER - ignore if in pending. */
            try_send_register( hdr ) 
        }
    }
}
```

### Notes

 * In testing it was noted that if a symmetric NAT firewall shuts down the UDP
association but the known_peers registration is still active, then the peer
becomes unreachable until the known_peers registration is deleted. Suggest two
ways to mitigate this problem:
   (a) make the known_peers purge timeout a config parameter;
   (b) send packets direct and via supernode if the registration is older than 
       eg. 60 sec.


## Gratuitous ARP

In addition to the ARP who-has mechanism noted above, two edge nodes can become
aware of one another by gratuitous ARP. A gratuitous ARP packet is a broadcast
packet sent by a node for no other purpose than to announce its presence and
identify its MAC and IP address. Gratuitous ARP packets are to keep ARP caches
up to date so contacting the host will be faster after an long idle time.


## man Pages

Look at a non-installed man page like this (linux/UNIX):

`nroff -man edge.8 | less`


## PACKET message format

All message encoding and decoding is contained in wire.c. The PACKET message is
of main concern as it is the most frequently transferred as it contains
encapsulated ethernet packets.

```
Version 3

    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ! Version=3     ! TTL           ! Flags                         !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4 ! Community                                                     :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 ! ... Community ...                                             :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 ! ... Community ...                                             :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 ! ... Community ...                                             :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
20 ! ... Community ...                                             !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
24 ! Source MAC Address                                            :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
28 :                               ! Destination MAC Address       :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
32 :                                                               !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
36 ! Socket Flags (v=IPv4)         ! Destination UDP Port          !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
40 ! Destination IPv4 Address                                      !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
44 ! Compress'n ID !  Transform ID !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
48 ! Payload
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

So each n3n PACKET has a 48 byte overhead. For a 1500 byte ethernet packet this
is roughly 3%.

Socket flags provides support for IPv6. In this case the PACKET message ends as
follows:

```
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
36 ! Socket Flags (v=IPv6)         ! Destination UDP Port          !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
40 ! Destination IPv6 Address                                      :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
44 :                                                               :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
48 :                                                               :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
52 :                                                               !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
56 ! Compress'n ID !  Transform ID !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
60 ! Encapsulated ethernet payload
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

-------
(C) 2008-2010 - Richard Andrews

January 2010 - Richard Andrews <andrews@ntop.org>
