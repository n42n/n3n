<!--
SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2022 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman
-->

# Why use n3n

Since there are a number of different open source VPN software solutions
available, this document provides some insight of the reasons for and against
using n3n.

## What n3n is not trying to do:

- It is not intended to be the fastest VPN.
  While we are happy to try and improve the speed of n3n, it is fundamentally
  a userspace solution, which puts limits on how quick any VPN can be.
  If you are looking for speed, we recommend looking at wireguard.

- It is not intended to be a layer-3 VPN.
  (See the next section for layer-2 discussion)
  Some Operating Systems and execution environments only provide support for
  layer-3 VPN (eg Android and increasingly MacOS).  While a layer-2 emulation
  is planned to be added to n3n, it should be understood that this is best
  addressed by using a layer-3 native VPN - again, we recommend looking at
  wireguard for this.
  Additionally - since the main target for requiring layer-3 support is
  currently MacOS - it is important to be able to test this, and the project
  does not have access to any Apple hardware to test with.

- It is not intended to grow to include every possible feature.
  If the Operating System can provide a feature, then that facility should be
  used instead of adding more code to n3n that needs to be supported.
  Obviously, there is a balance to be maintained here, so there is a grey area
  in which some features exist.
  There are a number of pre-existing n3n features that could be considered
  like this - packet filtering and automatic address discovery are two
  examples of features that can probably be done better by the OS, but are
  already part of n3n.

- It is not intended to replace transport security.
  While n3n does include VPN-layer encryption, users should be aware that they
  are fundamentally building a shared network segment.  The packets carried
  by the VPN should still use their own encryption - use of TLS and similar
  should still be done.

## What n3n is trying to do:

- Be a layer-2 VPN.
  The n3n VPN is fundamentally a virtualised and distributed ethernet switch.
  (It might not currently support all the features of a real ethernet switch,
  but this is certainly a target to aim for)
  This is a differentiating feature compared to most other currently used VPN
  solutions.

- Be peer-to-peer connected.
  By allowing the edge nodes to discover each other and communicate directly,
  n3n avoids a lot of reliance on a centralised router.  While the supernode
  can route packets between edges, this should be considered a reliability
  fallback setup.  If your network environment or architecture ends up sending
  large amounts of traffic via the supernode, then we recommend you consider
  a more traditional peer-to-server VPN, such as wireguard.
  This is a differentiating feature compared to most other currently used VPN
  solutions.

- Be simple to setup.
  Keeping the configuration and deployment process as simple as possible helps
  people to try out and to use the VPN.
  This might be a differentiating feature compared to most other currently
  used VPN solutions, depending on how you configure other VPN solutions.

- Be low overhead to run.
  Ensuring that the core of the VPN consumes a small amount of resources to
  allow deployments in all systems - including resource constrained ones.
  This also helps with the efficiency and system footprint.
