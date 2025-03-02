Copyright (C) Hamish Coleman
SPDX-License-Identifier: GPL-3.0-only

# Management API

Both the edge and the supernode provide a JsonRPC management interface.

A Quick start example query:
```
curl --unix-socket /run/n3n/edge/mgmt http://x/v1 -d '{"jsonrpc": "2.0", "method": "get_edges", "id": 1}' |jq
```
or
```
n3nctl edges
```

(The supernode still uses the legacy default of TCP/5645, but it will soon
switch to using the unix domain socket as its default)

In addition to the main JsonRPC interface, there are a small number of simple
HTTP pages.  These are not intended for complex data, being mainly for
human UI or interoperation with other systems.

Example fetching the list of HTTP pages:
```
curl --unix-socket /run/n3n/edge/mgmt http://x/help
```

## Listening sockets

When the daemon is started, it is either given a session name or uses the
default (simply "edge" for the edge and "supernode" for the supernode)

This session name is used to calculate the path to use for the Unix Domain
socket:

- `/run/n3n/$sessionname/mgmt`

This directory is created if is does not exist, and is created with the
same owner/group that the daemon will run as.  The administrator can adjust
permissions and group memberships as needed.

On exit, the daemon will attempt to remove its socket and session directory,
allowing this to be used as a simple way to see which session names are
running.

Note that since Windows does not support Unix Domain sockets, it listens on
TCP/5644 by default (and creates an empty session directory in
%USERPROFILE%\n3n)

## List the HTTP endpoints

Make a request to `/help` to get a list of the HTTP endpoints.

eg:
```
curl --unix-socket /run/n3n/edge/mgmt http://x/help
```

## List the JsonRPC Methods

Make a call to the "help" method and a list of all known methods will be
returned, along with a short description.

eg:
```
curl --unix-socket /run/n3n/edge/mgmt http://x/v1 -d '{"jsonrpc": "2.0", "method": "help", "id": 1}' |jq
```
or
```
n3nctl help
```

## Events Stream

An event stream is available at the "/events/$topic" URL.  Making a request
to that endpoint will switch that connection to streaming JSON packets,
formatted as described in RFC7464.

Once a connection has been made, any events published on that topic will be
forwarded to the client.

Only one client can be subscribed to any given event topic, with newer
subscriptions replacing older ones.

The special topic "debug" will receive copies of all events published.
Note that this is for debugging of events!

A list of event topics is returned by the JsonRPC method "help.events"

## Authentication

Some API requests will make global changes to the running daemon and may
affect the availability of the n3n networking.  In this case, the daemon
will check for a standard HTTP Authorization header in the request.

The authentication is a simple password that the client must provide. It
defaults to 'n3n' and can either be set with the config option
`management.password`

## Pagination

If the result of an API call will overrun the size of the internal buffer,
the response will indicate an "overflow" condition by returning a 507 result
and a JsonRPC error object.

When an overflow condition is returned, the error object may contain the
count of the number of items that could be added before the overflow occurred.
The request can be retried with pagination parameters to avoid the overflow.
(Note that this also opens up a window for the internal data to change during
the paginated request)

Add the offset and limit values to the param dictionary.

The n3nctl tool has an example on how to use this implemented in its
JsonRPC.get() method
