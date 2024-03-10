Wireshark Lua plugin to dissect n2n traffic.

Quick load:

```
  wireshark -X lua_script:n3n.lua
```

NOTE: the dissector only decodes traffic on UDP port 50001. In order to decode n2n traffic on another UDP port you can use the "Decode As..." function of wireshark.

To install, place in either the user plugin dir
(`~/.local/lib/wireshark/plugins/`) or the system plugin dir (often something
like `/usr/lib/x86_64-linux-gnu/wireshark/plugins/`)
