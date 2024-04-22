# Setting up a Custom Supernode

For the privacy of your data sent and to reduce the server load or reliance
on `supernode.ntop.org`, it is also suggested to set up a custom supernode.

You can create your own infrastructure by setting up a supernode on a public
server (e.g. a VPS). You just need to open a single port (1234 in the example
below) on your firewall (usually `iptables`).

1. Install the n3n package
2. Edit `/etc/n3n/supernode.conf` and add the following:
   ```
   [connection]
   bind=1234
   ```
3. Start the supernode service with `sudo systemctl start n3n-supernode`
4. Optionally enable supernode start on boot: `sudo systemctl enable n3n-supernode`

Now the supernode service should be up and running on port 1234. On your edge
nodes you can now specify `-l your_supernode_ip:1234` to use it. All the edge
nodes must use the same supernode (or be part of the same
[supernode federation](Federation.md))
