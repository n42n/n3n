# Configuration Files

To help deployment and better handle locally different configurations, n3n
supports the use of configuration files for `edge` and `supernode`.

The daemon will attempt to locate a configuration file based on the
"sessionname" - which defaults to "edge" for the edge daemon.  This would
result in a config file called "edge.conf", which is located in "/etc/n3n" (or
the %USERPROFILE%\n3n directory on Windows)

They are plain text files formatted very similar to INI files.

To generate the help documentation for all current options:
```bash
edge help config
```

If you created the following `/etc/n3n/testing.conf` file:

```
[community]
cipher = Speck
key = mysecretpass
name = mynetwork
supernode = supernode.ntop.org:7777

[daemon]
background = false

[tuntap]
address = 192.168.100.1
address_mode = static
```

which can be loaded by

```
sudo ./edge start testing
```

If needed, the settings from the config file can all be overridden using a
command line parameter:

If required, additional command line parameters can also be supplied:

```
sudo edge start testing \
    -Oconnection.description=myComputer \
    -O community.compression=lzo
```

Some of the most common options also have a shortcut version, you can see all
these with:

```
edge help options
```
