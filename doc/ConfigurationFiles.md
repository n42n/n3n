# Configuration Files

To help deployment and better handle locally different configurations, n3n
supports the optional use of configuration files for `edge` and `supernode`.

They are plain text files and contain the desired command line options, **one
per line**.

The exemplary command line

```bash
sudo edge -c mynetwork -k mysecretpass -a 192.168.100.1 -f -l supernode.ntop.org:7777
```

translates into the following `edge.conf` file:

```
-c mynetwork
-k mysecretpass
-a 192.168.100.1
-f
-l supernode.ntop.org:7777
-A5
```

which can be loaded by

```
sudo ./edge start edge
```

Comment lines starting with a hash '#' are ignored.

```
# automated edge configuration
# created by bot7
# on April 31, 2038 – 1800Z
-c    mynetwork
-k    mysecretpass
-a    192.168.100.1
-f
-A5
# --- supernode section ---
-l    supernode.ntop.org:7777
```

Long options can be used as well. Please note the double minus/dash-character `--`, just like you would use them on the command line with long options:

```
--community    mynetwork
-k             mysecretpass
-a             192.168.100.1
-f
-A5
-l             supernode.ntop.org:7777
```

The edge will attempt to locate a configuration file based on the "sessionname", which
defaults to "edge".  This would result in a config file called "edge.conf", which is
located in "/etc/n3n" (or the current directory on Windows)

If required, additional command line parameters can also be supplied:

```
sudo edge edge.conf -z1 -I myComputer
```

Finally, the `.conf` file syntax also allows `=` between parameter and its option:

```
-c=mynetwork
-k=mysecretpass
-a=192.168.100.1
-f
-A5
-l=supernode.ntop.org:7777
```

When used with `=`, there is no whitespace allowed between parameter, delimiter (`=`), and option. So, do **not** put `-c = mynetwork` – it is required to be `-c=mynetwork`.
