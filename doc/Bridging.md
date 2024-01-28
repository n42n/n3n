# Bridging (Linux)

## General Remarks

`edge`s can be part of network bridges. As such, n3n can connect otherwise un-connected LANs.

## How To Use with `brctl`

... requires `-r`
... general syntax 
... one example connecting two remote sites' LANs, including commands

## How it works

... remembers peer info MAC
... ageing
... internal MAC replaced inside usually encrypted packet data (no disclosure then)
... initial learning

## Broadcasts

... note on broadcast domain

## Compile Time Option

The `-r`option at edge does not differentiate between the use cases _routing_ and _bridging_. In case the MAC-learning and MAC-replacing bridging code
interfers with some special routing scenario, removal of the `-DHAVE_BRIDGING_SUPPORT` from `Makefile` file disables it at compile time.
