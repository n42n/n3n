## Prerequisites

This instructions explain how to build an OpenWRT .ipk package for n3n.

You will either need to build a full OpenWRT buildchain (See the github
action for building openwrt.yml for some example steps) or have a working
cross-compiling build environment for the OpenWRT version installed into
your device.

### Downloading a cross-compiling build environment

This usually comes down to the following steps:

1. Download and extract the SDK toolchain for your device. The toolchain
   must match the *exact* OpenWRT version installed in your device. Toolchain
   for official OpenWRT images can be downloaded from https://downloads.openwrt.org

2. Build the toolchain: run `make menuconfig`, save the configuration, then
   run `make` to build the cross compiling tools

3. Download the feeds with `./scripts/feeds update -a`

## Compilation

These instructions are for building the current checked out version of the
n3n source  (The generally used OpenWRT alternative is to download a tar.gz
file of a specific n3n version, but that is not as suitable for development
or local builds)

You need both the openwrt repository and the n3n repository checked out
for this.  In these instructions, we assume that `openwrt` is the directory
where your openwrt checkout is located and `n3n` is the directory for
the n3n repository.

```
git clone https://github.com/n42n/n3n n3n
N2N_PKG_VERSION=$(n3n/scripts/version.sh)
export N2N_PKG_VERSION
echo $N2N_PKG_VERSION

cp -r n3n/packages/openwrt openwrt/package/n3n

cd openwrt
make oldconfig
# In the VPN section, select "m" for n3n-edge and n3n-supernode

make package/n3n/clean V=s
make package/n3n/prepare USE_SOURCE_DIR=$(realpath ../n3n) V=s
make package/n3n/compile V=s
```

If everything went fine, two ipk will be generated, one for the n3n-edge
and the other for n3n-supernode. They can be found with `find . -name "n3n*.ipk"`,
copied to the target device, and installed with `opkg install`.

The github action described in `.github/workflows/openwrt.yml` implements
an automated version of the above steps.

## Configuration

The edge node can be started with `/etc/init.d/edge start`.
Its configuration file is `/etc/n3n/edge.conf`.

The supernode can be started with `/etc/init.d/supernode start`.
Its configuration file is `/etc/n3n/supernode.conf`.
