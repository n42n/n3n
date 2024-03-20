#
# Copyright (C) 2021 - ntop.org and contributors
#

include $(TOPDIR)/rules.mk

PKG_NAME:=n3n
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz

PKG_SOURCE_URL:=https://github.com/n42n/n3n

# These are defaults for compiling without any environmental overrides
# (eg, the github action calculates the correct overrides for each build)
PKG_VERSION?=FIXME
PKG_SOURCE_VERSION?=main
PKG_MIRROR_HASH:=skip

PKG_MAINTAINER:=Hamish Coleman <hamish@zot.org>
PKG_LICENSE:=GPL-3.0-only

# autogen fix
PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

define Package/n3n/Default
  SECTION:=net
  CATEGORY:=Network
  TITLE:=N2N Peer-to-peer VPN
  URL:=http://github.com/n42n/n3n
  SUBMENU:=VPN
  DEPENDS+=+libcap
endef

define Package/n3n-edge
  $(call Package/n3n/Default)
  TITLE+= client (edge node)
  DEPENDS+=+kmod-tun
endef

define Package/n3n-supernode
  $(call Package/n3n/Default)
  TITLE+= server (supernode)
endef

define Package/n3n-edge/description
The client node for the N2N infrastructure
endef

define Package/n3n-supernode/description
The supernode for the N2N infrastructure
endef

define Build/Configure
	( cd $(PKG_BUILD_DIR); \
	./autogen.sh; \
	LDFLAGS=--static ./configure )
endef

define Package/n3n-edge/conffiles
/etc/n3n/edge.conf
endef

define Package/n3n-edge/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scripts/n3nctl $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/apps/n3n-edge $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/packages/openwrt/etc/init.d/n3n-edge $(1)/etc/init.d/n3n-edge
	$(INSTALL_DIR) $(1)/etc/n3n
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/doc/edge.conf.sample $(1)/etc/n3n/edge.conf
endef

define Package/n3n-supernode/conffiles
/etc/n3n/supernode.conf
endef

define Package/n3n-supernode/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/apps/n3n-supernode $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/packages/openwrt/etc/init.d/n3n-supernode $(1)/etc/init.d/n3n-supernode
	$(INSTALL_DIR) $(1)/etc/n3n
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/doc/supernode.conf.sample $(1)/etc/n3n/supernode.conf
endef

$(eval $(call BuildPackage,n3n-edge))
$(eval $(call BuildPackage,n3n-supernode))
