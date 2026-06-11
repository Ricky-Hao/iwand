include $(TOPDIR)/rules.mk

PKG_NAME:=iwand
PKG_VERSION:=0.2.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/Ricky-Hao/iwand.git
PKG_SOURCE_DATE:=2026-06-01
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
PKG_MIRROR_HASH:=skip

PKG_LICENSE:=MIT
PKG_MAINTAINER:=Ricky-Hao <14084342+Ricky-Hao@users.noreply.github.com>

include $(INCLUDE_DIR)/package.mk

define Package/iwand
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=Panabit iWAN SD-WAN Client
  DEPENDS:=+kmod-tun
  URL:=https://github.com/Ricky-Hao/iwand
endef

define Package/iwand/description
  Panabit iWAN SD-WAN client daemon. Reverse-engineered reimplementation
  of the official client, compatible with Panabit SD-WAN servers.
  Supports encrypted tunneling, latency measurement, IP fragment
  reassembly, and segment routing.
endef

define Package/iwand/conffiles
/etc/config/iwand
endef

define Build/Compile
	$(TARGET_CC) \
		$(TARGET_CFLAGS) \
		$(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/iwand \
		$(PKG_BUILD_DIR)/src/iwand.c \
		$(PKG_BUILD_DIR)/src/tun_linux.c \
		$(PKG_BUILD_DIR)/src/tun_freebsd.c
endef

define Package/iwand/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/iwand $(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/luci-app-iwand/root/etc/init.d/iwand $(1)/etc/init.d/iwand

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/luci-app-iwand/root/etc/config/iwand $(1)/etc/config/iwand
	chmod 0600 $(1)/etc/config/iwand
endef

define Package/iwand/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
[ -x /etc/init.d/iwand ] && /etc/init.d/iwand enable 2>/dev/null
exit 0
endef

define Package/iwand/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
/etc/init.d/iwand stop 2>/dev/null
/etc/init.d/iwand disable 2>/dev/null
rm -f /etc/rc.d/S99iwand /etc/rc.d/K10iwand 2>/dev/null
exit 0
endef

$(eval $(call BuildPackage,iwand))
