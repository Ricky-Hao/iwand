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
/etc/iwan/iwan.conf
endef

define Build/Compile
	$(TARGET_CC) \
		$(TARGET_CFLAGS) \
		$(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/iwand \
		$(PKG_BUILD_DIR)/src/iwand.c
endef

define Package/iwand/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/iwand $(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/luci-app-iwand/root/etc/init.d/iwand $(1)/etc/init.d/iwand

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/luci-app-iwand/root/etc/config/iwand $(1)/etc/config/iwand
	chmod 0600 $(1)/etc/config/iwand

	$(INSTALL_DIR) $(1)/etc/iwan
	[ -f $(1)/etc/iwan/iwan.conf ] || \
		$(INSTALL_CONF) $(PKG_BUILD_DIR)/openwrt/iwan.conf.example $(1)/etc/iwan/iwan.conf
	chmod 0600 $(1)/etc/iwan/iwan.conf
endef

$(eval $(call BuildPackage,iwand))
