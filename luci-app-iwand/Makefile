include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for iWAN SD-WAN
LUCI_DEPENDS:=+iwand
LUCI_PKGARCH:=all

PKG_LICENSE:=MIT

include $(TOPDIR)/feeds/luci/luci.mk

$(eval $(call BuildPackage,luci-app-iwand))
