include $(TOPDIR)/rules.mk

PKG_NAME:=saned-static
PKG_VERSION:=1.0.24
PKG_RELEASE:=1

PKG_LICENSE:=GPLv2
PKG_LICENSE_FILES:=COPYING
PKG_MAINTAINER:=Matteo Croce <matteo@openwrt.org>

include $(INCLUDE_DIR)/package.mk

define Package/saned-static
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Printing
  TITLE:=Scanner Access Now Easy
  URL:=http://sane-project.org/
endef

define Package/saned-static/conffiles
/etc/config/saned
endef

define Package/saned-static/description
 saned is the SANE (Scanner Access Now Easy) daemon that allows remote
 clients to access image acquisition devices available on the local host.
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/saned-static/install
	cp -a ./files/* $(1)/
endef

$(eval $(call BuildPackage,saned-static))
