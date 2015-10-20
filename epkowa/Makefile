#
# Copyright (C) 2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=saned-epkowa
PKG_VERSION:=2.10.0
PKG_RELEASE:=1

PKG_SOURCE:=iscan-free_$(PKG_VERSION)-1.tar.bz2
PKG_BUILD_DIR:=$(BUILD_DIR)/iscan-$(PKG_VERSION)
#PKG_SOURCE_URL:=
PKG_LICENSE:=GPLv2
PKG_LICENSE_FILES:=COPYING
PKG_MD5SUM:=6d650409874f90b7190249ca734b23d1
PKG_MAINTAINER:=Matteo Croce <matteo@openwrt.org>

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/saned-epkowa
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Printing
  DEPENDS:=saned +libpthread +libusb-1.0 +libltdl
  TITLE:=Scanner Access Now Easy
  URL:=http://sane-project.org/
  TITLE:=epkowa backend
endef

define Package/saned-epkowa/description
 saned is the SANE (Scanner Access Now Easy) daemon that allows remote
 clients to access image acquisition devices available on the local host.
endef

CONFIGURE_ARGS += --with-pic

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) CXXFLAGS+=-fpermissive
endef

define Package/saned-epkowa/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/usr/lib $(1)/etc/sane.d
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/saned-epkowa $(1)/usr/sbin/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libsane.so* $(1)/usr/lib/
endef

define Package/saned-epkowa/install
	$(INSTALL_DIR) $(1)/usr/lib/sane $(1)/etc/sane.d $(1)/etc/sane.d/dll.d
	$(CP) $(PKG_BUILD_DIR)/backend/epkowa.conf $(1)/etc/sane.d/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/sane/libsane-epkowa.so* $(1)/usr/lib/sane/
	echo epkowa >$(1)/etc/sane.d/dll.d/epkowa
endef

$(eval $(call BuildPackage,saned-epkowa))
