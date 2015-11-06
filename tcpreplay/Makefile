#
# Copyright (C) 20015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=tcpreplay
PKG_VERSION:=4.1.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/appneta/tcpreplay/releases/download/v4.1.0
PKG_MD5SUM:=fd48d73d84ade30ece0a9abb538c82d5

PKG_MAINTAINER:=Matteo Croce <matteo@openwrt.org>
PKG_LICENSE:=GPL

include $(INCLUDE_DIR)/package.mk

define Package/tcpreplay
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libpcap +libpthread
  TITLE:=Pcap editing and replaying utilities
  URL:=http://tcpreplay.appneta.com/
endef

define Package/tcpreplay/description
 Tcpreplay is a suite of free Open Source utilities for editing
 and replaying previously captured network traffic.
 Originally designed to replay malicious traffic patterns to
 Intrusion Detection/Prevention Systems,
 it has seen many evolutions including capabilities to replay to web servers.
endef

CONFIGURE_ARGS += --with-libpcap=$(STAGING_DIR)/usr

define Package/tcpreplay/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/tcpreplay $(1)/usr/bin/
endef

$(eval $(call BuildPackage,tcpreplay))
