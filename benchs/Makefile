#
# Copyright (C) 2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=benchs
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=HEAD
PKG_SOURCE_SUBDIR:=emqbit
PKG_SOURCE_URL:=git://github.com/arhuaco/junkcode.git
PKG_SOURCE:=$(PKG_SOURCE_SUBDIR).tar.gz

include $(INCLUDE_DIR)/package.mk

define Package/benchs
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Various benchmarking tools
  MAINTAINER:=Matteo Croce <matteo@openwrt.org>
endef

define Package/benchs/description
 This package many tools to benchmark the performance or the system and/or the toolchain
endef

define Build/Prepare
	tar xf $(DL_DIR)/$(PKG_SOURCE) -C $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

TOOLS := flops dry emqbit/emqbit-bench/cfft emqbit/emqbit-bench/bench

define Package/benchs/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(foreach t, $(TOOLS), $(PKG_BUILD_DIR)/$(t)) $(1)/bin/
endef

$(eval $(call BuildPackage,benchs))
