#
# Copyright (C) 2016 Matteo Croce <matteo@openwrt.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=simh
PKG_VERSION:=3.9-0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/simh/simh
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=v$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/simh/Default
  SECTION:=net
  CATEGORY:=Utilities
  TITLE:=SIMH is a highly portable, multi-system simulator
  URL:=http://simh.trailing-edge.com/
  DEPENDS:=+libpthread +librt
endef

define Package/simh
  $(call Package/simh/Default)
  MENU:=1
endef

define Package/simh/description
	The Computer History Simulation Project is a loose Internet-based
	collective of people interested in restoring historically significant
	computer hardware and software systems by simulation.
	The goal of the project is to create highly portable system simulators
	and to publish them as freeware on the Internet,
	with freely available copies of significant or representative software.
endef

define BuildSimulator
  ifneq ($(CONFIG_PACKAGE_simh-$(1)),)
    SIMULATORS += $(1)
  endif

  define Package/simh-$(1)
    $(call Package/simh/Default)
    DEPENDS:=simh
    TITLE:=$(1) simulator
  endef

  define Package/simh-$(1)/install
	$(INSTALL_DIR) $$(1)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/BIN/$(1) $$(1)/usr/bin
  endef

 $$(eval $$(call BuildPackage,simh-$(1)))
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) GCC=$(TARGET_CC) $$(SIMULATORS)
endef

$(eval $(call BuildPackage,simh))
$(eval $(call BuildSimulator,altair))
$(eval $(call BuildSimulator,altairz80))
$(eval $(call BuildSimulator,eclipse))
$(eval $(call BuildSimulator,gri))
$(eval $(call BuildSimulator,h316))
$(eval $(call BuildSimulator,hp2100))
$(eval $(call BuildSimulator,i1401))
$(eval $(call BuildSimulator,i1620))
$(eval $(call BuildSimulator,i7094))
$(eval $(call BuildSimulator,ibm1130))
$(eval $(call BuildSimulator,id16))
$(eval $(call BuildSimulator,id32))
$(eval $(call BuildSimulator,lgp))
$(eval $(call BuildSimulator,nova))
$(eval $(call BuildSimulator,pdp1))
$(eval $(call BuildSimulator,pdp10))
$(eval $(call BuildSimulator,pdp11))
$(eval $(call BuildSimulator,pdp15))
$(eval $(call BuildSimulator,pdp4))
$(eval $(call BuildSimulator,pdp7))
$(eval $(call BuildSimulator,pdp8))
$(eval $(call BuildSimulator,pdp9))
$(eval $(call BuildSimulator,s3))
$(eval $(call BuildSimulator,sds))
$(eval $(call BuildSimulator,swtp6800mp-a))
$(eval $(call BuildSimulator,swtp6800mp-a2))
$(eval $(call BuildSimulator,vax))
$(eval $(call BuildSimulator,vax780))
