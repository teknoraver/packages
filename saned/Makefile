#
# Copyright (C) 2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=saned
PKG_VERSION:=1.0.25
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/sane-backends-$(PKG_VERSION)
PKG_SOURCE:=sane-backends-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://alioth.debian.org/frs/download.php/file/4146
PKG_LICENSE:=GPLv2
PKG_LICENSE_FILES:=COPYING
#PKG_MD5SUM:=1ca68e536cd7c1852322822f5f6ac3a4
PKG_MD5SUM:=f9ed5405b3c12f07c6ca51ee60225fe7
PKG_MAINTAINER:=Matteo Croce <matteo@openwrt.org>

PKG_CHECK_FORMAT_SECURITY:=0
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/saned/Default
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Printing
  DEPENDS:=+libpthread +libusb-1.0 +libltdl +PACKAGE_libjpeg:libjpeg +PACKAGE_libpng:libpng
  TITLE:=Scanner Access Now Easy
  URL:=http://sane-project.org/
endef

define Package/saned
  $(call Package/saned/Default)
  MENU:=1
endef

define Package/saned/conffiles
/etc/config/saned
endef

define Package/saned/description
 saned is the SANE (Scanner Access Now Easy) daemon that allows remote
 clients to access image acquisition devices available on the local host.
endef

CONFIGURE_ARGS += --enable-libusb_1_0 --enable-shared --enable-static
export BACKENDS := test

define Package/saned/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/sbin $(1)/usr/lib $(1)/etc/sane.d $(1)/etc/config $(1)/etc/init.d
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/saned $(1)/usr/sbin/
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/scanimage $(1)/usr/bin/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libsane.so* $(1)/usr/lib/
	$(INSTALL_DATA) ./files/saned.config $(1)/etc/config/saned
	$(INSTALL_BIN) ./files/saned.init $(1)/etc/init.d/sane
	echo 0.0.0.0/0 >$(1)/etc/sane.d/saned.conf
endef

define BuildBackend
  ifneq ($(CONFIG_PACKAGE_saned-$(1)),)
    BACKENDS += $(1)
  endif

  define Package/saned-$(1)
    $(call Package/saned/Default)
    DEPENDS:=saned
    TITLE:=$(1) backend
  endef

  define Package/saned-$(1)/install
	$(INSTALL_DIR) $$(1)/usr/lib/sane $$(1)/etc/sane.d/dll.d
	-$(CP) $(PKG_INSTALL_DIR)/etc/sane.d/$(1).conf $$(1)/etc/sane.d/
	echo $(1) >$$(1)/etc/sane.d/dll.d/$(1)
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/sane/libsane-$(1).so* $$(1)/usr/lib/sane/
  endef

  $$(eval $$(call BuildPackage,saned-$(1)))
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include $(1)/etc/sane.d
	$(CP) $(PKG_INSTALL_DIR)/usr/include/sane $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libsane.{a,so*} $(1)/usr/lib/
endef

$(eval $(call BuildPackage,saned))

$(eval $(call BuildBackend,abaton))
$(eval $(call BuildBackend,agfafocus))
$(eval $(call BuildBackend,apple))
$(eval $(call BuildBackend,artec))
$(eval $(call BuildBackend,artec_eplus48u))
$(eval $(call BuildBackend,as6e))
$(eval $(call BuildBackend,avision))
$(eval $(call BuildBackend,bh))
$(eval $(call BuildBackend,canon))
$(eval $(call BuildBackend,canon630u))
$(eval $(call BuildBackend,canon_dr))
$(eval $(call BuildBackend,cardscan))
$(eval $(call BuildBackend,coolscan))
$(eval $(call BuildBackend,coolscan2))
$(eval $(call BuildBackend,coolscan3))
$(eval $(call BuildBackend,dc25))
$(eval $(call BuildBackend,dmc))
$(eval $(call BuildBackend,epjitsu))
$(eval $(call BuildBackend,epson))
$(eval $(call BuildBackend,epson2))
$(eval $(call BuildBackend,fujitsu))
$(eval $(call BuildBackend,genesys))
$(eval $(call BuildBackend,gt68xx))
$(eval $(call BuildBackend,hp))
$(eval $(call BuildBackend,hp3500))
$(eval $(call BuildBackend,hp3900))
$(eval $(call BuildBackend,hp4200))
$(eval $(call BuildBackend,hp5400))
$(eval $(call BuildBackend,hp5590))
$(eval $(call BuildBackend,hpljm1005))
$(eval $(call BuildBackend,hs2p))
$(eval $(call BuildBackend,ibm))
$(eval $(call BuildBackend,kodak))
$(eval $(call BuildBackend,kodakaio))
$(eval $(call BuildBackend,kvs1025))
$(eval $(call BuildBackend,kvs20xx))
$(eval $(call BuildBackend,kvs40xx))
$(eval $(call BuildBackend,leo))
$(eval $(call BuildBackend,lexmark))
$(eval $(call BuildBackend,ma1509))
$(eval $(call BuildBackend,magicolor))
$(eval $(call BuildBackend,matsushita))
$(eval $(call BuildBackend,microtek))
$(eval $(call BuildBackend,microtek2))
$(eval $(call BuildBackend,mustek))
$(eval $(call BuildBackend,mustek_usb))
$(eval $(call BuildBackend,mustek_usb2))
$(eval $(call BuildBackend,nec))
$(eval $(call BuildBackend,net))
$(eval $(call BuildBackend,niash))
$(eval $(call BuildBackend,p5))
$(eval $(call BuildBackend,pie))
$(eval $(call BuildBackend,pixma))
$(eval $(call BuildBackend,plustek))
$(eval $(call BuildBackend,plustek_pp))
$(eval $(call BuildBackend,qcam))
$(eval $(call BuildBackend,ricoh))
$(eval $(call BuildBackend,rts8891))
$(eval $(call BuildBackend,s9036))
$(eval $(call BuildBackend,sceptre))
$(eval $(call BuildBackend,sharp))
$(eval $(call BuildBackend,sm3600))
$(eval $(call BuildBackend,sm3840))
$(eval $(call BuildBackend,snapscan))
$(eval $(call BuildBackend,sp15c))
$(eval $(call BuildBackend,st400))
$(eval $(call BuildBackend,stv680))
$(eval $(call BuildBackend,tamarack))
$(eval $(call BuildBackend,teco1))
$(eval $(call BuildBackend,teco2))
$(eval $(call BuildBackend,teco3))
$(eval $(call BuildBackend,test))
$(eval $(call BuildBackend,u12))
$(eval $(call BuildBackend,umax))
$(eval $(call BuildBackend,umax1220u))
$(eval $(call BuildBackend,umax_pp))
$(eval $(call BuildBackend,xerox_mfp))
