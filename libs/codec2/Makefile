# 
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=codec2
PKG_VERSION:=0.9.2
PKG_RELEASE:=1

PKG_SOURCE_URL_FILE:=v$(PKG_VERSION).tar.gz
PKG_SOURCE:=$(PKG_NAME)-$(PKG_SOURCE_URL_FILE)
PKG_SOURCE_URL:=https://github.com/drowe67/$(PKG_NAME)/archive/refs/tags
PKG_HASH:=19181a446f4df3e6d616b50cabdac4485abb9cd3242cf312a0785f892ed4c76c

PKG_LICENSE:=LGPL-2.1
PKG_LICENSE_FILES:=COPYING
PKG_MAINTAINER:=Andre Heider <a.heider@gmail.com>

include $(INCLUDE_DIR)/package.mk

CMAKE_BINARY_SUBDIR:=build
CMAKE_INSTALL:=1
CMAKE_OPTIONS:=-DGENERATE_CODEBOOK=$(PKG_BUILD_DIR)/generate_codebook

include $(INCLUDE_DIR)/cmake.mk

define Package/libcodec2/description/Default
 Codec 2 is an open source speech codec designed for communications quality
 speech between 700 and 3200 bit/s. The main application is low bandwidth
 HF/VHF digital radio. It fills a gap in open source voice codecs beneath
 5000 bit/s and is released under the GNU Lesser General Public License
 (LGPL).
endef

define Package/libcodec2
  SUBMENU:=Telephony
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=Codec 2 library
  URL:=https://www.rowetel.com/?page_id=452
endef

define Package/libcodec2/description
  $(call Package/libcodec2/description/Default)
endef

define Package/c2enc
  SECTION:=sound
  CATEGORY:=Sound
  DEPENDS:=+libcodec2
  TITLE:=Codec 2 encoder
  URL:=https://www.rowetel.com/?page_id=452
endef

define Package/c2enc/description
  $(call Package/libcodec2/description/Default)
endef

define Package/c2dec
  SECTION:=sound
  CATEGORY:=Sound
  DEPENDS:=+libcodec2
  TITLE:=Codec 2 decoder
  URL:=https://www.rowetel.com/?page_id=452
endef

define Package/c2dec/description
  $(call Package/libcodec2/description/Default)
endef

define Build/Configure
	$(HOSTCC) -o $(PKG_BUILD_DIR)/generate_codebook \
		$(HOST_CFLAGS) $(HOST_CPPFLAGS) $(HOST_LDFLAGS) \
		$(PKG_BUILD_DIR)/src/generate_codebook.c \
		-lm
	$(call Build/Configure/Default)
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/codec2
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/usr/include/codec2/*.h \
		$(1)/usr/include/codec2
	$(INSTALL_DIR) $(1)/usr/lib/{cmake/codec2,pkgconfig}
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libcodec2.so* $(1)/usr/lib
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/*.pc \
		$(1)/usr/lib/pkgconfig
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/usr/lib/cmake/codec2/*.cmake \
		$(1)/usr/lib/cmake/codec2
endef

define Package/libcodec2/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libcodec2.so* $(1)/usr/lib/
endef

define Package/c2enc/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/c2enc $(1)/usr/bin
endef

define Package/c2dec/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/c2dec $(1)/usr/bin
endef

$(eval $(call BuildPackage,libcodec2))
$(eval $(call BuildPackage,c2enc))
$(eval $(call BuildPackage,c2dec))
