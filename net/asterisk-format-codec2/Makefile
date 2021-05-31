#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=asterisk-format-codec2
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Andre Heider <a.heider@gmail.com>

include $(INCLUDE_DIR)/package.mk

define Package/asterisk-format-codec2
  SUBMENU:=Telephony
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Codec2 audio format support
  DEPENDS:=asterisk +libcodec2
endef

define Package/asterisk-format-codec2/install
	$(INSTALL_DIR) $(1)/usr/lib/asterisk/modules
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/format_codec2.so \
		$(1)/usr/lib/asterisk/modules
endef

define Build/Compile
	$(TARGET_CC) \
		$(TARGET_CPPFLAGS) $(TARGET_CFLAGS) $(FPIC) \
		-Wall -pthread -shared -Wl,--warn-common \
		-DAST_MODULE=\"format_codec2\" \
		-DAST_MODULE_SELF_SYM=__internal_format_codec2 \
		-o $(PKG_BUILD_DIR)/format_codec2.so format_codec2.c
endef

$(eval $(call BuildPackage,asterisk-format-codec2))
