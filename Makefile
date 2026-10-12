#
# Copyright (C) 2026 ming
#
# OpenWrt package for the FCC netfilter NAT helper.
#
# This file IS the OpenWrt package Makefile and lives at the project root,
# so the OpenWrt tree symlinks the whole project as one package:
#
#   ln -s <repo> <tree>/package/fcc-nathelper
#   make package/fcc-nathelper/compile
#
# Out-of-tree kernel builds work standalone too — just run make; see targets
# below (KERNEL_DIR defaults to the running kernel's build dir).
#
# Artifact: bin/targets/<board>/<subtarget>/packages/kmod-nf-nathelper-fcc-<kver>.apk
#
# FCC port configuration on the device: edit
# /etc/modules.d/45-nf-nathelper-fcc and append the module parameter,
# e.g. "nf_conntrack_fcc port=8030", then restart the boot script.

KERNEL_DIR  ?= /lib/modules/$(shell uname -r)/build
ARCH        ?=
CROSS_COMPILE ?=

ifeq ($(TOPDIR),)
# ----------------------------------------------------------- standalone build
.PHONY: all modules clean install

all: modules

modules:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR)/src ARCH=$(ARCH) \
		CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR)/src clean

install: modules
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR)/src ARCH=$(ARCH) \
		CROSS_COMPILE=$(CROSS_COMPILE) modules_install

else
# ------------------------------------------------------------- OpenWrt build

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=fcc-nathelper
PKG_VERSION:=1.0.0
PKG_RELEASE:=10

PKG_MAINTAINER:=ming
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define KernelPackage/nf-nathelper-fcc
  SUBMENU:=Netfilter Extensions
  TITLE:=FCC (Fast Channel Change) NAT helper
  DEPENDS:=+kmod-nf-conntrack +kmod-nf-nat
  FILES:=$(PKG_BUILD_DIR)/nf_conntrack_fcc.ko $(PKG_BUILD_DIR)/nf_nat_fcc.ko
  AUTOLOAD:=$(call AutoLoad,45,nf_conntrack_fcc nf_nat_fcc)
endef

define KernelPackage/nf-nathelper-fcc/description
 Conntrack and NAT helpers for IPTV Fast Channel Change protocol
 (Huawei and Telecom variants).
endef

# Explicit list: the source dir also holds build artifacts.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/Kbuild ./src/nf_fcc.h \
	      ./src/nf_conntrack_fcc.c ./src/nf_nat_fcc.c $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" modules
endef

# Register the fcc helper in fw4's helper database and accept
# helper-expected media in the forward chain. postinst must be
# IPKG_INSTROOT-aware: at image build time OpenWrt runs it against the
# rootfs staging dir, so the helper section is baked into the image;
# modprobe/firewall reload only run on the device. prerm removes the
# section again by name (apk del only deletes files the package owns,
# the appended block would otherwise survive uninstall). Helper
# rendering is gated on the module being loaded, so a missing module
# simply hides the rules instead of breaking the firewall.
define Package/kmod-nf-nathelper-fcc/postinst
#!/bin/sh
HELPERS="$$IPKG_INSTROOT/usr/share/firewall4/helpers"
[ -f "$$HELPERS" ] || exit 0

if ! grep -q "option name 'fcc'" "$$HELPERS"; then
	# exactly one blank line between sections: strip trailing blank
	# lines, make sure the file ends with a newline, then append
	while [ -z "$$(tail -n 1 "$$HELPERS")" ]; do sed -i '$$d' "$$HELPERS"; done
	[ -n "$$(tail -c 1 "$$HELPERS")" ] && echo >> "$$HELPERS"
	cat >> "$$HELPERS" <<'EOF'

config helper
	option name 'fcc'
	option description 'FCC connection tracking'
	option module 'nf_conntrack_fcc'
	option family 'ipv4'
	option proto 'udp'
	option port '8027'
EOF
fi

if [ -z "$$IPKG_INSTROOT" ]; then
	modprobe nf_conntrack_fcc 2>/dev/null
	/etc/init.d/firewall reload >/dev/null 2>&1 &
fi
exit 0
endef

define Package/kmod-nf-nathelper-fcc/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0

HELPERS="/usr/share/firewall4/helpers"
if [ -f "$$HELPERS" ] && grep -q "option name 'fcc'" "$$HELPERS"; then
	sed -i '/./{H;$$!d};x;/option name .fcc./d' "$$HELPERS"
	# do not leave a trailing blank line behind
	while [ -z "$$(tail -n 1 "$$HELPERS")" ]; do sed -i '$$d' "$$HELPERS"; done
	sed -i '1{/^$/d}' "$$HELPERS"
	/etc/init.d/firewall reload >/dev/null 2>&1
fi
exit 0
endef

$(eval $(call KernelPackage,nf-nathelper-fcc))

endif
