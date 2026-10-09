#
# Copyright (C) 2026 ming
#
# OpenWrt/ImmortalWrt package for the FCC netfilter NAT helper.
# Single kmod package, modeled after the classic kmod-nf-nathelper-rtsp:
# both modules + autoload, no userspace parts.
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
 Kernel conntrack/NAT helpers for IPTV Fast Channel Change signaling
 (Huawei and Telecom variants).  Rewrites the client address/ports
 embedded in FCC requests and opens the unicast RTP media channel
 through NAT.

 Modules autoload at boot.  Helper assignment is integrated with fw4
 like the other well-known protocols (rtsp/sip/tftp): the postinst
 script appends an "fcc" section to /usr/share/firewall4/helpers, so
 the ct helper object and the dport-8027 assignment rule are rendered
 automatically.  The FCC port is changed by appending "port=<n>" to
 the nf_conntrack_fcc line in /etc/modules.d/45-nf-nathelper-fcc
 (default 8027; the helper name is "fcc" for the default port,
 "fcc-<n>" otherwise).
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

# Merge the fcc helper into fw4's helper database (idempotent), accept
# helper-expected media in the forward chain via an nftables include,
# then have fw4 re-render so everything appears without a reboot.
# Helper rendering is gated on the module being loaded, so a missing
# module simply hides the rules instead of breaking the firewall.
define Package/kmod-nf-nathelper-fcc/postinst
#!/bin/sh
[ -d /usr/share/firewall4 ] || exit 0

# helper database section
if [ -f /usr/share/firewall4/helpers ] && \
   ! grep -q "option name 'fcc'" /usr/share/firewall4/helpers; then
    cat >> /usr/share/firewall4/helpers <<'EOF'

config helper
	option name 'fcc'
	option description 'FCC connection tracking'
	option module 'nf_conntrack_fcc'
	option family 'ipv4'
	option proto 'udp'
	option port '8027'
EOF
fi

modprobe nf_conntrack_fcc 2>/dev/null
/etc/init.d/firewall reload >/dev/null 2>&1 &
exit 0
endef

$(eval $(call KernelPackage,nf-nathelper-fcc))

endif
