// SPDX-License-Identifier: GPL-2.0
/*
 * nf_conntrack_fcc.c - FCC (Fast Channel Change) connection tracking helper
 *
 * FCC carries IPTV fast-channel-change signaling over UDP in RTCP
 * feedback packets (Huawei and Telecom operator variants).  The client
 * advertises its own IP address and RTP ports inside the request
 * payload, so the signaling and media flows it negotiates cannot
 * traverse plain NAT on their own.
 *
 * This module registers a connection tracking helper named "fcc" bound
 * to a configurable UDP port (module parameter 'port', default 8027).
 * Flow activation works through any of the usual mechanisms: automatic
 * helper assignment (net.netfilter.nf_conntrack_helper=1) or an
 * explicit CT target rule, e.g.
 *
 *     iptables -t raw -A PREROUTING -p udp --dport 8027 -j CT --helper fcc
 *
 * The companion module nf_nat_fcc performs the payload rewriting and
 * registers the media-channel expectation; it runs from a POSTROUTING
 * hook because an FCC request is the very first packet of its UDP flow
 * and the source-NAT decision is not known before that point (see
 * nf_nat_fcc.c for details).
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/netfilter.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>

#include "nf_fcc.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FCC (Fast Channel Change) connection tracking helper");
MODULE_ALIAS_NFCT_HELPER("fcc");
MODULE_VERSION("r9");

static unsigned short port __read_mostly = 8027;
module_param(port, ushort, 0444);
MODULE_PARM_DESC(port,
		 "UDP port FCC signaling is carried on (default 8027)");

static const struct nf_conntrack_expect_policy fcc_exp_policy = {
	.max_expected	= 4,
	.timeout	= 30,
	.name		= "fcc",
};

static struct nf_conntrack_helper fcc_helper __read_mostly;

/*
 * All the work happens in nf_nat_fcc after source NAT has been decided;
 * this helper only marks the flow (and gives it a name for conntrack
 * tooling and firewall assignment).
 */
static int fcc_help(struct sk_buff *skb, unsigned int protoff,
		    struct nf_conn *ct, enum ip_conntrack_info ctinfo)
{
	return NF_ACCEPT;
}

static int __init nf_conntrack_fcc_init(void)
{
	int ret;

	BUILD_BUG_ON(FCC_HUAWEI_REQ_CLIENT_IP_OFF != 20);
	BUILD_BUG_ON(FCC_HUAWEI_REQ_SIGNAL_PORT_OFF != 24);
	BUILD_BUG_ON(FCC_HUAWEI_REQ_MIN_LEN != 28);
	BUILD_BUG_ON(FCC_TELECOM_REQ_CLIENT_PORT_OFF != 16);
	BUILD_BUG_ON(FCC_TELECOM_REQ_LEN != 40);
	NF_CT_HELPER_BUILD_BUG_ON(sizeof(struct fcc_ct_master));

	if (!port) {
		pr_err("invalid port 0\n");
		return -EINVAL;
	}

	nf_ct_helper_init(&fcc_helper, NFPROTO_IPV4, IPPROTO_UDP,
			  "fcc", 8027, port, 0,
			  &fcc_exp_policy, 0, fcc_help, NULL, THIS_MODULE);

	ret = nf_conntrack_helper_register(&fcc_helper);
	if (ret) {
		pr_err("failed to register helper: %d\n", ret);
		return ret;
	}

	pr_info("FCC conntrack helper r9: UDP port %u (helper name \"%s\")\n",
		port, fcc_helper.name);

	return 0;
}

static void __exit nf_conntrack_fcc_exit(void)
{
	synchronize_rcu();
	nf_conntrack_helper_unregister(&fcc_helper);
}

module_init(nf_conntrack_fcc_init);
module_exit(nf_conntrack_fcc_exit);
