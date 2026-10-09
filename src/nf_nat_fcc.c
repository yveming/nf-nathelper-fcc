// SPDX-License-Identifier: GPL-2.0
/*
 * nf_nat_fcc.c - FCC (Fast Channel Change) NAT helper
 *
 * Rewrites the client address/ports embedded in FCC requests and opens
 * the conntrack expectation for the unicast RTP (media) channel, the
 * same way nf_nat_ftp handles FTP data connections.
 *
 * Why a POSTROUTING hook instead of mangling inside the conntrack
 * helper: unlike RTSP (a TCP control channel whose payload commands
 * only flow once the connection is established and its NAT mapping is
 * final), an FCC request is the very first packet of its UDP flow.  At
 * PREROUTING time source NAT has not been decided yet, so the public
 * address/port to advertise is simply not knowable there.  This hook
 * therefore runs after the source-NAT hooks, reads the final mapping
 * from the conntrack reply tuple, rewrites the payload and registers
 * the expectation.
 *
 * Rewrites performed (fields per fccproxy's nat_*_request()):
 *
 *   Huawei  REQ (FMT 5, >=28B):  client_ip    (off 20) -> NAT public IP
 *                                signal_port (off 24) -> WAN port P+1,
 *                                   where P is the pinned WAN media port
 *   Telecom REQ (FMT 2, 40B):    client_port (off 16) -> pinned WAN port
 *
 * Expectations (reverse direction, server -> client):
 *
 *   Huawei:  {any -> client_WAN:P}  mapped to {client_LAN:signal_port-1}
 *   Telecom: {any -> client_WAN:P}  mapped to {client_LAN:client_port}
 *
 * Server->client response fields (server_ip, media_port, ...) are left
 * untouched: the FCC server is on the public side and reachable as is.
 * Huawei NAT-traversal punches (magic 00 03) need no help either; a
 * helper expectation covers inbound RTP even without a punch.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <net/ip.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_helper.h>

#include "nf_fcc.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FCC NAT helper");
MODULE_ALIAS_NF_NAT_HELPER("fcc");
MODULE_VERSION("r9");

static struct nf_conntrack_nat_helper fcc_nat_helper =
	NF_CT_NAT_HELPER_INIT("fcc");

/* Number of WAN ports to try when the preferred one is taken */
#define FCC_PORT_TRIES		32

/*
 * Field debugging: every decision of the hook is silent by design, so
 * without this there is nothing in dmesg telling where a request got
 * dropped off.  Load with debug=1 (or echo 1 >/sys/module/nf_nat_fcc/
 * parameters/debug at run time) to get one line per decision.
 */
static bool debug;
module_param(debug, bool, 0644);
MODULE_PARM_DESC(debug, "log every hook decision");

#define FCC_DBG(fmt, ...)						\
	do {								\
		if (debug)						\
			pr_info(fmt, ##__VA_ARGS__);			\
	} while (0)

/*
 * Parse an FCC request payload.
 *
 * Returns 0 and fills in the protocol plus the advertised client
 * address (Huawei only, network order) and media port (network order)
 * when the payload is an outgoing FCC request; returns -1 for anything
 * else (replies, sync, termination, BYE, punches, foreign traffic),
 * which the caller treats as "leave untouched".
 */
static int fcc_parse_request(const u8 *payload, unsigned int len,
			     int *proto, __be32 *lan_ip, __be16 *lan_port)
{
	const struct fcc_rtcp_fb_hdr *rtcp = (const void *)payload;
	int fmt;

	if (len < FCC_RTCP_FB_HDR_LEN)
		return -1;

	/* RTCP feedback, version 2 */
	if ((rtcp->vpfmt & 0xC0) != 0x80 || rtcp->pt != FCC_RTCP_PT_RTPFB)
		return -1;

	fmt = rtcp->vpfmt & 0x1F;

	/*
	 * FMT 5 is shared: a 16-byte packet is a Telecom termination,
	 * anything >= 28 bytes is a Huawei request (fcc_detect_proto()).
	 */
	switch (fmt) {
	case FCC_FMT_HUAWEI_REQ:
		if (len < FCC_HUAWEI_REQ_MIN_LEN)
			return -1;
		*proto = FCC_PROTO_HUAWEI;
		memcpy(lan_ip, payload + FCC_HUAWEI_REQ_CLIENT_IP_OFF,
		       sizeof(*lan_ip));
		memcpy(lan_port, payload + FCC_HUAWEI_REQ_SIGNAL_PORT_OFF,
		       sizeof(*lan_port));
		return 0;
	case FCC_FMT_TELECOM_REQ:
		if (len < FCC_TELECOM_REQ_LEN)
			return -1;
		*proto = FCC_PROTO_TELECOM;
		*lan_ip = 0;
		memcpy(lan_port, payload + FCC_TELECOM_REQ_CLIENT_PORT_OFF,
		       sizeof(*lan_port));
		return 0;
	default:
		return -1;
	}
}

/*
 * Telecom servers follow redirect chains, and every hop re-sends the
 * REQ from the same client port while advertising it again, so the
 * previous hop's expectation (same client, 30s TTL) still occupies the
 * advertised port — the -EBUSY.
 *
 * Drop that stale expectation when it clearly belongs to this client
 * (same LAN source address and port), so the current hop can take the
 * port over with a fresh expectation of its own: the port and the
 * advertisement stay unchanged, while the new expectation's master
 * points at the current hop — so the media source needs no address
 * rewriting.  Expectations of other clients are left alone.
 *
 * Returns true when the port was freed for the caller.
 */
static bool fcc_claim_client_port(struct nf_conn *ct,
				  const struct nf_conntrack_tuple *tuple)
{
	const struct nf_conntrack_man *held_src, *cur;
	struct nf_conntrack_expect *held;
	bool ours = false;

	held = nf_ct_expect_find_get(nf_ct_net(ct), nf_ct_zone(ct), tuple);
	if (!held)
		return false;

	held_src = &held->master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src;
	cur = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src;

	ours = held_src->u3.ip == cur->u3.ip &&
	       held_src->u.udp.port == cur->u.udp.port;

	FCC_DBG("port %u held by %s client\n",
		ntohs(tuple->dst.u.udp.port), ours ? "this" : "another");

	if (ours)
		nf_ct_remove_expect(held);

	nf_ct_expect_put(held);
	return ours;
}

/*
 * Translate the expected media connection: destination-NAT only.
 *
 * Unlike FTP, FCC media does not come from the signaling server —
 * redirect chains hand media off to dedicated servers from a resource
 * pool, and the client has already punched towards the real media
 * address.  Rewriting the source (as nf_nat_follow_master() would,
 * mapping it to the signaling server) would make the media arrive
 * from an address the client is not expecting.  Preserve the real
 * source; map only the destination back to the client's LAN
 * address/port from saved_proto.
 */
static void fcc_expect_translate(struct nf_conn *ct,
				 struct nf_conntrack_expect *exp)
{
	struct nf_nat_range2 range;

	range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
	range.min_addr = range.max_addr =
		ct->master->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
	range.min_proto = range.max_proto = exp->saved_proto;
	nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
}

/*
 * Register the media-channel expectation.  Follows nf_nat_ftp: pin the
 * client's NATed address as the destination tuple, remember the
 * originally advertised (LAN) port in saved_proto, and let
 * fcc_expect_translate() map the expected connection when it arrives.
 * On -EBUSY the port is taken over from this same client's earlier
 * redirect hop (fresh expectation, master switched to the current hop)
 * or, if held by someone else, bumped until free; the caller must
 * advertise the returned value in the payload.
 *
 * A fresh expectation object is allocated per insert attempt: never
 * re-insert an object that already went through a failed attempt.
 *
 * Returns the pinned WAN media port on success (the inserted
 * expectation is returned in *@exp_out, for the caller to
 * nf_ct_expect_put()), 0 on failure.
 */
static u16 fcc_expect_media(struct nf_conn *ct,
			    const struct nf_conntrack_tuple *reply,
			    __be16 lan_media_port,
			    struct nf_conntrack_expect **exp_out)
{
	struct nf_conntrack_expect *exp;
	unsigned int tries;
	u16 port;

	*exp_out = NULL;

	for (port = ntohs(lan_media_port), tries = 0;
	     port != 0 && tries < FCC_PORT_TRIES;
	     port++, tries++) {
		int ret;

		exp = nf_ct_expect_alloc(ct);
		if (!exp) {
			FCC_DBG("cannot allocate expectation\n");
			break;
		}

		/* Media may originate from the signaling server or from
		 * a redirect target: match any source, pin only the
		 * destination.
		 *
		 * nf_ct_expect_init() resets expectfn and saved_proto, so
		 * both must be set AFTER it: an expectation inserted
		 * without them is consumed by the media flow but
		 * translates nothing. */
		nf_ct_expect_init(exp, NF_CT_EXPECT_CLASS_DEFAULT,
				  NFPROTO_IPV4, NULL, &reply->dst.u3,
				  IPPROTO_UDP, NULL, &lan_media_port);
		exp->saved_proto.udp.port = lan_media_port;
		exp->dir = IP_CT_DIR_REPLY;
		exp->expectfn = fcc_expect_translate;

		exp->tuple.dst.u.udp.port = htons(port);
		ret = nf_ct_expect_related(exp, 0);
		if (ret == 0) {
			FCC_DBG("media expectation created on port %u\n", port);
			*exp_out = exp;
			return port;
		}
		nf_ct_expect_put(exp);

		if (ret != -EBUSY) {
			FCC_DBG("expect_related(%u) failed: %d\n", port, ret);
			break;
		}

		/* Port held by this client's earlier redirect hop: take
		 * the port over with a fresh expectation whose master is
		 * this hop, keeping the advertised port unchanged. */
		if (!fcc_claim_client_port(ct, &exp->tuple)) {
			FCC_DBG("port %u held by another client, bumping\n",
				port);
			continue;
		}

		exp = nf_ct_expect_alloc(ct);
		if (!exp)
			break;
		nf_ct_expect_init(exp, NF_CT_EXPECT_CLASS_DEFAULT,
				  NFPROTO_IPV4, NULL, &reply->dst.u3,
				  IPPROTO_UDP, NULL, &lan_media_port);
		exp->saved_proto.udp.port = lan_media_port;
		exp->dir = IP_CT_DIR_REPLY;
		exp->expectfn = fcc_expect_translate;
		exp->tuple.dst.u.udp.port = htons(port);
		ret = nf_ct_expect_related(exp, 0);
		if (ret == 0) {
			FCC_DBG("media expectation taken over on port %u\n",
				port);
			*exp_out = exp;
			return port;
		}
		FCC_DBG("expect_related(%u) failed after takeover: %d\n",
			port, ret);
		nf_ct_expect_put(exp);
		break;
	}

	return 0;
}

/*
 * Recognise flows assigned to our helper by name: the conntrack side
 * registers as "fcc" for the default port and "fcc-<port>" for any
 * other one.  Matching by name keeps the NAT side independent of the
 * conntrack module (no cross-module symbols, load order irrelevant).
 */
static bool is_fcc_helper(const struct nf_conntrack_helper *h)
{
	return h && (strcmp(h->name, "fcc") == 0 ||
		     strncmp(h->name, "fcc-", 4) == 0);
}

static unsigned int fcc_nat_out(void *priv, struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	struct nf_conntrack_tuple *reply;
	enum ip_conntrack_info ctinfo;
	struct nf_conntrack_expect *exp = NULL;
	struct nf_conntrack_helper *helper;
	struct nf_conn_help *help;
	struct fcc_ct_master *master;
	unsigned int protoff, dataoff, datalen, buflen;
	const u8 *payload;
	u8 buf[FCC_PARSE_BUF_LEN];
	__be32 lan_ip = 0;
	__be16 lan_port = 0;
	bool ok = true, ours;
	int dir, proto;
	u16 media_port, wan_port;

	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

	if (!ct)
		return NF_ACCEPT;

	dir = CTINFO2DIR(ctinfo);
	if (dir != IP_CT_DIR_ORIGINAL)
		return NF_ACCEPT;

	if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum != IPPROTO_UDP)
		return NF_ACCEPT;

	/* Only flows assigned to our helper (CT rule or auto-assign). */
	help = nfct_help(ct);
	if (!help)
		return NF_ACCEPT;

	rcu_read_lock();
	helper = rcu_dereference(help->helper);
	ours = is_fcc_helper(helper);
	rcu_read_unlock();
	if (!ours) {
		FCC_DBG("helper \"%s\" is not ours, skip\n",
			helper ? helper->name : "(none)");
		return NF_ACCEPT;
	}

	master = (struct fcc_ct_master *)help->data;
	if (master->done) {
		FCC_DBG("flow already handled, skip\n");
		return NF_ACCEPT;
	}

	/* No source NAT in effect (including null bindings): the
	 * embedded client address is already valid as is. */
	if (!(ct->status & IPS_SRC_NAT)) {
		FCC_DBG("no source NAT in effect, advertisement is already public\n");
		master->done = 1;
		return NF_ACCEPT;
	}

	reply = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;

	protoff = skb_network_offset(skb) + ip_hdrlen(skb);
	dataoff = protoff + sizeof(struct udphdr);
	if (dataoff >= skb->len) {
		FCC_DBG("UDP packet without payload, skip\n");
		return NF_ACCEPT;
	}

	datalen = skb->len - dataoff;
	buflen = min_t(unsigned int, datalen, sizeof(buf));
	payload = skb_header_pointer(skb, dataoff, buflen, buf);
	if (!payload)
		return NF_ACCEPT;

	if (fcc_parse_request(payload, buflen, &proto, &lan_ip, &lan_port)) {
		FCC_DBG("payload is not an FCC REQ (len %u), skip\n", buflen);
		return NF_ACCEPT;
	}

	media_port = ntohs(lan_port);
	if (proto == FCC_PROTO_HUAWEI) {
		/* Huawei convention: RTP arrives on signal_port - 1 */
		if (media_port < 2) {
			FCC_DBG("huawei signal port %u too small\n", media_port);
			master->done = 1;
			return NF_ACCEPT;
		}
		media_port--;
	} else if (!media_port) {
		/* No media port advertised: nothing to NAT */
		FCC_DBG("telecom REQ without client port\n");
		master->done = 1;
		return NF_ACCEPT;
	}

	wan_port = fcc_expect_media(ct, reply, htons(media_port), &exp);
	if (!wan_port) {
		FCC_DBG("no usable WAN port for media %u\n", media_port);
		nf_ct_helper_log(skb, ct, "no free port for FCC media");
		master->done = 1;
		return NF_ACCEPT;
	}

	/* Rewrite the embedded values; same-size replacements only, so
	 * the offsets below stay valid across edits. */
	if (proto == FCC_PROTO_HUAWEI) {
		__be32 new_ip = reply->dst.u3.ip;
		__be16 new_signal_port = htons(wan_port + 1);

		if (memcmp(&lan_ip, &new_ip, sizeof(new_ip)) != 0)
			ok = nf_nat_mangle_udp_packet(skb, ct, ctinfo, protoff,
					FCC_HUAWEI_REQ_CLIENT_IP_OFF,
					sizeof(new_ip),
					(char *)&new_ip, sizeof(new_ip));
		if (ok && lan_port != new_signal_port)
			ok = nf_nat_mangle_udp_packet(skb, ct, ctinfo, protoff,
					FCC_HUAWEI_REQ_SIGNAL_PORT_OFF,
					sizeof(new_signal_port),
					(char *)&new_signal_port,
					sizeof(new_signal_port));

		pr_debug("huawei req: %pI4:%u -> %pI4:%u, media %u\n",
			 &lan_ip, ntohs(lan_port), &new_ip, wan_port + 1,
			 wan_port);
	} else {
		__be16 new_port = htons(wan_port);

		if (lan_port != new_port) {
			FCC_DBG("telecom: rewriting client_port %u -> %u\n",
				ntohs(lan_port), wan_port);
			ok = nf_nat_mangle_udp_packet(skb, ct, ctinfo, protoff,
					FCC_TELECOM_REQ_CLIENT_PORT_OFF,
					sizeof(new_port),
					(char *)&new_port, sizeof(new_port));
		} else {
			FCC_DBG("telecom: client_port %u already correct, no rewrite\n",
				wan_port);
		}
	}

	if (!ok) {
		FCC_DBG("payload rewrite failed, undoing the expectation\n");
		nf_ct_helper_log(skb, ct, "cannot mangle FCC request");
		/* The payload was not (fully) rewritten, so nothing gets
		 * advertised on the pinned port; undo the expectation. */
		nf_ct_unexpect_related(exp);
	}

	/* Drop the allocation reference of the inserted expectation;
	 * unexpect_related above already removed the table reference
	 * when the payload could not be rewritten. */
	if (exp)
		nf_ct_expect_put(exp);

	master->done = 1;
	return NF_ACCEPT;
}

static struct nf_hook_ops fcc_nat_ops __read_mostly = {
	.hook		= fcc_nat_out,
	.pf		= NFPROTO_IPV4,
	.hooknum	= NF_INET_POST_ROUTING,
	/* After the source-NAT hooks, so the reply tuple is final. */
	.priority	= NF_IP_PRI_NAT_SRC + 10,
};

static int __init nf_nat_fcc_init(void)
{
	int ret;

	BUILD_BUG_ON(sizeof(struct fcc_ct_master) >
		     sizeof_field(struct nf_conn_help, data));

	nf_nat_helper_register(&fcc_nat_helper);

	ret = nf_register_net_hook(&init_net, &fcc_nat_ops);
	if (ret) {
		nf_nat_helper_unregister(&fcc_nat_helper);
		return ret;
	}

	pr_info("FCC NAT helper r9 (dst-only translate) registered\n");
	return 0;
}

static void __exit nf_nat_fcc_exit(void)
{
	nf_unregister_net_hook(&init_net, &fcc_nat_ops);
	nf_nat_helper_unregister(&fcc_nat_helper);
	synchronize_rcu();
}

module_init(nf_nat_fcc_init);
module_exit(nf_nat_fcc_exit);
