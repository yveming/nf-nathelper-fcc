/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FCC (Fast Channel Change) protocol definitions shared by
 * nf_conntrack_fcc and nf_nat_fcc.
 *
 * Wire formats are ported from the fccproxy userspace implementation
 * (src/fcc.h, src/fcc_huawei.h, src/fcc_telecom.h).  FCC carries IPTV
 * fast-channel-change signaling over UDP inside RTCP feedback packets;
 * both protocol variants embed the client's address/ports in the
 * payload, which is what the NAT helper has to rewrite.
 */

#ifndef __NF_FCC_H__
#define __NF_FCC_H__

#include <linux/stddef.h>
#include <linux/types.h>

/* RTCP common fields */
#define FCC_RTCP_PT_RTPFB	205	/* generic RTP feedback */
#define FCC_RTCP_PT_BYE		203

#define FCC_RTCP_FB_HDR_LEN	12

struct fcc_rtcp_fb_hdr {
	__u8	vpfmt;		/* version(2) / padding(1) / FMT(5) */
	__u8	pt;		/* payload type */
	__be16	length;
	__be32	sender_ssrc;
	__be32	media_ssrc;
} __packed;

/* FCC FMT values */
#define FCC_FMT_TELECOM_REQ	2	/* RTCP Request */
#define FCC_FMT_TELECOM_RESP	3	/* RTCP Response */
#define FCC_FMT_TELECOM_SYN	4	/* RTCP Sync Notification */
#define FCC_FMT_TELECOM_TERM	5	/* RTCP Termination (16B) */
#define FCC_FMT_HUAWEI_REQ	5	/* RTCP Request (>=28B, shares FMT 5) */
#define FCC_FMT_HUAWEI_RESP	6	/* RTCP Response */
#define FCC_FMT_HUAWEI_SYN	8	/* RTCP Sync Notification */
#define FCC_FMT_HUAWEI_TERM	9	/* RTCP Termination */

#define FCC_PROTO_UNKNOWN	0
#define FCC_PROTO_TELECOM	1
#define FCC_PROTO_HUAWEI	2

struct fcc_huawei_req {
	struct fcc_rtcp_fb_hdr rtcp;
	__u8	type;		/* 0x00 Huawei Request */
	__u8	reserved13;
	__be16	mcast_seq;
	__be32	mcast_ip;
	__be32	client_ip;
	__be16	signal_port;	/* client media port = signal_port - 1 */
	__be16	flag;
	__be32	redirect;
} __packed;

struct fcc_telecom_req {
	struct fcc_rtcp_fb_hdr rtcp;
	__u8	version;
	__u8	reserved13[3];
	__be16	client_port;	/* client signaling+RTP port (single port) */
	__be16	mcast_port;
	__be32	mcast_ip;
	__u8	stbid[16];
} __packed;

/* Field offsets within the FCC payload (verified by BUILD_BUG_ON) */
#define FCC_HUAWEI_REQ_CLIENT_IP_OFF					\
	offsetof(struct fcc_huawei_req, client_ip)		/* 20 */
#define FCC_HUAWEI_REQ_SIGNAL_PORT_OFF					\
	offsetof(struct fcc_huawei_req, signal_port)		/* 24 */
#define FCC_HUAWEI_REQ_MIN_LEN						\
	offsetof(struct fcc_huawei_req, redirect)		/* 28 */

#define FCC_TELECOM_REQ_CLIENT_PORT_OFF					\
	offsetof(struct fcc_telecom_req, client_port)		/* 16 */
#define FCC_TELECOM_REQ_LEN		sizeof(struct fcc_telecom_req)	/* 40 */

#define FCC_TELECOM_TERM_LEN	(FCC_RTCP_FB_HDR_LEN + 4)	/* 16 */

/* Longest request we parse */
#define FCC_PARSE_BUF_LEN	64

/*
 * Per-conntrack helper data (nf_conn_help.data, at most 32 bytes).
 * FCC requests are the first packet of a UDP flow and clients retry
 * them; this flag makes nf_nat_fcc process the flow only once.
 */
struct fcc_ct_master {
	u8	done;
};

#endif /* __NF_FCC_H__ */
