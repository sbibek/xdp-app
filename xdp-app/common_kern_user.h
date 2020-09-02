#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

struct datarec
{
	__u64 rx_packets;
	__u64 rx_bytes;
};

struct packet_metadata
{
	__u32 key;
	__u16 ethernet_protocol;
	__u32 ip_src;
	__u32 ip_dst;
	__u8 ip_ttl;
	__u8 ip_protocol;

	/* populated for both TCP and UDP */
	__be16 src_p;
	__be16 dst_p;
	__be32 length; // payload length

	/* this is populated if TCP Only */
	__be32 acknowledge;
	__be32 sequence;
	__be16 window;
	__be16 urg_ptr;
	__u16 cwr,
		ece,
		urg,
		ack,
		psh,
		rst,
		syn,
		fin;
};

struct flow_key_info
{
	__u32 ip_src;
	__u32 ip_dst;
	__be16 src_p;
	__be16 dst_p;
	__u8 ip_protocol;
};

struct flows_info {
	__u64 totalPackets,
			totalBytes,
			totalRxBytes,
			totalTxBytes,
			totalTtl,
			totalEce,
			totalUrg,
			totalAck,
			totalPsh,
			totalRst,
			totalSyn,
			totalFin;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif
