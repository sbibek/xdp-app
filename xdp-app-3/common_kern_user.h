#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#define TOTAL_KEYS 0
#define MAX_ENTRIES_TOTAL_KEYS 1
#define MAX_ENTRIES_FLOW_KEYS 10000
#define MAX_ENTRIES_FLOWS 10000

struct datarec
{
	__u64 rx_packets;
	__u64 rx_bytes;
};

struct packet_metadata
{
	__u32 key;
	__u32 ip_src;
	__be32 length; // payload length
	__u32 ip_dst;
	__be32 acknowledge; //TCP
	__be32 sequence; //TCP




	__u16 ethernet_protocol;
	__be16 src_p;
	__be16 dst_p;


	/* this is populated if TCP Only */
	__be16 window;
	__be16 urg_ptr;
	__u16 cwr;
	__u16 ece;
	__u16	urg;
	__u16	ack;
	__u16	psh;
	__u16	rst;
	__u16	syn;
	__u16	fin;

	__u8 ip_ttl;
	__u8 ip_protocol;

};

struct total_keys {
	__u64 total_keys;
};

struct flow_key_info
{
	__u32 key;
	__u32 ip_src;
	__u32 ip_dst;
	__be16 src_p;
	__be16 dst_p;
	__u8 ip_protocol;
	
	char padding[3];
};

struct flows_info {
	__u64 timestamp;
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

	unsigned long checksum;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif

