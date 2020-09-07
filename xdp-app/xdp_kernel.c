/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common_kern_user.h"
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>

/** for the crc16 implementation only **/
// #define		CRC_START_16		0x0000
// #define		CRC_POLY_16		0xA001
// #define NULL ((void*)0)

// static bool  crc_tab16_init = false;
// static __u16 crc_tab16[256];

// static void init_crc16_tab( void ) {
// 	__u16 i;
// 	__u16 j;
// 	__u16 crc;
// 	__u16 c;

// 	#pragma unroll
// 	for (i=0; i<256; i++) {
// 		crc = 0;
// 		c   = i;
// 		#pragma unroll
// 		for (j=0; j<8; j++) {
// 			if ( (crc ^ c) & 0x0001 ) crc = ( crc >> 1 ) ^ CRC_POLY_16;
// 			else                      crc =   crc >> 1;
// 			c = c >> 1;
// 		}
// 		crc_tab16[i] = crc;
// 	}
// 	crc_tab16_init = true;
// }

// __u16 crc_16( const unsigned char *input_str, __u32 num_bytes, __u16 *prev_crc ) {
// 	__u16 crc;
// 	const unsigned char *ptr;
// 	__u32 a;

// 	if ( ! crc_tab16_init ) init_crc16_tab();

//     if(prev_crc) {
//         crc = *prev_crc;
//     } else {
//     	crc = CRC_START_16;
// 	}

// 	ptr = input_str;

// 	if ( ptr != NULL ) for (a=0; a<num_bytes; a++) {

// 		crc = (crc >> 8) ^ crc_tab16[ (crc ^ (__u16) *ptr++) & 0x00FF ];
// 	}
// 	return crc;
// }
/** for the crc16 implementation only **/

// static __always_inline
// unsigned long checksum_update(unsigned char *buf, int bufsz, unsigned long *prev_checksum) {
//     unsigned long sum = 0;

//     if(prev_checksum) {
//         sum = (*prev_checksum);
//     }

//     while (bufsz > 0) {
//         sum += *buf;
//         buf++;
//         bufsz -= 1;
//         sum = (sum & 0xffff) + (sum >> 16);
//         sum = (sum & 0xffff) + (sum >> 16);
//     }

//     return sum;
// }

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

#define DEBUG

#ifdef DEBUG
/* logs in/sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                        \
	({                                             \
		char ____fmt[] = fmt;                      \
		bpf_trace_printk(____fmt, sizeof(____fmt), \
						 ##__VA_ARGS__);           \
	})
#endif

struct vlan_hdr
{
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

// #define TOTAL_KEYS 0

struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,

};

struct bpf_map_def SEC("maps") xdp_total_keys = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct total_keys),
	.max_entries = MAX_ENTRIES_TOTAL_KEYS,
};

struct bpf_map_def SEC("maps") xdp_flow_keys = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flow_key_info),
	.max_entries = MAX_ENTRIES_FLOW_KEYS,
};

struct bpf_map_def SEC("maps") xdp_flows = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flows_info),
	.max_entries = MAX_ENTRIES_FLOWS,
};

struct bpf_map_def SEC("maps") xdp_flows_history = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flows_info),
	.max_entries = MAX_ENTRIES_FLOWS,
};

static __always_inline bool parse_eth(struct ethhdr *eth, void *data_end,
									  u16 *eth_proto, u64 *l3_offset, struct packet_metadata *metadata)
{
	u16 eth_type;
	u64 offset;

	offset = sizeof(*eth);
	if ((void *)eth + offset > data_end)
		return false;

	eth_type = eth->h_proto;
	metadata->ethernet_protocol = bpf_ntohs(eth_type);
	//bpf_debug("type:0x%x\n", bpf_ntohs(eth_type));

	/* Skip non 802.3 Ethertypes */
	if (bpf_ntohs(eth_type) < ETH_P_802_3_MIN)
		return false;

	/* Handle VLAN tagged packet */
	if (eth_type == bpf_htons(ETH_P_8021Q) || eth_type == bpf_htons(ETH_P_8021AD))
	{
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);
		if ((void *)eth + offset > data_end)
			return false;
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}

	*eth_proto = bpf_ntohs(eth_type);
	*l3_offset = offset;

	// populate the metadata

	bpf_debug("metadata: eth_type:0x%x\n", metadata->ethernet_protocol);

	return true;
}

static __always_inline
	u32
	parse_ipv4(struct xdp_md *ctx, u64 l3_offset, struct iphdr *iph, struct packet_metadata *metadata)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	iph = data + l3_offset;

	if (iph + 1 > data_end)
	{
#ifdef DEBUG
		//bpf_debug("Invalid IPv4 packet: L3off:%llu\n", l3_offset);
#endif
		return XDP_ABORTED;
	}

	// populate metadata
	metadata->ip_src = bpf_ntohl(iph->saddr);
	metadata->ip_dst = bpf_ntohl(iph->daddr);
	metadata->ip_protocol = iph->protocol;
#ifdef DEBUG
	//bpf_debug("saddr:0x%x, daddr:0x%x, protocol:%u\n", metadata->ip_src, metadata->ip_dst, metadata->ip_protocol);
#endif

	void *h = iph + 1;
	if (iph->protocol == IPPROTO_UDP)
	{
		struct udphdr *udph = h;
		if (udph + 1 > data_end)
		{
#ifdef DEBUG
			// bpf_debug("Invalid UDPv4 packet: L4off:%llu\n",
					//   sizeof(struct iphdr) + sizeof(struct udphdr));
#endif
		}
		else
		{
			void *current = udph + 1;
			metadata->src_p = bpf_htons(udph->source);
			metadata->dst_p = bpf_htons(udph->dest);
			metadata->length = data_end - current;
			metadata->key = metadata->ip_src ^ metadata->ip_dst ^ metadata->src_p ^ metadata->dst_p ^ metadata->ip_protocol;
#ifdef DEBUG
			// bpf_debug("(UDP) src:%u, dst:%u, payload:%d", metadata->src_p, metadata->dst_p, metadata->length);
#endif
		}
	}
	else if (iph->protocol == IPPROTO_TCP)
	{
		struct tcphdr *tcph = h;
		if (tcph + 1 > data_end)
		{
#ifdef DEBUG
			// bpf_debug("Invalid TCPv4 packet: L4off:%llu\n",
					//   sizeof(struct iphdr) + sizeof(struct tcphdr));
#endif
		}
		else
		{
			void *current = tcph + 1;
			metadata->src_p = bpf_htons(tcph->source);
			metadata->dst_p = bpf_htons(tcph->dest);
			metadata->acknowledge = bpf_ntohl(tcph->ack_seq);
			metadata->sequence = bpf_ntohl(tcph->seq);
			metadata->cwr = tcph->cwr;
			metadata->ece = tcph->ece;
			metadata->urg = tcph->urg;
			metadata->ack = tcph->ack;
			metadata->psh = tcph->psh;
			metadata->rst = tcph->rst;
			metadata->syn = tcph->syn;
			metadata->fin = tcph->fin;
			metadata->length = data_end - current;
			metadata->key = metadata->ip_src ^ metadata->ip_dst ^ metadata->src_p ^ metadata->dst_p ^ metadata->ip_protocol;
#ifdef DEBUG
			// bpf_debug("(TCP) src:%u, dst:%u, payload:%d", metadata->src_p, metadata->dst_p, metadata->length);
#endif
		}
	}

	return 0;
}

static __always_inline void parse_ipv6(struct xdp_md *ctx, u64 l3_offset, struct ipv6hdr *iph, struct packet_metadata *metadata)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	iph = data + l3_offset;

	/* Hint: +1 is sizeof(struct iphdr) */
	if (iph + 1 > data_end)
	{
#ifdef DEBUG
		// bpf_debug("Invalid IPv6 packet: L3off:%llu\n", l3_offset);
#endif
		return;
	}
}

static __always_inline
	u32
	handle_eth_protocol(struct xdp_md *ctx, u16 eth_proto, u64 l3_offset, struct packet_metadata *metadata)
{
	struct iphdr ipv4hdr;
	struct ipv6hdr _ipv6hdr;
	switch (eth_proto)
	{
	case ETH_P_IP:
		return parse_ipv4(ctx, l3_offset, &ipv4hdr, metadata);
		break;
	case ETH_P_IPV6:
		parse_ipv6(ctx, l3_offset, &_ipv6hdr, metadata);
		return 0;
	default:
#ifdef DEBUG
		// bpf_debug("Not handling eth_proto:0x%x\n", eth_proto);
#endif
		return XDP_PASS;
	}
	return XDP_PASS;
}

SEC("xdp_stats_kernel")
int xdp_stats(struct xdp_md *ctx)
{
#ifdef DEBUG
	// bpf_debug("<-->\n");
#endif
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	// checksum_update(data, (data_end-data), (void *)0);
	// get_checksum(&test1);

	// bpf_debug("checksum => %u", ck);

	struct ethhdr *eth = data;
	struct packet_metadata metadata = {
		.key = 0,
		.ethernet_protocol = 0,
		.ip_src = 0,
		.ip_dst = 0,
		.ip_ttl = 0,
		.ip_protocol = 0,
		.src_p = 0,
		.dst_p = 0,
		.length = 0,
		.acknowledge = 0,
		.sequence = 0,
		.window = 0,
		.urg_ptr = 0,
		.cwr = 0,
		.ece = 0,
		.urg = 0,
		.ack = 0,
		.psh = 0,
		.rst = 0,
		.syn = 0,
		.fin = 0,
	};

	u16 eth_proto = 0;
	u64 l3_offset = 0;

	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset, &metadata)))
	{
#ifdef DEBUG
		// bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x\n",
				//   l3_offset, eth_proto);
#endif
		return XDP_PASS;
	}
	//bpf_debug("Reached L3: L3off:%llu proto:0x%x\n", l3_offset, eth_proto);
	handle_eth_protocol(ctx, eth_proto, l3_offset, &metadata);

	// TODO with metadata
	__u32 totalKeys = TOTAL_KEYS;
	struct total_keys *keysCount = bpf_map_lookup_elem(&xdp_total_keys, &totalKeys);
	if (!keysCount)
	{
		// means there is no keys count yet so, lets initialize it
		struct total_keys tkeys = {
			.total_keys = 0,
		};

		bpf_map_update_elem(&xdp_total_keys, &totalKeys, &tkeys, BPF_ANY);
		keysCount = bpf_map_lookup_elem(&xdp_total_keys, &totalKeys);
	}

	if (keysCount)
	{
		// now we are sure that we have the total keys
		struct flows_info *flowsInfo = bpf_map_lookup_elem(&xdp_flows, &metadata.key);

		if (!flowsInfo)
		{
			struct flow_key_info flowKeyInfo = {
				.key = metadata.key,
				.ip_src = metadata.ip_src,
				.ip_dst = metadata.ip_dst,
				.src_p = metadata.src_p,
				.dst_p = metadata.dst_p,
				.ip_protocol = metadata.ip_protocol,
			};
			bpf_map_update_elem(&xdp_flow_keys, &keysCount->total_keys, &flowKeyInfo, BPF_ANY);
			lock_xadd(&keysCount->total_keys, 1);
		}

		if (!flowsInfo)
		{
			// ++keysCount->total_keys;

			// now we add the flow
			struct flows_info fi = {
				.checksum = 0,
				.totalPackets = 0,
				.totalBytes = 0,
				.totalRxBytes = 0,
				.totalTxBytes = 0,
				.totalTtl = 0,
				.totalEce = 0,
				.totalUrg = 0,
				.totalAck = 0,
				.totalPsh = 0,
				.totalRst = 0,
				.totalSyn = 0,
				.totalFin = 0};
			bpf_map_update_elem(&xdp_flows, &metadata.key, &fi, BPF_ANY);
			flowsInfo = bpf_map_lookup_elem(&xdp_flows, &metadata.key);
		}

		// // by here, we should have a valid flow info
		if (flowsInfo)
		{
			//flowsInfo->checksum = checksum_update(data, (data_end-data), &flowsInfo->checksum);
			lock_xadd(&flowsInfo->totalPackets, 1);
			lock_xadd(&flowsInfo->totalBytes, metadata.length);

			if (eth_proto == ETH_P_IP)
			{
				lock_xadd(&flowsInfo->totalTtl, metadata.ip_ttl);
			}

			if (metadata.ip_protocol == IPPROTO_TCP)
			{
				lock_xadd(&flowsInfo->totalEce, metadata.ece);
				lock_xadd(&flowsInfo->totalUrg, metadata.urg);
				lock_xadd(&flowsInfo->totalAck, metadata.ack);
				lock_xadd(&flowsInfo->totalPsh, metadata.psh);
				lock_xadd(&flowsInfo->totalRst, metadata.rst);
				lock_xadd(&flowsInfo->totalSyn, metadata.syn);
				lock_xadd(&flowsInfo->totalFin, metadata.fin);
			}
#ifdef DEBUG
			// bpf_debug("key: %u, total flows %llu, totalPackets: %llu\n", metadata.key, keysCount->total_keys, flowsInfo->totalPackets);
			// bpf_debug("totalBytes: %llu\n", flowsInfo->totalBytes);
#endif
		}
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
