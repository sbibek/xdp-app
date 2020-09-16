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

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

#define DEBUG
// #define TEST

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

struct bpf_map_def SEC("maps") xdp_stats_map = {
#ifndef PER_CPU
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
#else
	.type = BPF_MAP_TYPE_ARRAY,
#endif
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

struct bpf_map_def SEC("maps") xdp_total_keys = {
#ifndef PER_CPU
	.type = BPF_MAP_TYPE_PERCPU_HASH,
#else
	.type = BPF_MAP_TYPE_HASH,
#endif
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct total_keys),
	.max_entries = MAX_ENTRIES_TOTAL_KEYS,
};

struct bpf_map_def SEC("maps") xdp_flow_keys = {
#ifndef PER_CPU
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
#else
	.type = BPF_MAP_TYPE_ARRAY,
#endif
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flow_key_info),
	.max_entries = MAX_ENTRIES_FLOW_KEYS,
};

struct bpf_map_def SEC("maps") xdp_flows = {
#ifndef PER_CPU
	.type = BPF_MAP_TYPE_PERCPU_HASH,
#else
	.type = BPF_MAP_TYPE_HASH,
#endif
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flows_info),
	.max_entries = MAX_ENTRIES_FLOWS,
};

struct bpf_map_def SEC("maps") xdp_flows_history = {
#ifndef PER_CPU
	.type = BPF_MAP_TYPE_PERCPU_HASH,
#else
	.type = BPF_MAP_TYPE_HASH,
#endif
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flows_info),
	.max_entries = MAX_ENTRIES_FLOWS,
};

// static __always_inline
// unsigned long checksum_update(unsigned char *buf, unsigned char *buffer_end, int bufsz, unsigned long *prev_checksum) {
//     unsigned long sum = 0;

//     if(prev_checksum) {
//         sum = (*prev_checksum);
//     }

//     // while (bufsz > 0) {
// 	// 	if(buf <= buffer_end) {
//     //     sum += *buf;
//     //     buf++;
//     //     sum = (sum & 0xffff) + (sum >> 16);
//     //     sum = (sum & 0xffff) + (sum >> 16);
// 	// 	}
//     //     bufsz -= 1;
//     // }
// 	int i = 0;
// 	#pragma clang loop unroll(full)
// 	for(i=0;i<750;i++){
// 		if(buf+i <= buffer_end) {
// 			// means this is safe access
// 			sum += i;
// 		}
// 	}

//     return sum;
// }

// static __always_inline unsigned short checksum(unsigned short *buf, int bufsz) {
//     unsigned long sum = 0;

//     while (bufsz > 1) {
//         sum += *buf;
//         buf++;
//         bufsz -= 2;
//     }

//     if (bufsz == 1) {
//         sum += *(unsigned char *)buf;
//     }

//     sum = (sum & 0xffff) + (sum >> 16);
//     sum = (sum & 0xffff) + (sum >> 16);

//     return ~sum;
// }

// static __always_inline __u32 sum16(void *data, void *data_end, __u8 len)
// {
// 	__u8 *addr = data;

// 	__u32 sum = 0;
// 	int i;

// #pragma clang loop unroll(full)
// 	for (i = 0; i < 1500; i++)
// 	{
// 		if(addr < data_end) {
// 			sum += *addr;
// 			++addr;
// 		}
// 	}

// 	return sum;
// }

static __always_inline __u32 sum16(void *data, void *data_end)
{
	if (data < data_end)
	{
		__u8 *current = data;
		__u32 sum = 0;

		int i;
		for (i = 1; i < 1500; i++)
		{
			sum += *(current+i);

			if (current +i >= data_end)
				break;
		}
		return sum;
	}
	else
	{
		return 0;
	}
}

#ifndef TEST
static __always_inline
	u32
	parse_ipv4(struct xdp_md *ctx, u64 l3_offset, struct iphdr *iph, struct packet_metadata *metadata)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	iph = data + l3_offset;

	if (iph + 1 > data_end)
	{
		return XDP_ABORTED;
	}

	// populate metadata
	metadata->ip_src = bpf_ntohl(iph->saddr);
	metadata->ip_dst = bpf_ntohl(iph->daddr);
	metadata->ip_protocol = iph->protocol;

	void *h = iph + 1;
	if (iph->protocol == IPPROTO_UDP)
	{
		struct udphdr *udph = h;
		if (udph + 1 <= data_end)
		{
			void *current = udph + 1;
			metadata->src_p = bpf_htons(udph->source);
			metadata->dst_p = bpf_htons(udph->dest);
			metadata->length = data_end - current;
			metadata->key = metadata->ip_src ^ metadata->ip_dst ^ metadata->src_p ^ metadata->dst_p ^ metadata->ip_protocol;
			// if(current < data_end)
			metadata->payload_checksum = sum16(current, data_end);
		}
	}
	else if (iph->protocol == IPPROTO_TCP)
	{
		struct tcphdr *tcph = h;
		if (tcph + 1 <= data_end)
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
			// if(current < data_end)
			metadata->payload_checksum = sum16(current, data_end);
		}
	}

	return 0;
}

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
	return true;
}

static __always_inline
	__u32
	handle_eth_protocol(struct xdp_md *ctx, u16 eth_proto, u64 l3_offset, struct packet_metadata *metadata)
{
	struct iphdr ipv4hdr;
	//struct ipv6hdr _ipv6hdr;

	switch (eth_proto)
	{
	case ETH_P_IP:
		return parse_ipv4(ctx, l3_offset, &ipv4hdr, metadata);
		break;
	case ETH_P_IPV6:
		//parse_ipv6(ctx, l3_offset, &_ipv6hdr, metadata);
		return XDP_PASS;
	default:
		return XDP_PASS;
	}
	return XDP_PASS;
}

static __always_inline void update_maps(struct packet_metadata *metadata, u16 eth_proto, void *data, void *data_end)
{
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
		struct flows_info *flowsInfo = bpf_map_lookup_elem(&xdp_flows, &metadata->key);
		if (!flowsInfo)
		{
			struct flow_key_info flowKeyInfo = {
				.key = metadata->key,
				.ip_src = metadata->ip_src,
				.ip_dst = metadata->ip_dst,
				.src_p = metadata->src_p,
				.dst_p = metadata->dst_p,
				.ip_protocol = metadata->ip_protocol,
			};
			bpf_map_update_elem(&xdp_flow_keys, &keysCount->total_keys, &flowKeyInfo, BPF_ANY);
			// lock_xadd(&keysCount->total_keys, 1);

			// // now we add the flow
			// struct flows_info fi = {
			// 	.checksum = 0,
			// 	.totalPackets = 0,
			// 	.totalBytes = 0,
			// 	.totalRxBytes = 0,
			// 	.totalTxBytes = 0,
			// 	.totalTtl = 0,
			// 	.totalEce = 0,
			// 	.totalUrg = 0,
			// 	.totalAck = 0,
			// 	.totalPsh = 0,
			// 	.totalRst = 0,
			// 	.totalSyn = 0,
			// 	.totalFin = 0};
			// bpf_map_update_elem(&xdp_flows, &metadata->key, &fi, BPF_ANY);
			// flowsInfo = bpf_map_lookup_elem(&xdp_flows, &metadata->key);
		}
	
	}
}
#endif

SEC("xdp_stats_kernel")
int xdp_stats(struct xdp_md *ctx)
{
	// get the start and end of the packet
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	
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
		.payload_checksum = 0
	};


#ifndef TEST
	u16 eth_proto = 0;
	u64 l3_offset = 0;

	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset, &metadata)))
	{
		return XDP_PASS;
	}

	//else handle the protocol and populate the metadata information
	handle_eth_protocol(ctx, eth_proto, l3_offset, &metadata);
	// finally update the maps
	update_maps(&metadata, eth_proto, data, data_end);
#endif

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";