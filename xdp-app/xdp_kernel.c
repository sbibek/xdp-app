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

#ifdef DEBUG
/* logs in/sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                        \
	({                                             \
		char ____fmt[] = fmt;                      \
		bpf_trace_printk(____fmt, sizeof(____fmt), \
						 ##__VA_ARGS__);           \
	})
#else
#define bpf_debug(fmt, ...) \
	{                       \
	}                       \
	while (0)
#endif

struct vlan_hdr
{
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};


struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,

};
struct bpf_map_def SEC("maps") xdp_total_keys = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") xdp_flow_keys = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flow_key_info),
	.max_entries = 10000,
};

struct bpf_map_def SEC("maps") xdp_flows = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flows_info),
	.max_entries = 10000,
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
	//bpf_debug("Debug: eth_type:0x%x\n", bpf_ntohs(eth_type));

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
	metadata->ethernet_protocol = bpf_ntohs(eth_type);
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
		bpf_debug("Invalid IPv4 packet: L3off:%llu\n", l3_offset);
		return XDP_ABORTED;
	}

	// populate metadata
	metadata->ip_src = bpf_ntohl(iph->saddr);
	metadata->ip_dst = bpf_ntohl(iph->daddr);
	metadata->ip_protocol = iph->protocol;
	bpf_debug("saddr:0x%x, daddr:0x%x, protocol:%u\n", metadata->ip_src, metadata->ip_dst, metadata->ip_protocol);

	void *h = iph + 1;
	if (iph->protocol == IPPROTO_UDP)
	{
		struct udphdr *udph = h;
		if (udph + 1 > data_end)
		{
			bpf_debug("Invalid UDPv4 packet: L4off:%llu\n",
					  sizeof(struct iphdr) + sizeof(struct udphdr));
		}
		else
		{
			void *current = udph + 1;
			metadata->src_p = bpf_htons(udph->source);
			metadata->dst_p = bpf_htons(udph->dest);
			metadata->length = data_end - current;
			metadata->key = metadata->ip_src ^ metadata->ip_dst ^ metadata->src_p ^ metadata->dst_p ^ metadata->ip_protocol;
			bpf_debug("(UDP) src:%u, dst:%u, payload:%d", metadata->src_p, metadata->dst_p, metadata->length);
		}
	}
	else if (iph->protocol == IPPROTO_TCP)
	{
		struct tcphdr *tcph = h;
		if (tcph + 1 > data_end)
		{
			bpf_debug("Invalid TCPv4 packet: L4off:%llu\n",
					  sizeof(struct iphdr) + sizeof(struct tcphdr));
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
			bpf_debug("(TCP) src:%u, dst:%u, payload:%d", metadata->src_p, metadata->dst_p, metadata->length);
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
		bpf_debug("Invalid IPv6 packet: L3off:%llu\n", l3_offset);
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
		bpf_debug("Not handling eth_proto:0x%x\n", eth_proto);
		return XDP_PASS;
	}
	return XDP_PASS;
}

SEC("xdp_stats_kernel")
int xdp_stats(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	struct packet_metadata metadata;
	u16 eth_proto = 0;
	u64 l3_offset = 0;

	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset, &metadata)))
	{
		bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x\n",
				  l3_offset, eth_proto);
		return XDP_PASS;
	}
	//bpf_debug("Reached L3: L3off:%llu proto:0x%x\n", l3_offset, eth_proto);
	handle_eth_protocol(ctx, eth_proto, l3_offset, &metadata);

	// TODO with metadata

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
