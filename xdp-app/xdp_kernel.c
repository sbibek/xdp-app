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
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

#define DEBUG

#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};


struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,

};

static __always_inline
bool parse_eth(struct ethhdr *eth, void *data_end,
	       u16 *eth_proto, u64 *l3_offset)
{
	u16 eth_type;
	u64 offset;

	offset = sizeof(*eth);
	if ((void *)eth + offset > data_end)
		return false;

	eth_type = eth->h_proto;
	bpf_debug("Debug: eth_type:0x%x\n", bpf_ntohs(eth_type));

	/* Skip non 802.3 Ethertypes */
	if (bpf_ntohs(eth_type) < ETH_P_802_3_MIN)
		return false;

	/* Handle VLAN tagged packet */
	if (eth_type == bpf_htons(ETH_P_8021Q) || eth_type == bpf_htons(ETH_P_8021AD)) {
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

// void parse_protocol(struct xdp_md *ctx, u8 proto, void *hdr){
// 	void *data_end = (void *)(long)ctx->data_end;
// 	struct udphdr *udph;
// 	struct tcphdr *tcph;

// 	switch(proto) {
// 		case IPPROTO_UDP:
// 			udph = hdr;
// 			if (udph + 1 > data_end) {
// 				bpf_debug("Invalid UDPv4 packet: L4off:%llu\n",
// 					sizeof(struct iphdr) + sizeof(struct udphdr));
// 			} else {
// 				bpf_debug("valud UDP packet: ");
// 			}
// 			break;

// 		case IPPROTO_TCP:
// 			tcph = hdr;
// 			if (tcph + 1 > data_end) {
// 				bpf_debug("Invalid TCPv4 packet: L4off:%llu\n",
// 					sizeof(struct iphdr) + sizeof(struct tcphdr));
// 			} else {
// 				bpf_debug("valud TCP packet: ");
// 			}
// 			break;
// 	}
// }

static __always_inline
u32 parse_ipv4(struct xdp_md *ctx, u64 l3_offset, struct iphdr *iph)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	iph = data + l3_offset;
	u32 ip_src; /* type need to match map */

	/* Hint: +1 is sizeof(struct iphdr) */
	if (iph + 1 > data_end) {
		bpf_debug("Invalid IPv4 packet: L3off:%llu\n", l3_offset);
		return XDP_ABORTED;
	}

	ip_src = iph->saddr;
	ip_src = bpf_ntohl(ip_src); 

	bpf_debug("Valid IPv4 packet: raw saddr:0x%x\n", ip_src);

	// parse_protocol(ctx, iph->protocol, iph + 1);

	return 0;
}

static __always_inline
void parse_ipv6(struct xdp_md *ctx, u64 l3_offset, struct ipv6hdr *iph)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	iph = data + l3_offset;

	/* Hint: +1 is sizeof(struct iphdr) */
	if (iph + 1 > data_end) {
		bpf_debug("Invalid IPv6 packet: L3off:%llu\n", l3_offset);
		return;
	}
	bpf_debug("Valid IPv6 packet extracted");
}

static __always_inline
u32 handle_eth_protocol(struct xdp_md *ctx, u16 eth_proto, u64 l3_offset)
{
	struct iphdr ipv4hdr;
	struct ipv6hdr _ipv6hdr;
	switch (eth_proto) {
	case ETH_P_IP:
		return parse_ipv4(ctx, l3_offset, &ipv4hdr);
		break;
	case ETH_P_IPV6: 
		parse_ipv6(ctx, l3_offset, &_ipv6hdr);
		return 0;
	default:
		bpf_debug("Not handling eth_proto:0x%x\n", eth_proto);
		return XDP_PASS;
	}
	return XDP_PASS;
}



SEC("xdp_stats_kernel")
int  xdp_stats(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	u16 eth_proto = 0;
	u64 l3_offset = 0;

	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset))) {
		bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x\n",
			  l3_offset, eth_proto);
		return XDP_PASS;
	}
	bpf_debug("Reached L3: L3off:%llu proto:0x%x\n", l3_offset, eth_proto);
	handle_eth_protocol(ctx, eth_proto, l3_offset);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
