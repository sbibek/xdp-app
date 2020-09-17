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
/* logs in /sys/kernel/debug/tracing/trace_pipe
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


static __always_inline
void checksum(struct xdp_md *ctx, __u32 *offset, __u32 *val)
{
	 void *data_end = (void *)(long)ctx->data_end;
	 void *data = (void *)(long)ctx->data;

	 __u8 *current = data + *offset;
		int i = 0;
	 for(i=0;i<9000;i++) {
		 if(current + 1 > data_end) break;

		 *val += *current;
		 ++current;
	 }

	// if (data + *offset > data_end)
	// {
	// 	*val = 0;
	// 	return;
	// }

	// // else
	// __u32 sum = 0;

	// for (int i = 0; i < 1500; i++)
	// {
	// 	if (data + *offset < data_end)
	// 	{
	// 		sum += *((__u8 *)data + *offset);
	// 		++(*offset);
	// 	}
	// }

	// // because the offset will not increase as soon as it is equal to the data_end
	// // so adding the last value
	// sum += *((__u8 *)data + *offset);

	// *val = sum;

	// __u8 *current = data + *offset;
	// if (current + 1 > data_end){
	// 	*val = 0;
	// 	return;
	// } else {
	// 	*val = *(current);
	// }
}

SEC("xdp_stats_kernel")
int xdp_stats(struct xdp_md *ctx)
{
	// get the start and end of the packet
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	__u32 offset = 0;

	struct ethhdr *ethernet_header = data;
	struct iphdr *ipv4hdr;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;
	__u32 payload_checksum = 0;

	/** START of ETH HEADER parsing **/

	// now lets first parse the ethernet header information
	// first offset is the size of the ethernet header information
	offset = sizeof(struct ethhdr);
	// now we check to make sure that we won't run beyond the packet end
	if (data + offset > data_end)
	{
		// this means we reached more than we need to so just abort
		return XDP_PASS;
	}

	// extracting the ethernet type information
	__u16 eth_type = bpf_ntohs(ethernet_header->h_proto);

	// we will just handle specific type of ethernet packets
	if (eth_type < ETH_P_802_3_MIN)
		return XDP_PASS;

	// we will make a check if the packets are vlan packets, if not we move forward
	if (eth_type == bpf_htons(ETH_P_8021Q) || eth_type == bpf_htons(ETH_P_8021AD))
	{
		struct vlan_hdr *vlan = data + offset;
		offset += sizeof(struct vlan_hdr);
		// thing is we should be within limits when extracting the vlan header info
		if (data + offset > data_end)
			return XDP_PASS;

		// now we update the ethernet type information from vlan
		eth_type = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
	}
	/** END of ETH HEADER parsing **/

// else we know that we can move forward as we are within the data limit
#ifdef DEBUG
	bpf_debug("eth-type:0x%x\n", eth_type);
#endif

	/* START of IP parsing */
	if (eth_type == ETH_P_IP)
	{
		// means this is a IP header
		ipv4hdr = data + offset;
		// now we need to check the data bounds
		if (ipv4hdr + 1 > data_end)
			return XDP_PASS;

		// now we update the offset
		offset += sizeof(struct iphdr);

#ifdef DEBUG
		bpf_debug("ip-proto:%u\n", ipv4hdr->protocol);
#endif

		if (ipv4hdr->protocol == IPPROTO_TCP)
		{
			// so this is a TCP packet
			tcphdr = data + offset;
			// now we check the data bounds
			if (tcphdr + 1 > data_end)
				return XDP_PASS;
			// now we update the offset
			offset += sizeof(struct tcphdr);
			checksum(ctx, &offset, &payload_checksum);
			// __u8 *t = (data+offset);

			// if(t+1 > data_end) return XDP_PASS;

			// payload_checksum = *t;
#ifdef DEBUG
			bpf_debug("payload-checksum:%u\n", payload_checksum);
#endif
		}
		else if (ipv4hdr->protocol == IPPROTO_UDP)
		{
			// this is a UDP packet
			udphdr = data + offset;
			// now we make the data bounds check
			if (udphdr + 1 > data_end)
				return XDP_PASS;
			// now we update the offset
			offset += sizeof(struct udphdr);
			checksum(ctx, &offset, &payload_checksum);
		}

		/** END of IP parsing **/
	}
	else
	{
		// we just pass for now for IPV6 or other unknown protocol
		return XDP_PASS;
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
