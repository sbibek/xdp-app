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


static __always_inline __u32 sum16(void *data, void *data_end){
	__u8* current = data;
	__u32 sum = 0;

	int i;
	for(i=0;i<1500;i++){
		sum += *current;
		if(current < data_end) ++current;
		else break;
	}

	return sum;
}


SEC("xdp_stats_kernel")
int xdp_stats(struct xdp_md *ctx)
{
	// get the start and end of the packet
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	sum16(data, data_end);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
