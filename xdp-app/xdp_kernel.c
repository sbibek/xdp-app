/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common_kern_user.h"

#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

SEC("xdp_stats_kernel")
int  xdp_stats(struct xdp_md *ctx)
{
	struct datarec *rec;
	__u32 key = XDP_PASS;

	// lookup and get the element for key from the map
	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);

	// if nothing was found then abort	
	if (!rec) {
		return XDP_ABORTED;
	}

	// else update the record with the goodies	
	lock_xadd(&rec->rx_packets, 1);
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	lock_xadd(&rec->rx_bytes, data_end-data);
      

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
