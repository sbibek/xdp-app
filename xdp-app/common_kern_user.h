#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif
