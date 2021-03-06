/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader and stats program\n"
	" - Allows selecting BPF section --progsec name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "common_kern_user.h"
#include "bpf_util.h" /* bpf_num_possible_cpus */

static const char *default_filename = "xdp_kernel.o";
static const char *default_progsec = "xdp_stats";

#define MAX_U64 18446744073709551615

static const struct option_wrapper long_options[] = {
	{{"help", no_argument, NULL, 'h'},
	 "Show help",
	 false},

	{{"dev", required_argument, NULL, 'd'},
	 "Operate on device <ifname>",
	 "<ifname>",
	 true},

	{{"skb-mode", no_argument, NULL, 'S'},
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument, NULL, 'N'},
	 "Install XDP program in native mode"},

	{{"auto-mode", no_argument, NULL, 'A'},
	 "Auto-detect SKB or native mode"},

	{{"force", no_argument, NULL, 'F'},
	 "Force install, replacing existing program on interface"},

	{{"unload", no_argument, NULL, 'U'},
	 "Unload XDP program instead of loading"},

	{{"quiet", no_argument, NULL, 'q'},
	 "Quiet mode (no output)"},

	{{"filename", required_argument, NULL, 1},
	 "Load program from <file>",
	 "<file>"},

	{{"progsec", required_argument, NULL, 2},
	 "Load program in <section> of the ELF file",
	 "<section>"},

	{{0, 0, NULL, 0}}};

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;

	// find bpf object using bpf map
	map = bpf_object__find_map_by_name(bpf_obj, mapname);
	if (!map)
	{
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
		goto out;
	}

	map_fd = bpf_map__fd(map);
out:
	return map_fd;
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0)
	{
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (__u64)t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

struct record
{
	__u64 timestamp;
	struct datarec total; /* defined in common_kern_user.h */
};

struct stats_record
{
	struct record stats[1]; /* Assignment#2: Hint */
};

static double calc_period(struct record *r, struct record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double)period / NANOSEC_PER_SEC);

	return period_;
}

static double claculate_period(__u64 t1, __u64 t2) {
	double period_ = 0;
	__u64 period = 0;

	period = t2 - t1;
	if (period > 0)
		period_ = ((double)period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print(struct stats_record *stats_rec,
						struct stats_record *stats_prev)
{
	struct record *rec, *prev;
	double period;
	__u64 packets;
	double pps; /* packets per sec */

	__u64 bytes;
	double mbps;

	/* Assignment#2: Print other XDP actions stats  */
	{
		char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
					" %'11lld bytes"
					" period:%f\n";
		const char *action = action2str(XDP_PASS);
		rec = &stats_rec->stats[0];
		prev = &stats_prev->stats[0];

		period = calc_period(rec, prev);
		if (period == 0)
			return;

		packets = rec->total.rx_packets - prev->total.rx_packets;
		pps = packets / period;

		bytes = (rec->total.rx_bytes - prev->total.rx_bytes);

		printf(fmt, action, rec->total.rx_packets, pps, bytes, period);
	}
}

/* BPF_MAP_TYPE_ARRAY */
void map_get_value_array(int fd, __u32 key, struct datarec *value)
{
	if ((bpf_map_lookup_elem(fd, &key, value)) != 0)
	{
		fprintf(stderr,
				"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
	}
}

void map_get_total_keys(int fd, struct total_keys *value) {
	__u32 key = TOTAL_KEYS;

	if ((bpf_map_lookup_elem(fd, &key, value)) != 0)
	{
		// the lookup will fail for no keys at all	
		// so lets just return the 0 valued 
		struct total_keys tk = {.total_keys = 0};
		value = &tk;
	}
}

void update_flow_history(int fd, struct flow_key_info *fki, struct flows_info *info){
	struct flows_info fi = {0};
	if ((bpf_map_lookup_elem(fd, &fki->key, &fi)) != 0){
		// this means we have to create a new entry
		bpf_map_update_elem(fd, &fki->key, info, BPF_ANY);
	} else {
		// we already have it means we just need to update it
		fi.timestamp = info->timestamp;
		fi.totalPackets = info->totalPackets;
		fi.totalBytes = info->totalBytes;
		fi.totalRxBytes = info->totalRxBytes;
		fi.totalTxBytes = info->totalTxBytes;
		fi.totalTtl = info->totalTtl;
		fi.totalEce = info->totalEce;
		fi.totalUrg = info->totalUrg;
		fi.totalAck = info->totalAck;
		fi.totalPsh = info->totalPsh;
		fi.totalRst = info->totalRst;
		fi.totalSyn = info->totalSyn;
		fi.totalFin = info->totalFin;
		bpf_map_update_elem(fd, &fki->key, &fi, BPF_ANY);
	}
}

__u64 __diffu64Adjusted(__u64 new, __u64 old) {
	if(old > new) {
		return MAX_U64 - old + new;
	} else {
		return new - old;
	}
}

void process(struct flow_key_info *fki, struct flows_info *history, struct flows_info *current, double period){
	double pps = __diffu64Adjusted(current->totalPackets,history->totalPackets)/(period*1000000);
	double bps = __diffu64Adjusted(current->totalBytes, history->totalBytes)/ period;
	double Mbitps = bps * 8/(1024*1024);
	double synRate = __diffu64Adjusted(current->totalSyn , history->totalSyn)/period;
	double ackRate = __diffu64Adjusted(current->totalAck , history->totalAck)/period;
	double pshRate = __diffu64Adjusted(current->totalPsh , history->totalPsh)/period;
	double rstRate = __diffu64Adjusted(current->totalRst , history->totalRst)/period;
	double finRate = __diffu64Adjusted(current->totalFin , history->totalFin)/period;
	if(Mbitps < 1024) {
		printf("%u <-> %u (%llu packets) (%llu bytes) %f million pps(*), %f Mbits/sec(**), %f seconds\n synrate: %f, ackrate: %f, pshrate: %f, rstrate: %f, finrate: %f chksum: %u\n", fki->src_p, fki->dst_p, history->totalPackets, history->totalBytes, pps, Mbitps, period,
	synRate, ackRate, pshRate, rstRate, finRate, ~current->checksum);
	} else {
		printf("%u <-> %u (%llu packets) (%llu bytes) %f million pps(*), %f Gbits/sec(**), %f seconds\n synrate: %f, ackrate: %f, pshrate: %f, rstrate: %f, finrate: %f, chksum: %u\n", fki->src_p, fki->dst_p, history->totalPackets, history->totalBytes, pps, Mbitps/1024, period,
	synRate, ackRate, pshRate, rstRate, finRate, ~current->checksum);

	}
}

void map_get_keys(int fd, __u32 totalKeys, int flowsfd, int flowsbackupfd)
{
	for (__u32 i = 0; i < totalKeys; i++)
	{
		struct flow_key_info value = {0};
		if ((bpf_map_lookup_elem(fd, &i, &value)) != 0)
		{
			printf("unable to lookup");
		}
		else
		{
			//printf("keys:: %u, %u, %u\n", value.key, value.src_p, value.dst_p);

			struct flows_info finfo = {0};
			if ((bpf_map_lookup_elem(flowsfd, &value.key, &finfo)) != 0)
			{
					printf(
				"unable to get finfo"
					);
			} else {
				//printf("total packets: %llu, total bytes: %llu\n", finfo.totalPackets, finfo.totalBytes);
				// now we check the history
				finfo.timestamp = gettime();
				struct flows_info history = {0};
				if(bpf_map_lookup_elem(flowsbackupfd, &value.key, &history) != 0) {
					//printf("no backup found for this flow, so creating backup**\n");
					update_flow_history(flowsbackupfd, &value, &finfo);
				} else {
					// means there is backup already for this
					double period = claculate_period(history.timestamp,finfo.timestamp);
					process(&value, &history, &finfo, period);
					// printf("%llu perid calculated %f\n",history.timestamp, period);
					// now lets update it with the newer one
					update_flow_history(flowsbackupfd, &value, &finfo);
				}
			}
		}
	}
}

/* BPF_MAP_TYPE_PERCPU_ARRAY */
void map_get_value_percpu_array(int fd, __u32 key, struct datarec *value)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	// unsigned int nr_cpus = bpf_num_possible_cpus();
	// struct datarec values[nr_cpus];

	fprintf(stderr, "ERR: %s() not impl. see assignment#3", __func__);
}

static bool map_collect(int fd, __u32 map_type, __u32 key, struct record *rec)
{
	struct datarec value;

	/* Get time as close as possible to reading map contents */
	rec->timestamp = gettime();

	switch (map_type)
	{
	case BPF_MAP_TYPE_ARRAY:
		map_get_value_array(fd, key, &value);
		break;
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		/* fall-through */
	default:
		fprintf(stderr, "ERR: Unknown map_type(%u) cannot handle\n",
				map_type);
		return false;
		break;
	}

	/* Assignment#1: Add byte counters */
	rec->total.rx_packets = value.rx_packets;
	rec->total.rx_bytes = value.rx_bytes;
	return true;
}

static void stats_collect(int map_fd, __u32 map_type,
						  struct stats_record *stats_rec)
{
	/* Assignment#2: Collect other XDP actions stats  */
	__u32 key = XDP_PASS;

	map_collect(map_fd, map_type, key, &stats_rec->stats[0]);
}

static void collect(int totalkeysfd, int flowkeysfd, int flowsfd, int flowsbackupfd){
	struct total_keys tk = {0};
	map_get_total_keys(totalkeysfd, &tk);
	printf("total keys %u\n", tk.total_keys);
	map_get_keys(flowkeysfd,tk.total_keys, flowsfd, flowsbackupfd);
}

static void stats_poll(int map_fd, __u32 map_type, int interval)
{
	struct stats_record prev, record = {0};

	setlocale(LC_NUMERIC, "en_US");

	// stats_collect(map_fd, map_type, &record);
	usleep(1000000 / 4);

	while (1)
	{
		prev = record; /* struct copy */
		stats_collect(map_fd, map_type, &record);
		stats_print(&record, &prev);
		sleep(interval);
	}
}

static void __poll(int totalflowsfd, int flowkeysfd, int flowsfd, int flowsbackupfd, int interval)
{
	setlocale(LC_NUMERIC, "en_US");
	while (1)
	{
		collect(totalflowsfd, flowkeysfd, flowsfd, flowsbackupfd);
		sleep(interval);
	}
}

static int __check_map_fd_info(int map_fd, struct bpf_map_info *info,
							   struct bpf_map_info *exp)
{
	__u32 info_len = sizeof(*info);
	int err;

	if (map_fd < 0)
		return EXIT_FAIL;

	/* BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
	if (err)
	{
		fprintf(stderr, "ERR: %s() can't get info - %s\n",
				__func__, strerror(errno));
		return EXIT_FAIL_BPF;
	}

	if (exp->key_size && exp->key_size != info->key_size)
	{
		fprintf(stderr, "ERR: %s() "
						"Map key size(%d) mismatch expected size(%d)\n",
				__func__, info->key_size, exp->key_size);
		return EXIT_FAIL;
	}
	if (exp->value_size && exp->value_size != info->value_size)
	{
		fprintf(stderr, "ERR: %s() "
						"Map value size(%d) mismatch expected size(%d)\n",
				__func__, info->value_size, exp->value_size);
		return EXIT_FAIL;
	}
	if (exp->max_entries && exp->max_entries != info->max_entries)
	{
		fprintf(stderr, "ERR: %s() "
						"Map max_entries(%d) mismatch expected size(%d)\n",
				__func__, info->max_entries, exp->max_entries);
		return EXIT_FAIL;
	}
	if (exp->type && exp->type != info->type)
	{
		fprintf(stderr, "ERR: %s() "
						"Map type(%d) mismatch expected type(%d)\n",
				__func__, info->type, exp->type);
		return EXIT_FAIL;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_map_info map_expect = {0};
	struct bpf_map_info info = {0};
	struct bpf_object *bpf_obj;
	int stats_map_fd;

	struct bpf_map_info map_expect_totalkeys = {0}, map_expect_flowskeys = {0}, map_expect_flows = {0};
	int totalKeysFd, flowKeysFd, flowsFd, flowsBackupFd;
	struct bpf_map_info totalkeysinfo = {0}, flowkeysinfo = {0}, flowsinfo = {0}, flowsbackupinfo={0};
	int interval = 2;
	int err;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex = -1,
		.do_unload = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	strncpy(cfg.progsec, default_progsec, sizeof(cfg.progsec));
	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1)
	{
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload)
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	bpf_obj = load_bpf_and_xdp_attach(&cfg);
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	if (verbose)
	{
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
			   cfg.filename, cfg.progsec);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
			   cfg.ifname, cfg.ifindex);
	}

	stats_map_fd = find_map_fd(bpf_obj, "xdp_stats_map");
	totalKeysFd = find_map_fd(bpf_obj, "xdp_total_keys");
	flowKeysFd = find_map_fd(bpf_obj, "xdp_flow_keys");
	flowsFd = find_map_fd(bpf_obj, "xdp_flows");
	flowsBackupFd = find_map_fd(bpf_obj, "xdp_flows_history");

	// detach and return if any of the maps are not found;
	if (stats_map_fd < 0 || totalKeysFd < 0 || flowKeysFd < 0 || flowsFd < 0 || flowsBackupFd < 0)
	{
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}

	map_expect.key_size = sizeof(__u32);
	map_expect.value_size = sizeof(struct datarec);
	map_expect.max_entries = XDP_ACTION_MAX;

	map_expect_totalkeys.key_size = sizeof(__u32);
	map_expect_totalkeys.value_size = sizeof(struct total_keys);
	map_expect_totalkeys.max_entries = MAX_ENTRIES_TOTAL_KEYS;

	map_expect_flowskeys.key_size = sizeof(__u32);
	map_expect_flowskeys.value_size = sizeof(struct flow_key_info);
	map_expect_flowskeys.max_entries = MAX_ENTRIES_FLOW_KEYS;

	map_expect_flows.key_size = sizeof(__u32);
	map_expect_flows.value_size = sizeof(struct flows_info);
	map_expect_flows.max_entries = MAX_ENTRIES_FLOWS;

	err = __check_map_fd_info(stats_map_fd, &info, &map_expect);
	if (err ||
		__check_map_fd_info(totalKeysFd, &totalkeysinfo, &map_expect_totalkeys) ||
		__check_map_fd_info(flowKeysFd, &flowkeysinfo, &map_expect_flowskeys) ||
		__check_map_fd_info(flowsFd, &flowsinfo, &map_expect_flows) ||
		__check_map_fd_info(flowsBackupFd, &flowsbackupinfo, &map_expect_flows))
	{
		fprintf(stderr, "ERR: map via FD not compatible\n");
		return err;
	}
	if (verbose)
	{
		printf("\nCollecting stats from BPF map\n");
		printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
			   " key_size:%d value_size:%d max_entries:%d\n",
			   info.type, info.id, info.name,
			   info.key_size, info.value_size, info.max_entries);
	}

	printf("\n######################### ATTACHED ##############\n");

	// stats_poll(stats_map_fd, info.type, interval);
	__poll(totalKeysFd, flowKeysFd, flowsFd, flowsBackupFd, interval);
	return EXIT_OK;
}
