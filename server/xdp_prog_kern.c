/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* ABD constants */
#include "../common/common_abd.h"

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} map_tag SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, 1);
	__uint(max_entries, 1);
} map_value SEC(".maps");

/* Per-IP counters */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct in6_addr);
	__type(value, __u32);
	__uint(max_entries, 1);
} map_counters SEC(".maps");

static __always_inline int parse_abdmsg(struct hdr_cursor *nh,
										void *data_end,
										struct abdmsg **msg)
{
	struct abdmsg *m = nh->pos;

	if (m + 1 > data_end)
		return -1;

	nh->pos = m + 1;
	*msg = m;

	// Ensure the message type is valid
	if (m->type >= ABD_READ_ACK)
		return -1;

	return 0;
}

static __always_inline int handle_abd_read(struct ipv6hdr *ipv6hdr, struct abdmsg *msg)
{
	__u32 zero = 0;

	__u32 *counter = bpf_map_lookup_elem(&map_counters, &ipv6hdr->saddr);
	if (!counter)
	{
		// Initialize the counter to zero
		if (bpf_map_update_elem(&map_counters, &ipv6hdr->saddr, &zero, BPF_ANY) < 0)
		{
			bpf_printk("Failed to initialize counter for %pI6c\n", &ipv6hdr->saddr);
			return -1;
		}
		counter = bpf_map_lookup_elem(&map_counters, &ipv6hdr->saddr);
		if (!counter)
		{
			bpf_printk("Failed to lookup counter for %pI6c\n", &ipv6hdr->saddr);
			return -1;
		}
	}

	if (msg->counter < *counter)
	{
		bpf_printk("Dropping stale read request from %pI6c with counter %u\n",
				   &ipv6hdr->saddr, msg->counter);
		return -1;
	}

	if (bpf_map_update_elem(&map_counters, &ipv6hdr->saddr, &msg->counter, BPF_ANY) < 0)
	{
		bpf_printk("Failed to update counter for %pI6c\n", &ipv6hdr->saddr);
		return -1;
	}

	__u32 *val = bpf_map_lookup_elem(&map_value, &zero);
	if (!val)
	{
		// Initialize the value to zero
		if (bpf_map_update_elem(&map_value, &zero, &zero, BPF_ANY) < 0)
		{
			bpf_printk("Failed to initialize value\n");
			return -1;
		}
		val = bpf_map_lookup_elem(&map_value, &zero);
		if (!val)
		{
			bpf_printk("Failed to lookup value\n");
			return -1;
		}
	}

	/* Prepare ABD response */
	msg->type = ABD_READ_ACK;
	// msg->tag unchanged
	msg->value = *val;
	// msg->counter unchanged

	return 0;
}

static __always_inline int handle_abd_write(struct ipv6hdr *ipv6hdr, struct abdmsg *msg)
{
	__u32 zero = 0;

	__u32 *counter = bpf_map_lookup_elem(&map_counters, &ipv6hdr->saddr);
	if (!counter)
	{
		// Initialize the counter to zero
		if (bpf_map_update_elem(&map_counters, &ipv6hdr->saddr, &zero, BPF_ANY) < 0)
		{
			bpf_printk("Failed to initialize counter for %pI6c\n", &ipv6hdr->saddr);
			return -1;
		}
		counter = bpf_map_lookup_elem(&map_counters, &ipv6hdr->saddr);
		if (!counter)
		{
			bpf_printk("Failed to lookup counter for %pI6c\n", &ipv6hdr->saddr);
			return -1;
		}
	}

	if (msg->counter <= *counter)
	{
		bpf_printk("Dropping stale write request from %pI6c with counter %u\n",
				   &ipv6hdr->saddr, msg->counter);
		return -1;
	}

	if (bpf_map_update_elem(&map_counters, &ipv6hdr->saddr, &msg->counter, BPF_ANY) < 0)
	{
		bpf_printk("Failed to update counter for %pI6c\n", &ipv6hdr->saddr);
		return -1;
	}

	__u32 *tag = bpf_map_lookup_elem(&map_tag, &zero);
	if (!tag)
	{
		// Initialize the tag to zero
		if (bpf_map_update_elem(&map_tag, &zero, &zero, BPF_ANY) < 0)
		{
			bpf_printk("Failed to initialize tag\n");
			return -1;
		}
		tag = bpf_map_lookup_elem(&map_tag, &zero);
		if (!tag)
		{
			bpf_printk("Failed to lookup tag\n");
			return -1;
		}
	}

	if (msg->tag <= *tag)
	{
		bpf_printk("Dropping stale write request from %pI6c with tag %u\n",
				   &ipv6hdr->saddr, msg->tag);
		return -1;
	}

	// Update the tag
	if (bpf_map_update_elem(&map_tag, &zero, &msg->tag, BPF_ANY) < 0)
	{
		bpf_printk("Failed to update tag\n");
		return -1;
	}
	tag = bpf_map_lookup_elem(&map_tag, &zero);

	// Update the value
	if (bpf_map_update_elem(&map_value, &zero, &msg->value, BPF_ANY) < 0)
	{
		bpf_printk("Failed to update value\n");
		return -1;
	}

	/* Prepare ABD response */
	msg->type = ABD_WRITE_ACK;
	msg->tag = 0;
	msg->value = 0;
	// msg->counter unchanged

	return 0;
}

SEC("xdp")
int xdp_abd_server(struct xdp_md *ctx)
{
	int action = XDP_PASS;
	int eth_type, ip_type;
	struct ethhdr *eth;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct abdmsg *msg;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = {.pos = data};

	/* Parse Ethernet and IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
	{
		action = XDP_ABORTED;
		goto out;
	}
	if (eth_type == bpf_htons(ETH_P_IPV6))
	{
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	}
	else
	{
		goto out;
	}

	/* Parse UDP header */
	if (ip_type != IPPROTO_UDP)
		goto out;

	if (parse_udphdr(&nh, data_end, &udphdr) < 0)
	{
		action = XDP_ABORTED;
		goto out;
	}

	/* Check if the UDP packet is coming on the right port */
	if (udphdr->dest != bpf_htons(ABD_UDP_PORT))
		goto out;

	/* Parse ABD message */
	if (parse_abdmsg(&nh, data_end, &msg) < 0)
		goto out;
	bpf_printk("ABD message: type=%d, tag=%u, value=%u, counter=%u\n",
			   msg->type, msg->tag, msg->value, msg->counter);

	/* Handle ABD message */
	int ret;
	if (msg->type == ABD_READ)
	{
		ret = handle_abd_read(ipv6hdr, msg);
	}
	else if (msg->type == ABD_WRITE)
	{
		ret = handle_abd_write(ipv6hdr, msg);
	}
	else
	{
		goto out;
	}
	if (ret < 0)
		goto out;

	/* Swap Ethernet source and destination MAC addresses */
	swap_src_dst_mac(eth);

	/* Swap IPv6 source and destination addresses */
	swap_src_dst_ipv6(ipv6hdr);

	/* Swap UDP source and destination ports */
	swap_src_dst_udp(udphdr);

	/* Recalculate the UDP checksum */
	udphdr->check = 0;
	udphdr->check = calc_ipv6_udp_csum(ipv6hdr, udphdr, data_end);

	action = XDP_TX;
out:
	return xdp_stats_record_action(ctx, action);
}

// Dummy function must be loaded on the other interface
SEC("xdp")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
