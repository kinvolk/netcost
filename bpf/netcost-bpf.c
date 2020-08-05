#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>

#include <bpf/bpf_helpers.h>

#include "bpf_legacy.h"

#define offsetof(type, member)	__builtin_offsetof(type, member)


#ifndef printt
#define printt(fmt, ...)                                               \
        ({                                                              \
                char ____fmt[] = fmt;                                   \
                bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);  \
        })
#endif

struct bpf_map_def SEC("maps") ingress_ip = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = 8, // int + IPv4
	.value_size = sizeof(__u64),
	.max_entries = 256,
	.map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") egress_ip = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = 8, // int + IPv4
	.value_size = sizeof(__u64),
	.max_entries = 256,
	.map_flags = BPF_F_NO_PREALLOC,
};

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
	__u64 nhoff = ETH_HLEN;

	if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
		return 0;

	__u32 lpm_key[2];
	__u64 *value;

	lpm_key[0] = 32;

	if (skb->pkt_type == PACKET_OUTGOING) {
		int ret = bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &lpm_key[1], 4);
		if (ret < 0) {
			return 0;
		}
		value = bpf_map_lookup_elem(&egress_ip, lpm_key);
	} else {
		int ret = bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &lpm_key[1], 4);
		if (ret < 0) {
			return 0;
		}
		value = bpf_map_lookup_elem(&ingress_ip, lpm_key);
	}

	if (value)
		__sync_fetch_and_add(value, skb->len);

	return 0;
}

char _license[] SEC("license") = "GPL";
