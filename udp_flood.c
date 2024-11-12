#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#define THRESHOLD_PACKETS 100    // Maximum packets per interval for a single port
#define TIME_WINDOW 1000000000   // 1 second

struct port_stat {
    __u32 packet_count;
    __u64 last_check;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, struct port_stat);
    __uint(max_entries, 65536);
} port_counters SEC(".maps");

/*  
    Program to avoid packets being spammed to the same port.
    Keeps track of packets arrived for each port using port_stat
    last_check to reset the counter if it has been a while since the first packet has been sent
    not deleting any records since there's only 65k ports (Cannot go over that).
*/
SEC("xdp")
int xdp_udp_flood(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __u16 eth_proto = eth->h_proto;

    __u16 dest_port = 0; // holds dest port if found dest port after parsing headers

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;

        if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

        struct udphdr *udp = (void *)((unsigned char *)ip + (ip->ihl * 4));

        if ((void *)(udp + 1) > data_end) return XDP_PASS;

        dest_port = bpf_ntohs(udp->dest);
    } 
    else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ipv6 = (void *)(eth + 1);

        if ((void *)(ipv6 + 1) > data_end) return XDP_PASS;

        if (ipv6->nexthdr != IPPROTO_UDP) return XDP_PASS;

        struct udphdr *udp = (void *)(ipv6 + 1);

        if ((void *)(udp + 1) > data_end) return XDP_PASS;

        dest_port = bpf_ntohs(udp->dest);
    }

    if(dest_port!=0) {
         struct port_stat *stat = bpf_map_lookup_elem(&port_counters, &dest_port);
        __u64 now = bpf_ktime_get_ns();

        if (stat) {
            if (now - stat->last_check < TIME_WINDOW) {
                stat->packet_count += 1;

                // If packet count exceeds threshold, drop packet
                if (stat->packet_count > THRESHOLD_PACKETS) {
                    bpf_trace_printk("Dropping UDP packet to port %d due to flood\n", dest_port);
                    return XDP_DROP;
                }
            } else {
                stat->packet_count = 1;
                stat->last_check = now;
            }
            bpf_map_update_elem(&port_counters, &dest_port, stat, BPF_ANY);
        } else {
            struct port_stat new_stat = {};
            new_stat.packet_count = 1;
            new_stat.last_check = now;
            bpf_map_update_elem(&port_counters, &dest_port, &new_stat, BPF_ANY);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";