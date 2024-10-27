#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bcc/proto.h>

#define THRESHOLD_PACKETS 100    // Maximum packets per interval for a single port
#define TIME_WINDOW 1000000000   // 1 second

struct port_stat {
    __u32 packet_count;
    __u64 last_check;
};

BPF_HASH(port_counters, __u16, struct port_stat);

int xdp_udp_flood(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __u16 eth_proto = eth->h_proto;

    __u16 dest_port = 0; // holds dest port if found dest port after parsing headers

    if (eth_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;

        if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

        struct udphdr *udp = (void *)((unsigned char *)ip + (ip->ihl * 4));

        if ((void *)(udp + 1) > data_end) return XDP_PASS;

        dest_port = bpf_ntohs(udp->dest);
    } 
    else if (eth_proto == __constant_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ipv6 = (void *)(eth + 1);

        if ((void *)(ipv6 + 1) > data_end) return XDP_PASS;

        if (ipv6->nexthdr != IPPROTO_UDP) return XDP_PASS;

        struct udphdr *udp = (void *)(ipv6 + 1);

        if ((void *)(udp + 1) > data_end) return XDP_PASS;

        dest_port = bpf_ntohs(udp->dest);
    }

    if(dest_port!=0) {
         struct port_stat *stat = port_counters.lookup(&dest_port);
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
        } else {
            struct port_stat new_stat = {};
            new_stat.packet_count = 1;
            new_stat.last_check = now;
            port_counters.update(&dest_port, &new_stat);
        }
    }

    return XDP_PASS;
}
