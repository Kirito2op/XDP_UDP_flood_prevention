#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bcc/proto.h>

#define MAX_PACKET_SIZE 1000  // not sure about a good limit, can modify it later
#define MAX_PACKET_RATE 100
#define INTERVAL_NS 1000000000 // 1 second 
#define ICMP_TYPE 1

struct rate_limit_data {
    __u64 last_reset_time; 
    __u32 packet_count;     
}; 

BPF_HASH(rate_limit_map, __u32, struct rate_limit_data, 1);// map to rate limit packets globally, stores both count of packets and time when the count started  

int icmp_flood(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    if (ip->protocol != ICMP_TYPE) { // 1 == ICMP packets
        return XDP_PASS;
    }

    struct icmphdr *icmp = (void *)(ip + 1);
    if ((void *)(icmp + 1) > data_end) {
        return XDP_PASS;
    }
    if (icmp->type == 8) { // 8 == icmp echo request packets
        int packet_size = data_end - data;

        if (packet_size > MAX_PACKET_SIZE) {
            return XDP_DROP;
        }
        __u32 key = 0;
        struct rate_limit_data *rate_data = (struct rate_limit_data *)rate_limit_map.lookup(&key);
        __u64 now = bpf_ktime_get_ns();

        if (rate_data) {
            __u64 elapsed = now - rate_data->last_reset_time;

            if (elapsed >= INTERVAL_NS) { // if too much time has passed since the first packet arrival time.
                rate_data->packet_count = 1;
                rate_data->last_reset_time = now;
            } else {
                if (rate_data->packet_count >= MAX_PACKET_RATE) {
                    return XDP_DROP;
                }
                rate_data->packet_count++;
            }
            rate_limit_map.update(&key, rate_data);
        } else {
            struct rate_limit_data new_data = {
                .last_reset_time = now,
                .packet_count = 1
            };
            rate_limit_map.update(&key, &new_data);
        }
    }

    return XDP_PASS;
}
