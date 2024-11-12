#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>


#define MAX_PACKET_SIZE 1000  // not sure about a good limit, can modify it later
#define MAX_PACKET_RATE 100
#define INTERVAL_NS 1000000000 // 1 second 
#define ICMP_TYPE 1

struct rate_limit_data {
    __u64 last_reset_time; 
    __u32 packet_count;     
}; 

// map to rate limit packets globally, stores both count of packets and time when the count started  
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rate_limit_data);
} rate_limit_map SEC(".maps");


SEC("xdp")
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
        struct rate_limit_data *rate_data = bpf_map_lookup_elem(&rate_limit_map, &key);
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
            bpf_map_update_elem(&rate_limit_map, &key, rate_data, BPF_ANY);
        } else {
            struct rate_limit_data new_data = {
                .last_reset_time = now,
                .packet_count = 1
            };
            bpf_map_update_elem(&rate_limit_map, &key, &new_data, BPF_ANY);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";