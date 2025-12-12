/*
              xxxxxxxxxLabeledxxxxxxxxx
              x                       x
              x                       x
     +--------x---------+             x        +-------------------+
     | Created virtual  |             x        |External interface |
     |    interface     |             x        |                   |
     +--^-----------+---+             x        +-^--------------+--+
Egress  |   Ingress |xxx              x   Egress |              | Ingress
        |           |  x              x          |              v
        |           v  x              xxxxxxxxxxxx              x
                       x                                        x
                       xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

typedef __u32 u32;
typedef __u8 u8;

struct egress_settings  {
    u32 externalInterface;
    u32 egressID;
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct egress_settings);
} settings_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, u32);
} ingress_destinations_map SEC(".maps");



static __always_inline int check_packet_size(void *data, void *data_end, __u32 offset)
{
    return (data + offset <= data_end);
}

SEC("tc")
int egress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Bounds check before accessing packet data
    if (!check_packet_size(data, data_end, 2)) {
        return TC_ACT_SHOT;
    }

    // Load settings
    u32 key = 0;
    struct egress_settings *st;
    st = bpf_map_lookup_elem(&settings_map, &key);
    if (!st) {
        return TC_ACT_SHOT;
    }

    u8 *label = (u8 *)(data + 1);
    u8 tunnel_id = (u8)st->egressID;

    // Add tunnel_id while preserving the 4 rightmost bits
    *label = (tunnel_id << 4) | (*label & 0x0F);

    return bpf_redirect(st->externalInterface, 0); // Redirect to egress path
}


SEC("tc")
int ingress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Bounds check before accessing packet data
    if (!check_packet_size(data, data_end, 2)) {
        return TC_ACT_SHOT;
    }

    u8 *label = (u8 *)(data + 1);
    u8 tunnel_id = *label >> 4;

    // Turn the 4 leftmost bits to zero
    *label = *label & 0x0F;

    u32 key = (u32) tunnel_id;
    u32 *result = bpf_map_lookup_elem(&ingress_destinations_map, &key);
    if (!result) {
        return TC_ACT_SHOT;
    }

    return bpf_redirect(*result, BPF_F_INGRESS); // Redirect to ingress
}

char _license[] SEC("license") = "GPL";