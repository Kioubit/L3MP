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

#define TC_ACT_OK		0
#define TC_ACT_SHOT	    2
#define NULL            0

typedef __u32 u32;


struct egress_settings  {
    u32 externalInterface;
    u32 egressID;
};


struct bpf_map_def SEC("maps") settings_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct egress_settings),
	.max_entries = 1,
};


struct bpf_map_def SEC("maps") ingress_destinations_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 16,
};

SEC("tc_multiplex_egress")
int egress(struct __sk_buff *skb)
{
    // Load settings
    u32 key = 0;
    struct egress_settings *st = 0;
    st = bpf_map_lookup_elem(&settings_map, &key);
    if (st == NULL) {
        return TC_ACT_SHOT;
    }

    unsigned char *data_end = (unsigned char*)(long)skb->data_end;
    unsigned char *data = (unsigned char*)(long)skb->data;

    unsigned char* label = &data[1];
    if (data + 2 > data_end) {
        return TC_ACT_SHOT;
    }

    unsigned char tunnel_id = st->egressID;

    // Add tunnel_id while preserving the 4 rightmost bits
    *label = (tunnel_id << 4) | (*label & 15);

    return bpf_redirect(st->externalInterface, 0); // Redirect to egress path
}


SEC("tc_multiplex_ingress")
int ingress(struct __sk_buff *skb)
{
    unsigned char *data_end = (unsigned char*)(long)skb->data_end;
    unsigned char *data = (unsigned char*)(long)skb->data;

    unsigned char* label = &data[1];
    if (data + 2 > data_end) {
        return TC_ACT_SHOT;
    }

    unsigned char tunnel_id = *label >> 4;

    // Turn the 4 leftmost bits to zero
    *label = *label & 15;

    u32 key = (u32) tunnel_id;
    u32 *result = (u32*) bpf_map_lookup_elem(&ingress_destinations_map, &key);
    if (result == NULL) {
        return TC_ACT_SHOT;
    }

    return bpf_redirect(*result, BPF_F_INGRESS); // Redirect to ingress
}


char _license[] SEC("license") = "GPL";