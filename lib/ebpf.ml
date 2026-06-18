let engine_c_code = {c|#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_RULES 1024

/* Map to hold the dynamic rules */
struct lpf_rule {
    __u32 saddr;
    __u32 smask;
    __u32 daddr;
    __u32 dmask;
    __u16 sport_low;
    __u16 sport_high;
    __u16 dport_low;
    __u16 dport_high;
    __u8 proto;
    __u8 action;       /* 0=PASS, 1=DROP, 2=NAT, 3=RDR */
    __u8 keep_state;
    __u8 log;

    /* NAT/RDR target */
    __u32 xlate_ip;
    __u16 xlate_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct lpf_rule);
} lpf_ingress_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct lpf_rule);
} lpf_egress_rules SEC(".maps");

struct conntrack_tuple {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conntrack_tuple);
    __type(value, __u64);
} lpf_conntrack SEC(".maps");

/* Ringbuf for logging */
struct log_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
    __u8 action;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} lpf_ringbuf SEC(".maps");

static __always_inline void emit_log(struct log_event *ev) {
    bpf_ringbuf_output(&lpf_ringbuf, ev, sizeof(*ev), 0);
}

static __always_inline int process_tcp_state(struct tcphdr *tcp, struct conntrack_tuple *tuple) {
    if (tcp->fin || tcp->rst) {
        bpf_map_delete_elem(&lpf_conntrack, tuple);
        return 1; /* State deleted */
    }
    return 0;
}

static __always_inline int eval_rules(void *data, void *data_end, void *map, int is_ingress) {
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) return is_ingress ? XDP_DROP : TC_ACT_SHOT;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return is_ingress ? XDP_PASS : TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end) return is_ingress ? XDP_DROP : TC_ACT_SHOT;
    if (ip->ihl != 5) return is_ingress ? XDP_PASS : TC_ACT_OK;

    __u8 proto = ip->protocol;
    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;
    __u16 sport = 0, dport = 0;
    struct tcphdr *tcp = NULL;

    if (proto == IPPROTO_TCP) {
        tcp = data + sizeof(*eth) + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            sport = tcp->source;
            dport = tcp->dest;
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) <= data_end) {
            sport = udp->source;
            dport = udp->dest;
        }
    }

    /* 1. Fast path: Stateful Conntrack Lookup */
    struct conntrack_tuple tuple = {
        .src_ip = is_ingress ? daddr : saddr,
        .dst_ip = is_ingress ? saddr : daddr,
        .src_port = is_ingress ? dport : sport,
        .dst_port = is_ingress ? sport : dport,
        .proto = proto
    };

    __u64 *ts = bpf_map_lookup_elem(&lpf_conntrack, &tuple);
    if (ts) {
        if (tcp && process_tcp_state(tcp, &tuple)) {
            /* State was torn down */
        }
        return is_ingress ? XDP_PASS : TC_ACT_OK;
    }

    /* 2. Slow path: Evaluate Rules */
    #pragma unroll
    for (__u32 i = 0; i < MAX_RULES; i++) {
        __u32 key = i;
        struct lpf_rule *r = bpf_map_lookup_elem(map, &key);
        if (!r) break; /* End of rules */
        if (r->action == 255) break; /* Empty slot */

        /* Evaluate */
        if (r->proto != 0 && r->proto != proto) continue;
        if ((saddr & r->smask) != (r->saddr & r->smask)) continue;
        if ((daddr & r->dmask) != (r->daddr & r->dmask)) continue;
        if (r->sport_low != 0 && (bpf_ntohs(sport) < r->sport_low || bpf_ntohs(sport) > r->sport_high)) continue;
        if (r->dport_low != 0 && (bpf_ntohs(dport) < r->dport_low || bpf_ntohs(dport) > r->dport_high)) continue;

        /* Match found! */
        if (r->log) {
            struct log_event ev = {saddr, daddr, sport, dport, proto, r->action};
            emit_log(&ev);
        }

        if (r->keep_state) {
            __u64 now = bpf_ktime_get_ns();
            struct conntrack_tuple new_tuple = { saddr, daddr, sport, dport, proto };
            bpf_map_update_elem(&lpf_conntrack, &new_tuple, &now, BPF_ANY);
        }

        if (r->action == 0) return is_ingress ? XDP_PASS : TC_ACT_OK;
        if (r->action == 1) return is_ingress ? XDP_DROP : TC_ACT_SHOT;

        /* Hardware Accelerated NAT/RDR (Simplified PoC) */
        if (r->action == 2 && tcp && !is_ingress) { /* SNAT on Egress */
            ip->saddr = r->xlate_ip;
            /* Recalculate checksums using bpf_csum_diff... omitted for PoC brevity but structure is here */
            return TC_ACT_OK;
        }
        if (r->action == 3 && tcp && is_ingress) { /* RDR on Ingress */
            ip->daddr = r->xlate_ip;
            tcp->dest = bpf_htons(r->xlate_port);
            return XDP_PASS; /* Pass to kernel stack for actual forwarding in this PoC */
        }
    }

    return is_ingress ? XDP_DROP : TC_ACT_SHOT; /* Default Deny */
}

SEC("xdp")
int lpf_xdp_prog(struct xdp_md *ctx) {
    return eval_rules((void *)(long)ctx->data, (void *)(long)ctx->data_end, &lpf_ingress_rules, 1);
}

SEC("tc")
int lpf_tc_prog(struct __sk_buff *ctx) {
    return eval_rules((void *)(long)ctx->data, (void *)(long)ctx->data_end, &lpf_egress_rules, 0);
}

char _license[] SEC("license") = "GPL";
|c}

let compile_to_c (_ir : Ir.t) = engine_c_code
