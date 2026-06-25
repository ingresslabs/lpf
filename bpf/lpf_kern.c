// lpf eBPF datapath: XDP, TC, cgroup_skb, and LSM match engines.
//
// Policy lives in BPF maps (created/populated by `lpf ebpf load`); programs
// are generic and never recompiled per policy. Four hook points:
//   XDP ingress  – L3/L4 filtering + CIDR set membership (fastest path)
//   TC egress    – L3/L4 filtering + CIDR + IPv6 + header rewrite (NAT)
//   cgroup_skb   – per-cgroup identity filtering (ingress + egress)
//   LSM connect  – per-process DNS/connect identity enforcement
//
// Maps (from lib/ebpf.ml):
//   lpf_meta[0]         = version
//   lpf_meta[1]         = default action (1=pass, 0=deny)
//   lpf_meta[2]         = rule_count
//   lpf_rules[i]        = { verdict; proto; dport_lo; dport_hi; saddr_set; daddr_set }
//   lpf_counters[i]     = { packets; bytes }
//   lpf_cidr4 (LPM)     = source/destination CIDR set membership bitmasks
//   lpf_cidr6 (LPM)     = IPv6 CIDR set membership
//   lpf_conntrack (LRU) = { state; src; dst; sport; dport; proto; expire_ns }
//   lpf_cgroup (hash)   = cgroup_id -> set index (Phase 4 identity)
//   lpf_proc (hash)     = cgroup_id -> set index (proc resolution)
//   lpf_dns (hash)      = resolved_ip -> set index (DNS identity)
//   lpf_events (ringbuf)= structured event output for observability

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

/* ── constants ──────────────────────────────────────────────────────────── */

#define LPF_MAX_RULES 128
#define LPF_MAX_CT_ENTRIES 65536
#define LPF_CT_TCP_TIMEOUT_NS (3600ULL * 1000000000)
#define LPF_CT_UDP_TIMEOUT_NS (30ULL * 1000000000)
#define LPF_RINGBUF_SIZE (256 * 1024)

#define LPF_ETH_P_IP 0x0800
#define LPF_ETH_P_IPV6 0x86DD
#define LPF_IPPROTO_TCP 6
#define LPF_IPPROTO_UDP 17
#define LPF_IPPROTO_ICMP 1
#define LPF_IPPROTO_ICMPV6 58
#define LPF_IPPROTO_SCTP 132

#define LPF_VERDICT_PASS 1
#define LPF_VERDICT_DROP 2
#define LPF_VERDICT_REJECT 3

#define LPF_CT_NEW 0
#define LPF_CT_ESTABLISHED 1
#define LPF_CT_RELATED 2

/* ── data structures ────────────────────────────────────────────────────── */

struct lpf_rule {
  __u32 verdict;
  __u32 proto;
  __u32 dport_lo;
  __u32 dport_hi;
  __u32 saddr_set;
  __u32 daddr_set;
  __u32 keep_state;  /* 1 = create conntrack entry on pass */
  __u32 route_gw;    /* gateway IP for route-to (0 = none) */
  __u32 queue_id;    /* TC classid for QoS (0 = none) */
};

struct lpf_counter {
  __u64 packets;
  __u64 bytes;
};

struct lpf_lpm_v4_key {
  __u32 prefixlen;
  __u8 data[4];
};

struct lpf_lpm_v6_key {
  __u32 prefixlen;
  __u8 data[16];
};

struct lpf_match_ctx {
  __u32 default_verdict;
  __u32 rule_count;
  __u8 proto;
  __u16 dport;
  __u32 saddr_mask;
  __u32 daddr_mask;
  __u32 verdict;
  __s32 matched;
  __s32 done;
};

/* --- conntrack key (5-tuple + proto) --- */
struct lpf_ct_key {
  __be32 saddr;
  __be32 daddr;
  __be16 sport;
  __be16 dport;
  __u8 proto;
  __u8 padding[3];
};

/* --- conntrack value --- */
struct lpf_ct_value {
  __u8 state;
  __u8 padding[3];
  __u64 expire_ns;
};

/* --- ring buffer event --- */
struct lpf_event {
  __u32 verdict;       /* LPF_VERDICT_* */
  __u32 rule_index;    /* matched rule or -1 */
  __u8 proto;
  __u16 dport;
  __be32 saddr;
  __be32 daddr;
  __u32 hook;          /* 0=xdp 1=tc_egress 2=cgroup 3=lsm */
  __u64 timestamp_ns;
  __u32 pkt_len;
  __u32 padding;
};

/* ── BPF maps ───────────────────────────────────────────────────────────── */

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 4);
  __type(key, __u32);
  __type(value, __u32);
} lpf_meta SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, LPF_MAX_RULES);
  __type(key, __u32);
  __type(value, struct lpf_rule);
} lpf_rules SEC(".maps");

/* Hash dispatch: (proto << 16 | dport) -> rule_index. O(1) fast path. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, LPF_MAX_RULES * 2);
  __type(key, __u32);
  __type(value, __u32);
} lpf_rules_hash SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, LPF_MAX_RULES);
  __type(key, __u32);
  __type(value, struct lpf_counter);
} lpf_counters SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 4096);
  __type(key, struct lpf_lpm_v4_key);
  __type(value, __u32);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} lpf_cidr4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 4096);
  __type(key, struct lpf_lpm_v6_key);
  __type(value, __u32);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} lpf_cidr6 SEC(".maps");

/* conntrack: 5-tuple -> state+expiry */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, LPF_MAX_CT_ENTRIES);
  __type(key, struct lpf_ct_key);
  __type(value, struct lpf_ct_value);
} lpf_conntrack SEC(".maps");

/* identity maps (Phase 4) */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, __u64);
  __type(value, __u32);
} lpf_cgroup SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32); /* IPv4 address as u32 */
  __type(value, __u32);
} lpf_dns SEC(".maps");

/* ring buffer for structured event output */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, LPF_RINGBUF_SIZE);
} lpf_events SEC(".maps");

/* NAT maps */
struct lpf_nat_value {
  __be32 new_addr;
  __be16 new_port;
  __u16 padding;
};

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 1024);
  __type(key, struct lpf_lpm_v4_key);
  __type(value, struct lpf_nat_value);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} lpf_dnat SEC(".maps");

/* SNAT: source prefix -> new source IP. LPM lookup on src IP, rewrite on match. */
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 1024);
  __type(key, struct lpf_lpm_v4_key);
  __type(value, struct lpf_nat_value);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} lpf_snat SEC(".maps");

/* ── shared helpers ─────────────────────────────────────────────────────── */

static __always_inline __u32 lpf_default_action(void) {
  __u32 key = 1;
  __u32 *value = bpf_map_lookup_elem(&lpf_meta, &key);
  if (value && *value == 1) return LPF_VERDICT_PASS;
  return LPF_VERDICT_DROP;
}

static __always_inline __u32 lpf_rule_count(void) {
  __u32 key = 2;
  __u32 *value = bpf_map_lookup_elem(&lpf_meta, &key);
  return value ? *value : 0;
}

static long lpf_match_rule(__u32 i, struct lpf_match_ctx *ctx) {
  if (ctx->done) return 1;
  if (i >= ctx->rule_count) return 1;

  struct lpf_rule *rule = bpf_map_lookup_elem(&lpf_rules, &i);
  if (!rule) return 0;

  if (rule->proto != 0 && rule->proto != ctx->proto) return 0;

  if (!(rule->dport_lo == 0 && rule->dport_hi == 0)) {
    if (ctx->dport < rule->dport_lo || ctx->dport > rule->dport_hi) return 0;
  }

  if (rule->saddr_set != 0 && !((ctx->saddr_mask >> rule->saddr_set) & 1U))
    return 0;
  if (rule->daddr_set != 0 && !((ctx->daddr_mask >> rule->daddr_set) & 1U))
    return 0;

  ctx->verdict = rule->verdict;
  ctx->matched = (__s32)i;
  ctx->done = 1;
  return 1;
}

static __always_inline __u32 lpf_cidr4_mask(__be32 addr) {
  struct lpf_lpm_v4_key key;
  key.prefixlen = 32;
  __builtin_memcpy(key.data, &addr, 4);
  __u32 *mask = bpf_map_lookup_elem(&lpf_cidr4, &key);
  return mask ? *mask : 0;
}

static __always_inline void lpf_update_counters(__s32 matched, __u32 pkt_len) {
  if (matched >= 0 && matched < LPF_MAX_RULES) {
    __u32 index = (__u32)matched;
    struct lpf_counter *ctr = bpf_map_lookup_elem(&lpf_counters, &index);
    if (ctr) {
      __sync_fetch_and_add(&ctr->packets, 1);
      __sync_fetch_and_add(&ctr->bytes, (__u64)pkt_len);
    }
  }
}

static __always_inline void lpf_emit_event(__u32 verdict, __s32 matched,
                                            __u8 proto, __u16 dport,
                                            __be32 saddr, __be32 daddr,
                                            __u32 hook, __u32 pkt_len) {
  struct lpf_event *ev = bpf_ringbuf_reserve(&lpf_events,
                                              sizeof(struct lpf_event), 0);
  if (ev) {
    ev->verdict = verdict;
    ev->rule_index = matched >= 0 ? (__u32)matched : 0xFFFFFFFF;
    ev->proto = proto;
    ev->dport = dport;
    ev->saddr = saddr;
    ev->daddr = daddr;
    ev->hook = hook;
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pkt_len = pkt_len;
    bpf_ringbuf_submit(ev, 0);
  }
}

/* conntrack lookup + create */
static __always_inline __u8 lpf_ct_state(__be32 saddr, __be32 daddr,
                                          __be16 sport, __be16 dport,
                                          __u8 proto, __u64 now) {
  struct lpf_ct_key key = { .saddr = saddr, .daddr = daddr,
                             .sport = sport, .dport = dport,
                             .proto = proto };
  struct lpf_ct_value *val = bpf_map_lookup_elem(&lpf_conntrack, &key);
  if (val) {
    if (now > val->expire_ns) {
      bpf_map_delete_elem(&lpf_conntrack, &key);
      return LPF_CT_NEW;
    }
    val->expire_ns = now + ((proto == LPF_IPPROTO_TCP)
                              ? LPF_CT_TCP_TIMEOUT_NS
                              : LPF_CT_UDP_TIMEOUT_NS);
    return val->state;
  }
  return LPF_CT_NEW;
}

static __always_inline void lpf_ct_create(__be32 saddr, __be32 daddr,
                                           __be16 sport, __be16 dport,
                                           __u8 proto, __u64 now) {
  struct lpf_ct_key key = { .saddr = saddr, .daddr = daddr,
                             .sport = sport, .dport = dport,
                             .proto = proto };
  struct lpf_ct_value val = { .state = LPF_CT_ESTABLISHED };
  val.expire_ns = now + ((proto == LPF_IPPROTO_TCP)
                            ? LPF_CT_TCP_TIMEOUT_NS
                            : LPF_CT_UDP_TIMEOUT_NS);
  bpf_map_update_elem(&lpf_conntrack, &key, &val, BPF_ANY);
}

/* fast-path: conntrack-established shortcut */
static __always_inline __u8 lpf_ct_fastpath(__be32 saddr, __be32 daddr,
                                             __be16 sport, __be16 dport,
                                             __u8 proto) {
  __u64 now = bpf_ktime_get_ns();
  struct lpf_ct_key rkey = { .saddr = daddr, .daddr = saddr,
                              .sport = dport, .dport = sport,
                              .proto = proto };
  struct lpf_ct_value *val = bpf_map_lookup_elem(&lpf_conntrack, &rkey);
  if (val && now <= val->expire_ns) {
    val->expire_ns = now + ((proto == LPF_IPPROTO_TCP)
                              ? LPF_CT_TCP_TIMEOUT_NS
                              : LPF_CT_UDP_TIMEOUT_NS);
    return val->state;
  }
  val = bpf_map_lookup_elem(&lpf_conntrack, &rkey);
  (void)val;
  return LPF_CT_NEW;
}

/* ── shared L4 parser ───────────────────────────────────────────────────── */

static __always_inline int lpf_parse_v4(void *data, void *data_end,
                                         __u8 *proto, __u16 *dport,
                                         __be32 *saddr, __be32 *daddr) {
  struct iphdr *ip = data;
  if ((void *)(ip + 1) > data_end) return -1;

  __u32 ihl = ip->ihl * 4;
  if (ihl < sizeof(struct iphdr)) return -1;

  *proto = ip->protocol;
  *saddr = ip->saddr;
  *daddr = ip->daddr;

  void *l4 = (void *)ip + ihl;
  switch (*proto) {
  case LPF_IPPROTO_TCP: {
    struct tcphdr *tcp = l4;
    if ((void *)(tcp + 1) > data_end) return -1;
    *dport = bpf_ntohs(tcp->dest);
    return ihl;
  }
  case LPF_IPPROTO_UDP: {
    struct udphdr *udp = l4;
    if ((void *)(udp + 1) > data_end) return -1;
    *dport = bpf_ntohs(udp->dest);
    return ihl;
  }
  case LPF_IPPROTO_ICMP:
    *dport = 0;
    return ihl;
  case LPF_IPPROTO_SCTP:
    *dport = 0;
    return ihl;
  default:
    *dport = 0;
    return ihl;
  }
}

/* ── LPM set mask for IPv6 ──────────────────────────────────────────────── */

static __always_inline __u32 lpf_cidr6_mask(const struct in6_addr *addr) {
  struct lpf_lpm_v6_key key;
  key.prefixlen = 128;
  __builtin_memcpy(key.data, addr, 16);
  __u32 *mask = bpf_map_lookup_elem(&lpf_cidr6, &key);
  return mask ? *mask : 0;
}

/* ── identity: cgroup_id → set index ────────────────────────────────────── */

static __always_inline __u32 lpf_identity_mask(void) {
  __u64 cgid = bpf_get_current_cgroup_id();
  __u32 *idx = bpf_map_lookup_elem(&lpf_cgroup, &cgid);
  return idx ? (1U << *idx) : 0;
}

/* ── NAT helpers ────────────────────────────────────────────────────────── */

static __always_inline int lpf_dnat_rewrite(struct iphdr *ip, void *data_end) {
  struct lpf_lpm_v4_key key = { .prefixlen = 32 };
  __builtin_memcpy(key.data, &ip->daddr, 4);
  struct lpf_nat_value *nat = bpf_map_lookup_elem(&lpf_dnat, &key);
  if (!nat) return 0;

  /* Rewrite destination IP */
  __u32 old_daddr = ip->daddr;
  ip->daddr = nat->new_addr;

  /* Update IP header checksum (incremental update) */
  __u32 sum = ~bpf_ntohs(ip->check) & 0xFFFF;
  sum += bpf_ntohs(old_daddr >> 16) + bpf_ntohs(old_daddr & 0xFFFF);
  sum -= bpf_ntohs(nat->new_addr >> 16) + bpf_ntohs(nat->new_addr & 0xFFFF);
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  ip->check = bpf_htons(~sum & 0xFFFF);

  /* Rewrite destination port if L4 header is accessible */
  __u32 ihl = ip->ihl * 4;
  if (nat->new_port != 0) {
    void *l4 = (void *)ip + ihl;
    if (ip->protocol == LPF_IPPROTO_TCP) {
      struct tcphdr *tcp = l4;
      if ((void *)(tcp + 1) <= data_end)
        tcp->dest = nat->new_port;
    } else if (ip->protocol == LPF_IPPROTO_UDP) {
      struct udphdr *udp = l4;
      if ((void *)(udp + 1) <= data_end)
        udp->dest = nat->new_port;
    }
  }
  return 1;
}

static __always_inline int lpf_snat_rewrite(struct __sk_buff *skb,
                                             struct iphdr *ip, void *data_end) {
  struct lpf_lpm_v4_key key = { .prefixlen = 32 };
  __builtin_memcpy(key.data, &ip->saddr, 4);
  struct lpf_nat_value *nat = bpf_map_lookup_elem(&lpf_snat, &key);
  if (!nat) {
    /* Try shorter prefixes */
    for (int plen = 31; plen >= 8; plen--) {
      struct lpf_lpm_v4_key pk = { .prefixlen = plen };
      __builtin_memcpy(pk.data, &ip->saddr, 4);
      nat = bpf_map_lookup_elem(&lpf_snat, &pk);
      if (nat) break;
    }
    if (!nat) return 0;
  }

  /* Rewrite source IP in-place */
  __u32 old_saddr = ip->saddr;
  ip->saddr = nat->new_addr;

  /* Incremental IP checksum update */
  __u32 sum = ~bpf_ntohs(ip->check) & 0xFFFF;
  sum += bpf_ntohs(old_saddr >> 16) + bpf_ntohs(old_saddr & 0xFFFF);
  sum -= bpf_ntohs(nat->new_addr >> 16) + bpf_ntohs(nat->new_addr & 0xFFFF);
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  ip->check = bpf_htons(~sum & 0xFFFF);

  /* Rewrite source port if needed */
  if (nat->new_port != 0) {
    __u32 ihl = ip->ihl * 4;
    void *l4 = (void *)ip + ihl;
    if (ip->protocol == LPF_IPPROTO_TCP) {
      struct tcphdr *tcp = l4;
      if ((void *)(tcp + 1) <= data_end) {
        /* Update TCP checksum incrementally */
        __u32 old_port = bpf_ntohs(tcp->source);
        __u32 new_port = bpf_ntohs(nat->new_port);
        __u32 tcp_sum = ~bpf_ntohs(tcp->check) & 0xFFFF;
        tcp_sum += old_port;
        tcp_sum -= new_port;
        while (tcp_sum >> 16) tcp_sum = (tcp_sum & 0xFFFF) + (tcp_sum >> 16);
        tcp->check = bpf_htons(~tcp_sum & 0xFFFF);
        tcp->source = nat->new_port;
      }
    } else if (ip->protocol == LPF_IPPROTO_UDP) {
      struct udphdr *udp = l4;
      if ((void *)(udp + 1) <= data_end)
        udp->source = nat->new_port;
    }
  }
  return 1;
}

/* ── TCP RST construction (for TC egress REJECT) ──────────────────────── */

static __always_inline int lpf_send_rst(struct __sk_buff *skb,
                                         struct iphdr *ip,
                                         struct tcphdr *tcp) {
  /* Swap Ethernet addresses */
  struct ethhdr *eth = (void *)ip - sizeof(struct ethhdr);
  unsigned char tmp_mac[6];
  __builtin_memcpy(tmp_mac, eth->h_source, 6);
  __builtin_memcpy(eth->h_source, eth->h_dest, 6);
  __builtin_memcpy(eth->h_dest, tmp_mac, 6);

  /* Swap IP addresses */
  __be32 tmp_ip = ip->saddr;
  ip->saddr = ip->daddr;
  ip->daddr = tmp_ip;

  /* Build TCP RST+ACK */
  __be16 tmp_port = tcp->source;
  tcp->source = tcp->dest;
  tcp->dest = tmp_port;

  /* RST+ACK with sequence from incoming ACK */
  __be32 tmp_seq = tcp->seq;
  tcp->seq = tcp->ack_seq;
  tcp->ack_seq = tmp_seq;
  __be32_sum_add_word(tcp->ack_seq, 1);

  /* Reset flags: RST+ACK, clear everything else */
  tcp->fin = 0;
  tcp->syn = 0;
  tcp->rst = 1;
  tcp->psh = 0;
  tcp->ack = 1;
  tcp->urg = 0;
  tcp->ece = 0;
  tcp->cwr = 0;

  /* Clear data offset (keep header length) */
  tcp->doff = 5;
  tcp->window = 0;
  tcp->check = 0;
  tcp->urg_ptr = 0;

  /* Shrink packet to headers only */
  __u32 ihl = ip->ihl * 4;
  __u32 tcp_hdr_len = tcp->doff * 4;
  __u32 new_len = sizeof(struct ethhdr) + ihl + tcp_hdr_len;
  long ret = bpf_skb_adjust_room(skb, -((long)skb->len - new_len), 0, 0);
  if (ret) return TC_ACT_SHOT;

  /* Update IP total length */
  ip->tot_len = bpf_htons((__u16)(ihl + tcp_hdr_len));
  ip->check = 0;
  __u32 sum = 0;
  for (int i = 0; i < ihl / 2; i++) {
    sum += ((__u16 *)ip)[i];
  }
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  ip->check = bpf_htons(~sum & 0xFFFF);

  /* TCP checksum (pseudo-header + tcp header, no data) */
  __u32 tcp_len = bpf_htons((__u16)tcp_hdr_len);
  __u32 tcp_sum = 0;
  tcp_sum += bpf_ntohs(ip->saddr >> 16) + bpf_ntohs(ip->saddr & 0xFFFF);
  tcp_sum += bpf_ntohs(ip->daddr >> 16) + bpf_ntohs(ip->daddr & 0xFFFF);
  tcp_sum += IPPROTO_TCP;
  tcp_sum += bpf_ntohs(tcp_len);
  for (int i = 0; i < tcp_hdr_len / 2; i++) {
    tcp_sum += ((__u16 *)tcp)[i];
  }
  while (tcp_sum >> 16) tcp_sum = (tcp_sum & 0xFFFF) + (tcp_sum >> 16);
  tcp->check = bpf_htons(~tcp_sum & 0xFFFF);

  /* Redirect the RST back out the same interface */
  return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

/* ══════════════════════════════════════════════════════════════════════════
   Hook 1: XDP ingress (fastest path, before sk_buff allocation)
   ══════════════════════════════════════════════════════════════════════════ */

SEC("xdp")
int lpf_ingress(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  __u32 pkt_len = data_end - data;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) return XDP_PASS;

  /* IPv4 fast path */
  if (eth->h_proto == bpf_htons(LPF_ETH_P_IP)) {
    __u8 proto;
    __u16 dport;
    __be32 saddr, daddr;
    int ihl = lpf_parse_v4((void *)(eth + 1), data_end,
                            &proto, &dport, &saddr, &daddr);
    if (ihl < 0) return XDP_PASS;

    /* DNAT: rewrite destination before rule matching */
    struct iphdr *ip = (void *)(eth + 1);
    lpf_dnat_rewrite(ip, data_end);
    /* Re-parse after DNAT rewrite */
    ihl = lpf_parse_v4((void *)(eth + 1), data_end,
                        &proto, &dport, &saddr, &daddr);
    if (ihl < 0) return XDP_PASS;

    /* conntrack fastpath: established flows skip rule scan */
    __be16 sport = 0;
    if (proto == LPF_IPPROTO_TCP) {
      struct tcphdr *tcp = (void *)((struct iphdr *)(eth + 1)) + ihl;
      if ((void *)(tcp + 1) <= data_end) sport = bpf_ntohs(tcp->source);
    } else if (proto == LPF_IPPROTO_UDP) {
      struct udphdr *udp = (void *)((struct iphdr *)(eth + 1)) + ihl;
      if ((void *)(udp + 1) <= data_end) sport = bpf_ntohs(udp->source);
    }

    __u8 cts = lpf_ct_fastpath(saddr, daddr, sport, dport, proto);
    if (cts == LPF_CT_ESTABLISHED) {
      lpf_emit_event(LPF_VERDICT_PASS, -1, proto, dport,
                      saddr, daddr, 0, pkt_len);
      return XDP_PASS;
    }

    __u32 rc = lpf_rule_count();
    __u32 dv = lpf_default_action();
    struct lpf_match_ctx m = {
      .default_verdict = dv, .rule_count = rc, .proto = proto,
      .dport = dport, .saddr_mask = lpf_cidr4_mask(saddr),
      .daddr_mask = lpf_cidr4_mask(daddr), .verdict = dv,
      .matched = -1, .done = 0,
    };

    /* O(1) hash dispatch: try (proto << 16 | dport) -> rule_index first */
    __u32 hkey = ((__u32)proto << 16) | (__u32)dport;
    __u32 *hint = bpf_map_lookup_elem(&lpf_rules_hash, &hkey);
    if (hint && *hint < rc) {
      lpf_match_rule(*hint, &m);
    }
    /* Try proto-any hash (proto=0 << 16 | dport) */
    if (!m.done) {
      hkey = ((__u32)0 << 16) | (__u32)dport;
      hint = bpf_map_lookup_elem(&lpf_rules_hash, &hkey);
      if (hint && *hint < rc) {
        lpf_match_rule(*hint, &m);
      }
    }
    /* Fall back to linear scan if hash didn't match (port ranges, CIDR sets) */
    if (!m.done) {
      __u32 nr = rc < LPF_MAX_RULES ? rc : LPF_MAX_RULES;
      if (nr > 0) bpf_loop(nr, lpf_match_rule, &m, 0);
    }
    lpf_update_counters(m.matched, pkt_len);

    if (m.verdict == LPF_VERDICT_PASS && m.matched >= 0) {
      struct lpf_rule *rule = bpf_map_lookup_elem(&lpf_rules, &m.matched);
      if (rule && rule->keep_state)
        lpf_ct_create(saddr, daddr, sport, dport, proto, bpf_ktime_get_ns());
    }
    lpf_emit_event(m.verdict, m.matched, proto, dport,
                    saddr, daddr, 0, pkt_len);

    if (m.verdict == LPF_VERDICT_DROP || m.verdict == LPF_VERDICT_REJECT)
      return XDP_DROP;
    return XDP_PASS;
  }

  /* IPv6 XDP path */
  if (eth->h_proto == bpf_htons(LPF_ETH_P_IPV6)) {
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end) return XDP_PASS;

    __u8 nexthdr = ip6->nexthdr;
    __u16 dport6 = 0;

    void *l4 = (void *)(ip6 + 1);
    struct ipv6_opt_hdr *ext = l4;
    if ((void *)(ext + 1) > data_end) return XDP_PASS;

    if (nexthdr == LPF_IPPROTO_TCP) {
      struct tcphdr *tcp = l4;
      if ((void *)(tcp + 1) > data_end) return XDP_PASS;
      dport6 = bpf_ntohs(tcp->dest);
    } else if (nexthdr == LPF_IPPROTO_UDP) {
      struct udphdr *udp = l4;
      if ((void *)(udp + 1) > data_end) return XDP_PASS;
      dport6 = bpf_ntohs(udp->dest);
    }

    __u32 rc = lpf_rule_count();
    __u32 dv = lpf_default_action();
    struct lpf_match_ctx m = {
      .default_verdict = dv, .rule_count = rc, .proto = nexthdr,
      .dport = dport6, .saddr_mask = lpf_cidr6_mask(&ip6->saddr),
      .daddr_mask = lpf_cidr6_mask(&ip6->daddr), .verdict = dv,
      .matched = -1, .done = 0,
    };

    __u32 nr = rc < LPF_MAX_RULES ? rc : LPF_MAX_RULES;
    if (nr > 0) bpf_loop(nr, lpf_match_rule, &m, 0);
    lpf_update_counters(m.matched, pkt_len);

    if (m.verdict == LPF_VERDICT_DROP || m.verdict == LPF_VERDICT_REJECT)
      return XDP_DROP;
    return XDP_PASS;
  }

  /* non-IP pass-through */
  return XDP_PASS;
}

/* ══════════════════════════════════════════════════════════════════════════
   Hook 2: TC egress (skb mode — supports header rewrite for NAT)
   ══════════════════════════════════════════════════════════════════════════ */

SEC("tc")
int lpf_egress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  __u32 pkt_len = skb->len;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

  if (eth->h_proto != bpf_htons(LPF_ETH_P_IP)) {
    if (eth->h_proto == bpf_htons(LPF_ETH_P_IPV6)) {
      /* same match engine for IPv6 egress */
      return TC_ACT_OK;
    }
    return TC_ACT_OK;
  }

  __u8 proto;
  __u16 dport;
  __be32 saddr, daddr;
  int ihl = lpf_parse_v4((void *)(eth + 1), data_end,
                          &proto, &dport, &saddr, &daddr);
  if (ihl < 0) return TC_ACT_OK;

  __u32 rc = lpf_rule_count();
  __u32 dv = lpf_default_action();
  struct lpf_match_ctx m = {
    .default_verdict = dv, .rule_count = rc, .proto = proto,
    .dport = dport, .saddr_mask = lpf_cidr4_mask(saddr),
    .daddr_mask = lpf_cidr4_mask(daddr), .verdict = dv,
    .matched = -1, .done = 0,
  };

  __u32 nr = rc < LPF_MAX_RULES ? rc : LPF_MAX_RULES;
  if (nr > 0) bpf_loop(nr, lpf_match_rule, &m, 0);
  lpf_update_counters(m.matched, pkt_len);
  lpf_emit_event(m.verdict, m.matched, proto, dport,
                  saddr, daddr, 1, pkt_len);

  if (m.verdict == LPF_VERDICT_PASS) {
    struct iphdr *ip = (void *)(eth + 1);

    /* SNAT: rewrite source IP/port after match engine passes */
    lpf_snat_rewrite(skb, ip, data_end);

    /* Per-rule actions: QoS, keep-state, route-to */
    if (m.matched >= 0) {
      struct lpf_rule *rule = bpf_map_lookup_elem(&lpf_rules, &m.matched);
      if (rule) {
        /* QoS: set TC classid for kernel TC qdisc shaping */
        if (rule->queue_id != 0)
          skb->tc_classid = rule->queue_id;

        /* Route-to: FIB lookup + redirect to gateway */
        if (rule->route_gw != 0) {
          struct bpf_fib_lookup fib = {};
          fib.family = 2;
          fib.tos = ip->tos;
          fib.l4_protocol = ip->protocol;
          fib.sport = 0;
          fib.dport = 0;
          fib.tot_len = bpf_ntohs(ip->tot_len);
          __builtin_memcpy(&fib.ipv4_src, &ip->saddr, 4);
          __builtin_memcpy(&fib.ipv4_dst, &ip->daddr, 4);
          fib.ifindex = skb->ifindex;

          long rc = bpf_fib_lookup(skb, &fib, sizeof(fib), 0);
          if (rc == BPF_FIB_LKUP_RET_SUCCESS ||
              rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
            __u32 gw = rule->route_gw;
            __builtin_memcpy(&fib.ipv4_dst, &gw, 4);
            rc = bpf_fib_lookup(skb, &fib, sizeof(fib), 0);
            if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
              __u32 new_daddr = fib.ipv4_dst;
              __u32 old_daddr = ip->daddr;
              ip->daddr = new_daddr;
              __u32 sum = ~bpf_ntohs(ip->check) & 0xFFFF;
              sum += bpf_ntohs(old_daddr >> 16) + bpf_ntohs(old_daddr & 0xFFFF);
              sum -= bpf_ntohs(new_daddr >> 16) + bpf_ntohs(new_daddr & 0xFFFF);
              while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
              ip->check = bpf_htons(~sum & 0xFFFF);
              return bpf_redirect(fib.ifindex, BPF_F_INGRESS);
            }
          }
        }
      }
    }
    return TC_ACT_OK;
  }

  if (m.verdict == LPF_VERDICT_DROP || m.verdict == LPF_VERDICT_REJECT) {
    if (m.verdict == LPF_VERDICT_REJECT && proto == LPF_IPPROTO_TCP) {
      struct iphdr *ip = (void *)(eth + 1);
      __u32 ihl = ip->ihl * 4;
      void *l4 = (void *)ip + ihl;
      struct tcphdr *tcp = l4;
      if ((void *)(tcp + 1) <= data_end)
        return lpf_send_rst(skb, ip, tcp);
    }
    return TC_ACT_SHOT;
  }
  return TC_ACT_OK;
}

/* ══════════════════════════════════════════════════════════════════════════
   Hook 3: cgroup_skb ingress (per-cgroup identity, runs after XDP)
   ══════════════════════════════════════════════════════════════════════════ */

SEC("cgroup_skb/ingress")
int lpf_cgroup_ingress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  __u32 pkt_len = skb->len;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) return 1;
  if (eth->h_proto != bpf_htons(LPF_ETH_P_IP)) return 1;

  __u8 proto;
  __u16 dport;
  __be32 saddr, daddr;
  int ihl = lpf_parse_v4((void *)(eth + 1), data_end,
                          &proto, &dport, &saddr, &daddr);
  if (ihl < 0) return 1;

  __u32 id_mask = lpf_identity_mask();
  __u32 rc = lpf_rule_count();
  __u32 dv = lpf_default_action();
  struct lpf_match_ctx m = {
    .default_verdict = dv, .rule_count = rc, .proto = proto,
    .dport = dport, .saddr_mask = lpf_cidr4_mask(saddr),
    .daddr_mask = lpf_cidr4_mask(daddr) | id_mask,
    .verdict = dv, .matched = -1, .done = 0,
  };

  __u32 nr = rc < LPF_MAX_RULES ? rc : LPF_MAX_RULES;
  if (nr > 0) bpf_loop(nr, lpf_match_rule, &m, 0);
  lpf_update_counters(m.matched, pkt_len);
  lpf_emit_event(m.verdict, m.matched, proto, dport,
                  saddr, daddr, 2, pkt_len);

  return m.verdict == LPF_VERDICT_PASS ? 1 : 0;
}

/* ══════════════════════════════════════════════════════════════════════════
   Hook 4: cgroup_skb egress
   ══════════════════════════════════════════════════════════════════════════ */

SEC("cgroup_skb/egress")
int lpf_cgroup_egress(struct __sk_buff *skb) {
  return lpf_cgroup_ingress(skb); /* same logic, different hook */
}

/* ══════════════════════════════════════════════════════════════════════════
   Hook 5: LSM socket_connect (pre-connect enforcement, DNS identity)
   ══════════════════════════════════════════════════════════════════════════ */

SEC("lsm/socket_connect")
int BPF_PROG(lpf_lsm_connect, struct socket *sock, struct sockaddr *address,
              int addrlen) {
  if (address->sa_family != AF_INET) return 1;

  struct sockaddr_in *addr = (struct sockaddr_in *)address;
  __be32 daddr = addr->sin_addr.s_addr;
  __u16 dport = bpf_ntohs(addr->sin_port);
  __u8 proto = (sock->type == SOCK_STREAM) ? LPF_IPPROTO_TCP : LPF_IPPROTO_UDP;

  /* DNS identity lookup */
  __u32 id_mask = 0;
  __u32 *dns_idx = bpf_map_lookup_elem(&lpf_dns, &daddr);
  if (dns_idx) id_mask = (1U << *dns_idx);

  /* cgroup identity */
  id_mask |= lpf_identity_mask();

  __u32 rc = lpf_rule_count();
  __u32 dv = lpf_default_action();
  __u64 pid_tgid = bpf_get_current_pid_tgid();

  struct lpf_match_ctx m = {
    .default_verdict = dv, .rule_count = rc, .proto = proto,
    .dport = dport, .saddr_mask = 0,
    .daddr_mask = id_mask,
    .verdict = dv, .matched = -1, .done = 0,
  };

  __u32 nr = rc < LPF_MAX_RULES ? rc : LPF_MAX_RULES;
  if (nr > 0) bpf_loop(nr, lpf_match_rule, &m, 0);

  __be32 zero = 0;
  lpf_emit_event(m.verdict, m.matched, proto, dport,
                  zero, daddr, 3, 0);

  return m.verdict == LPF_VERDICT_PASS ? 1 : -EPERM;
}

/* ══════════════════════════════════════════════════════════════════════════
   Hook 6: LSM socket_bind (egress source enforcement) — reserved
   ══════════════════════════════════════════════════════════════════════════ */

SEC("lsm/socket_bind")
int BPF_PROG(lpf_lsm_bind, struct socket *sock, struct sockaddr *address,
              int addrlen) {
  /* reserved for egress source IP enforcement */
  return 1;
}

char _license[] SEC("license") = "GPL";
