// lpf eBPF datapath: a fixed, pre-verified XDP match engine.
//
// Policy lives entirely in BPF maps (created/populated by `lpf ebpf load`);
// this program is generic and never recompiled per policy. It mirrors the map
// schema in lib/ebpf.ml:
//   lpf_meta[1]      = default action (1 = pass, 0 = deny)
//   lpf_meta[2]      = rule_count
//   lpf_rules[i]     = { verdict; proto; dport_lo; dport_hi }  (verdict 1/2/3)
//   lpf_counters[i]  = { packets; bytes }
//   lpf_cidr4 (LPM)  = source/membership set (reserved for per-rule linkage)
//
// XDP cannot send a TCP RST, so a `reject` verdict (3) degrades to XDP_DROP,
// matching Ebpf.capability_diagnostics.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define LPF_MAX_RULES 64

#define LPF_ETH_P_IP 0x0800
#define LPF_IPPROTO_TCP 6
#define LPF_IPPROTO_UDP 17

#define LPF_VERDICT_PASS 1
#define LPF_VERDICT_DROP 2
#define LPF_VERDICT_REJECT 3

struct lpf_rule {
  __u32 verdict;
  __u32 proto;
  __u32 dport_lo;
  __u32 dport_hi;
};

struct lpf_counter {
  __u64 packets;
  __u64 bytes;
};

struct lpf_lpm_v4_key {
  __u32 prefixlen;
  __u8 data[4];
};

struct lpf_match_ctx {
  __u32 default_verdict;
  __u32 rule_count;
  __u8 proto;
  __u16 dport;
  /* output */
  __u32 verdict;
  __s32 matched;
  __s32 done;
};

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

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, LPF_MAX_RULES);
  __type(key, __u32);
  __type(value, struct lpf_counter);
} lpf_counters SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 1024);
  __type(key, struct lpf_lpm_v4_key);
  __type(value, __u32);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} lpf_cidr4 SEC(".maps");

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

/* bpf_loop callback: called once per rule index. Returns 1 early-exit. */
static long lpf_match_rule(__u32 i, struct lpf_match_ctx *ctx) {
  if (ctx->done) return 1;
  if (i >= ctx->rule_count) return 1;

  struct lpf_rule *rule = bpf_map_lookup_elem(&lpf_rules, &i);
  if (!rule) return 0;

  if (rule->proto != 0 && rule->proto != ctx->proto) return 0;

  if (!(rule->dport_lo == 0 && rule->dport_hi == 0)) {
    if (ctx->dport < rule->dport_lo || ctx->dport > rule->dport_hi) return 0;
  }

  ctx->verdict = rule->verdict;
  ctx->matched = (__s32)i;
  ctx->done = 1;
  return 1;
}

SEC("xdp")
int lpf_ingress(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) return XDP_PASS;
  if (eth->h_proto != bpf_htons(LPF_ETH_P_IP)) return XDP_PASS;

  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) return XDP_PASS;

  __u32 ihl = ip->ihl * 4;
  if (ihl < sizeof(struct iphdr)) return XDP_PASS;

  __u8 proto = ip->protocol;
  __u16 dport = 0;
  void *l4 = (void *)ip + ihl;

  if (proto == LPF_IPPROTO_TCP) {
    struct tcphdr *tcp = l4;
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;
    dport = bpf_ntohs(tcp->dest);
  } else if (proto == LPF_IPPROTO_UDP) {
    struct udphdr *udp = l4;
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    dport = bpf_ntohs(udp->dest);
  }

  __u32 rule_count = lpf_rule_count();

  struct lpf_match_ctx m = {
    .default_verdict = lpf_default_action(),
    .rule_count = rule_count,
    .proto = proto,
    .dport = dport,
    .verdict = lpf_default_action(),
    .matched = -1,
    .done = 0,
  };

  __u32 nr = rule_count < LPF_MAX_RULES ? rule_count : LPF_MAX_RULES;
  if (nr > 0) bpf_loop(nr, lpf_match_rule, &m, 0);

  if (m.matched >= 0) {
    __u32 index = (__u32)m.matched;
    struct lpf_counter *counter = bpf_map_lookup_elem(&lpf_counters, &index);
    if (counter) {
      __sync_fetch_and_add(&counter->packets, 1);
      __sync_fetch_and_add(&counter->bytes, (__u64)(data_end - data));
    }
  }

  if (m.verdict == LPF_VERDICT_DROP || m.verdict == LPF_VERDICT_REJECT)
    return XDP_DROP;
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
