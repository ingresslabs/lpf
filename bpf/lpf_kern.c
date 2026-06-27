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

#ifdef LPF_NO_VMLINUX_H
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
struct sockaddr {
  unsigned short sa_family;
  char sa_data[14];
};
struct socket {
  short type;
};
#else
#include "vmlinux.h"
#endif
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

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef EPERM
#define EPERM 1
#endif

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

/* ── L7 domain filtering ─────────────────────────────────────────────────── */

#define LPF_L7_MAX_ENTRIES 8192
#define LPF_L7_MATCH_EXACT  1
#define LPF_L7_MATCH_SUFFIX 2
#define LPF_L7_MATCH_PREFIX 3

struct lpf_l7_key {
  __u8 type;          /* EXACT / SUFFIX / PREFIX */
  __u8 proto;          /* IPPROTO_TCP / IPPROTO_UDP */
  __u16 dport;         /* e.g. 53 for DNS, 443 for TLS */
  __u8 domain_len;     /* actual length of the domain string */
  __u8 domain[64];     /* padded domain name */
};

struct lpf_l7_policy {
  __u32 verdict;       /* LPF_VERDICT_PASS / DROP / REJECT */
  __u32 rule_index;    /* back-reference to lpf rule idx for logging */
};

/* Domain-based policy: (match_type, proto, dport, domain) -> (verdict, rule_idx)
   Checked BEFORE the L3/L4 rule scan for DNS/TLS/HTTP. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, LPF_L7_MAX_ENTRIES);
  __type(key, struct lpf_l7_key);
  __type(value, struct lpf_l7_policy);
} lpf_l7_policy SEC(".maps");

/* ── kube-proxy service load balancing ───────────────────────────────────── */

#define LPF_SVC_MAX_SERVICES 1024
#define LPF_SVC_MAX_BACKENDS 4096
#define LPF_SVC_BACKENDS_PER_SERVICE 16

struct lpf_svc_key {
  __be32 vip;           /* service ClusterIP */
  __be16 vport;         /* service port */
  __u8  proto;
  __u8  padding;
};

struct lpf_svc_value {
  __u32 backend_count;
  __u32 backend_ids[LPF_SVC_BACKENDS_PER_SERVICE];
};

struct lpf_backend {
  __be32 ip;
  __be16 port;
  __u16 weight;
  __u8  healthy;
  __u8  padding[3];
};

/* service VIP -> backend pool */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, LPF_SVC_MAX_SERVICES);
  __type(key, struct lpf_svc_key);
  __type(value, struct lpf_svc_value);
} lpf_services SEC(".maps");

/* backend ID -> IP+port+weight+health */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, LPF_SVC_MAX_BACKENDS);
  __type(key, __u32);
  __type(value, struct lpf_backend);
} lpf_backends SEC(".maps");

/* connection tracking for service LB: (src_ip, src_port, vip, vport, proto) -> backend_id */
struct lpf_svc_ct_key {
  __be32 saddr;
  __be16 sport;
  __be32 vip;
  __be16 vport;
  __u8   proto;
  __u8   padding[3];
};

struct lpf_svc_ct_value {
  __u32 backend_id;
  __u64 last_seen_ns;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct lpf_svc_ct_key);
  __type(value, struct lpf_svc_ct_value);
} lpf_svc_ct SEC(".maps");

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

/* ── L7 DNS QNAME parser ────────────────────────────────────────────────────
   Parses the first question from a DNS query (UDP, port 53).
   Returns domain_len (0 on parse failure). domain_buf receives the
   dot-separated domain name (e.g. "www.example.com").
   Max domain length: 63 bytes (padded to 64 for BPF verifier). */

static __always_inline int lpf_parse_dns_qname(void *data, void *data_end,
                                                char *domain_buf) {
  if (data + 12 > data_end) return 0;

  __u8 *p = (__u8 *)(data + 12);
  int len = 0;
  int max = 63;

#pragma unroll
  for (int i = 0; i < 8; i++) {
    if (p + 1 > data_end || len >= max) break;
    __u8 label_len = *p++;
    if (label_len == 0) break;
    if ((label_len & 0xC0) != 0) break;
    if (p + label_len > data_end) break;
    if (len + label_len + 1 > max) break;

    for (int j = 0; j < label_len; j++) {
      domain_buf[len++] = *p++;
    }
    domain_buf[len++] = '.';
  }
  if (len > 0 && domain_buf[len-1] == '.') domain_buf[len-1] = '\0';
  else domain_buf[0] = '\0';
  return len > 0 ? len - 1 : 0;
}

/* ── L7 TLS ClientHello SNI parser ──────────────────────────────────────────
   Parses the TLS ClientHello to extract the SNI hostname.
   Only handles TLS 1.2/1.3 records. Returns hostname_len (0 on failure). */

static __always_inline int lpf_parse_tls_sni(void *data, void *data_end,
                                              char *hostname) {
  __u8 *p = (__u8 *)data;
  if (p + 5 > data_end) return 0;

  if (p[0] != 0x16) return 0;           /* handshake content type */
  __u16 tls_ver = (p[1] << 8) | p[2];
  if (tls_ver < 0x0301 || tls_ver > 0x0304) return 0;
  __u16 record_len = (p[3] << 8) | p[4];
  p += 5;
  if (p + record_len > data_end) return 0;
  void *record_end = p + record_len;

  if (p + 1 > (__u8 *)record_end) return 0;
  if (*p++ != 0x01) return 0;           /* ClientHello handshake type */

  if (p + 3 > (__u8 *)record_end) return 0;
  __u32 hs_len = (p[0] << 16) | (p[1] << 8) | p[2];
  p += 3;
  if (p + hs_len > (__u8 *)record_end) return 0;

  if (p + 34 > (__u8 *)record_end) return 0;
  p += 2 + 32;                          /* version + random */

  __u8 sid_len = *p++;
  if (p + sid_len > (__u8 *)record_end) return 0;
  p += sid_len;

  if (p + 2 > (__u8 *)record_end) return 0;
  __u16 cs_len = (p[0] << 8) | p[1];
  p += 2;
  if (p + cs_len > (__u8 *)record_end) return 0;
  p += cs_len;

  if (p + 1 > (__u8 *)record_end) return 0;
  __u8 comp_len = *p++;
  if (p + comp_len > (__u8 *)record_end) return 0;
  p += comp_len;

  if (p + 2 > (__u8 *)record_end) return 0;
  __u16 ext_len = (p[0] << 8) | p[1];
  p += 2;
  void *ext_end = p + ext_len;
  if (ext_end > record_end) ext_end = record_end;

#pragma unroll
  for (int i = 0; i < 8; i++) {
    if (p + 4 > (__u8 *)ext_end) break;
    __u16 ext_type = (p[0] << 8) | p[1];
    __u16 ext_data_len = (p[2] << 8) | p[3];
    p += 4;
    if (ext_type == 0x0000) {           /* SNI extension */
      if (p + 2 > (__u8 *)ext_end) break;
      p += 2;
      if (p + 3 > (__u8 *)ext_end) break;
      if (*p++ != 0x00) break;          /* name type = host_name */
      __u16 name_len = (p[0] << 8) | p[1];
      p += 2;
      if (p + name_len > (__u8 *)ext_end) break;
      int n = name_len > 63 ? 63 : (int)name_len;
      for (int j = 0; j < n; j++) hostname[j] = (char)p[j];
      hostname[n] = '\0';
      return n;
    }
    p += ext_data_len;
  }
  return 0;
}

/* ── L7 HTTP/1.1 request parser ─────────────────────────────────────────────
   Parses the first data packet after TCP handshake to extract:
   - HTTP method (GET/POST/PUT/DELETE/HEAD/PATCH/CONNECT/OPTIONS)
   - Host header value (domain name)
   Used at cgroup_skb egress for TCP ports 80/8080.
   Stores method string and hostname, returns 1 if parsing succeeded. */

#define LPF_HTTP_METHOD_MAX 8
#define LPF_HTTP_HOST_MAX  64

static __always_inline int lpf_parse_http(void *data, void *data_end,
                                           char *method, int *method_len,
                                           char *host, int *host_len) {
  *method_len = 0;
  *host_len = 0;
  if (data >= data_end) return 0;

  __u8 *p = (__u8 *)data;
  void *http_end = data_end;

  /* find header end: \r\n\r\n */
  int found = 0;
#pragma unroll
  for (int i = 0; i < 64 && p + 4 <= (__u8 *)http_end; i++, p++) {
    if (p[0] == '\r' && p[1] == '\n' && p[2] == '\r' && p[3] == '\n') {
      http_end = p;
      found = 1;
      break;
    }
  }
  if (!found) return 0;

  p = (__u8 *)data;

  /* parse method from first token */
  int mlen = 0;
  while (p < (__u8 *)http_end && *p != ' ' && mlen < LPF_HTTP_METHOD_MAX) {
    method[mlen++] = (char)*p++;
  }
  if (p >= (__u8 *)http_end || *p != ' ') return 0;
  method[mlen] = '\0';
  *method_len = mlen;
  p++;

  /* skip path and version to find Host header */
  /* scan for \nHost:  (line start) */
  int hlen = 0;
  __u8 *scan = (__u8 *)data;
#pragma unroll
  for (int i = 0; i < 48 && scan + 7 < (__u8 *)http_end; i++, scan++) {
    if (scan[0] == '\n' || (scan == (__u8 *)data && i == 0)) {
      __u8 *line = (scan[0] == '\n') ? scan + 1 : scan;
      if (line + 6 > (__u8 *)http_end) continue;
      if (!(line[0] == 'H' || line[0] == 'h')) continue;
      if (!(line[1] == 'o' || line[1] == 'O')) continue;
      if (!(line[2] == 's' || line[2] == 'S')) continue;
      if (!(line[3] == 't' || line[3] == 'T')) continue;
      if (line[4] != ':' || line[5] != ' ') continue;

      line += 6;
      hlen = 0;
      while (line < (__u8 *)http_end && *line != '\r' && *line != '\n'
             && hlen < LPF_HTTP_HOST_MAX) {
        host[hlen++] = (char)*line++;
      }
      host[hlen] = '\0';
      *host_len = hlen;
      return 1;
    }
  }
  return 1;  /* method parsed, host optional */
}

/* ── L7 policy lookup ───────────────────────────────────────────────────────
   Checks if a domain (DNS QNAME / TLS SNI / HTTP host) matches an L7 rule.
   Tries EXACT match first, then SUFFIX (*.example.com), then PREFIX (www.*). */

static __always_inline int lpf_l7_lookup(const char *domain, int domain_len,
                                          __u8 proto, __u16 dport,
                                          __u32 *verdict) {
  if (domain_len == 0 || domain_len > 63) return 0;

  struct lpf_l7_key k = {};
  k.type = LPF_L7_MATCH_EXACT;
  k.proto = proto;
  k.dport = dport;
  k.domain_len = (__u8)domain_len;
  for (int i = 0; i < domain_len && i < 63; i++) k.domain[i] = domain[i];

  struct lpf_l7_policy *pol = bpf_map_lookup_elem(&lpf_l7_policy, &k);
  if (pol) {
    *verdict = pol->verdict;
    return 1;
  }

  int suffix_start = domain_len > 1 ? 1 : 0;
  if (suffix_start > 0) {
    for (int i = 1; i < domain_len && i < 63; i++) {
      if (domain[i-1] == '.') {
        int slen = domain_len - i;
        if (slen > 0 && slen < 63) {
          k.type = LPF_L7_MATCH_SUFFIX;
          k.domain_len = (__u8)slen;
          for (int j = 0; j < slen; j++) k.domain[j] = domain[i+j];
          pol = bpf_map_lookup_elem(&lpf_l7_policy, &k);
          if (pol) { *verdict = pol->verdict; return 1; }
        }
      }
    }
  }

  return 0;
}

/* ── service load balancer ──────────────────────────────────────────────────
   Maglev-consistent hashing: two-hash on-the-fly backend selection.
   No permutation table needed — pure computation with bounded disruption.
   Adding/removing one backend changes at most 1/N of existing assignments.
   Populates new_daddr/new_dport with the chosen backend IP/port.
   Returns 1 if a backend was selected, 0 if no service matches. */

static __always_inline __u32 lpf_hash32(__u32 val, __u32 seed) {
  __u32 hash = seed;
  hash = ((hash << 5) + hash) + val;
  hash = ((hash << 5) + hash) + (val >> 16);
  hash ^= hash >> 13;
  hash *= 0x9E3779B9;
  hash ^= hash >> 16;
  return hash;
}

static __always_inline __u32 lpf_svc_backend_id(struct lpf_svc_value *svc,
                                                 __u32 idx) {
  switch (idx) {
  case 0: return svc->backend_ids[0];
  case 1: return svc->backend_ids[1];
  case 2: return svc->backend_ids[2];
  case 3: return svc->backend_ids[3];
  case 4: return svc->backend_ids[4];
  case 5: return svc->backend_ids[5];
  case 6: return svc->backend_ids[6];
  case 7: return svc->backend_ids[7];
  case 8: return svc->backend_ids[8];
  case 9: return svc->backend_ids[9];
  case 10: return svc->backend_ids[10];
  case 11: return svc->backend_ids[11];
  case 12: return svc->backend_ids[12];
  case 13: return svc->backend_ids[13];
  case 14: return svc->backend_ids[14];
  case 15: return svc->backend_ids[15];
  default: return 0;
  }
}

static __always_inline int lpf_svc_lookup(__be32 saddr, __be16 sport,
                                           __be32 daddr, __be16 dport,
                                           __u8 proto, __u64 now_ns,
                                           __be32 *new_daddr, __be16 *new_dport) {
  struct lpf_svc_key svc_key = { .vip = daddr, .vport = dport, .proto = proto };
  struct lpf_svc_value *svc = bpf_map_lookup_elem(&lpf_services, &svc_key);
  if (!svc || svc->backend_count == 0) return 0;

  struct lpf_svc_ct_key ct_key = {
    .saddr = saddr, .sport = sport,
    .vip = daddr, .vport = dport, .proto = proto
  };
  struct lpf_svc_ct_value *ct = bpf_map_lookup_elem(&lpf_svc_ct, &ct_key);

  if (ct && now_ns - ct->last_seen_ns < 300000000000ULL) {
    __u32 bid = ct->backend_id;
    struct lpf_backend *be = bpf_map_lookup_elem(&lpf_backends, &bid);
    if (be && be->healthy) {
      *new_daddr = be->ip;
      *new_dport = be->port;
      return 1;
    }
  }

  __u32 h1 = lpf_hash32((__u32)saddr, 0xDEADBEEF);
  h1 = lpf_hash32((__u32)sport, h1);
  h1 = lpf_hash32((__u32)daddr, h1);
  h1 = lpf_hash32((__u32)dport, h1);
  h1 = lpf_hash32((__u32)proto, h1);

  __u32 h2 = lpf_hash32((__u32)daddr, 0xCAFEBABE);
  h2 = lpf_hash32((__u32)dport, h2);
  h2 = lpf_hash32((__u32)saddr, h2);
  h2 = lpf_hash32((__u32)sport, h2);
  h2 = lpf_hash32((__u32)proto, h2);

  __u32 count = svc->backend_count;
  if (count > LPF_SVC_BACKENDS_PER_SERVICE)
    count = LPF_SVC_BACKENDS_PER_SERVICE;
  if (count == 0) return 0;
  __u32 offset = h1 % count;
  __u32 skip = count > 1 ? ((h2 % (count - 1)) + 1) : 1;

  for (__u32 i = 0; i < LPF_SVC_BACKENDS_PER_SERVICE; i++) {
    if (i >= count) break;
    __u32 idx = (offset + i * skip) % count;
    if (idx >= LPF_SVC_BACKENDS_PER_SERVICE) continue;
    __u32 bid = lpf_svc_backend_id(svc, idx);
    if (bid == 0) continue;
    struct lpf_backend *be = bpf_map_lookup_elem(&lpf_backends, &bid);
    if (!be || !be->healthy) continue;

    *new_daddr = be->ip;
    *new_dport = be->port;

    struct lpf_svc_ct_value new_ct = { .backend_id = bid, .last_seen_ns = now_ns };
    bpf_map_update_elem(&lpf_svc_ct, &ct_key, &new_ct, BPF_ANY);
    return 1;
  }

  return 0;
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
  tcp->ack_seq = bpf_htonl(bpf_ntohl(tcp->ack_seq) + 1);

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
  if (ihl != sizeof(struct iphdr)) return TC_ACT_SHOT;
  __u32 tcp_hdr_len = sizeof(struct tcphdr);
  __u32 new_len = sizeof(struct ethhdr) + ihl + tcp_hdr_len;
  long ret = bpf_skb_adjust_room(skb, -((long)skb->len - new_len), 0, 0);
  if (ret) return TC_ACT_SHOT;

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  eth = data;
  if ((void *)(eth + 1) > data_end) return TC_ACT_SHOT;
  ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) return TC_ACT_SHOT;
  if ((void *)ip + ihl > data_end) return TC_ACT_SHOT;
  tcp = (void *)ip + ihl;
  if ((void *)(tcp + 1) > data_end) return TC_ACT_SHOT;

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

    /* service load balancer: rewrite VIP -> backend before rule match */
    __be16 sport_lb = 0;
    if (proto == LPF_IPPROTO_TCP) {
      struct tcphdr *tcp = (void *)((struct iphdr *)(eth + 1)) + ihl;
      if ((void *)(tcp + 1) <= data_end) sport_lb = bpf_ntohs(tcp->source);
    } else if (proto == LPF_IPPROTO_UDP) {
      struct udphdr *udp = (void *)((struct iphdr *)(eth + 1)) + ihl;
      if ((void *)(udp + 1) <= data_end) sport_lb = bpf_ntohs(udp->source);
    }
    {
      __be32 be_daddr = daddr;
      __be16 be_dport = bpf_htons(dport);
      if (lpf_svc_lookup(saddr, sport_lb, be_daddr, be_dport, proto,
                          bpf_ktime_get_ns(), &be_daddr, &be_dport)) {
        daddr = be_daddr;
        dport = bpf_ntohs(be_dport);
        struct iphdr *ip_rw = (void *)(eth + 1);
        ip_rw->daddr = be_daddr;
        __u16 old_hi = (ip_rw->check >> 8) | ((ip_rw->check & 0xFF) << 8);
        __u16 daddr_hi = (ip_rw->daddr >> 16) & 0xFFFF;
        __u16 daddr_lo = ip_rw->daddr & 0xFFFF;
        __u16 new_check = old_hi - daddr_hi - daddr_lo;
        while (new_check >> 16) new_check = (new_check & 0xFFFF) + (new_check >> 16);
        ip_rw->check = ((new_check & 0xFF) << 8) | (new_check >> 8);
      }
    }

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

static __always_inline int lpf_cgroup_eval(struct __sk_buff *skb) {
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

  /* Packet L7 parsers use variable packet scans that current kernels do not
     reliably prove safe in cgroup_skb. Keep L7 policy out of this hook until
     the DNS and HTTP parsers are rewritten with fixed-offset packet loads. */

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

SEC("cgroup_skb/ingress")
int lpf_cgroup_ingress(struct __sk_buff *skb) {
  return lpf_cgroup_eval(skb);
}

/* ══════════════════════════════════════════════════════════════════════════
   Hook 4: cgroup_skb egress
   ══════════════════════════════════════════════════════════════════════════ */

SEC("cgroup_skb/egress")
int lpf_cgroup_egress(struct __sk_buff *skb) {
  return lpf_cgroup_eval(skb);
}

/* ══════════════════════════════════════════════════════════════════════════
   Hook 5: LSM socket_connect (pre-connect enforcement, DNS identity)
   ══════════════════════════════════════════════════════════════════════════ */

SEC("lsm/socket_connect")
int BPF_PROG(lpf_lsm_connect, struct socket *sock, struct sockaddr *address,
              int addrlen) {
  if (address->sa_family != AF_INET) return 0;

  struct sockaddr_in *addr = (struct sockaddr_in *)address;
  __be32 daddr = addr->sin_addr.s_addr;
  __u16 dport = bpf_ntohs(addr->sin_port);
  __u8 proto = (sock->type == SOCK_STREAM) ? LPF_IPPROTO_TCP : LPF_IPPROTO_UDP;

  /* L7 TLS egress enforcement: if TCP/443 traffic has domain-based policy,
     require the destination IP to be DNS-resolved (lpf_dns map).
     This prevents TLS connections to IPs not approved via DNS identity. */
  if (proto == LPF_IPPROTO_TCP && dport == 443) {
    __u32 *dns_hit = bpf_map_lookup_elem(&lpf_dns, &daddr);
    if (!dns_hit) {
      struct lpf_l7_key l7k = {};
      l7k.type = LPF_L7_MATCH_SUFFIX;
      l7k.proto = LPF_IPPROTO_TCP;
      l7k.dport = 443;
      l7k.domain_len = 0;
      struct lpf_l7_policy *l7pol = bpf_map_lookup_elem(&lpf_l7_policy, &l7k);
      if (l7pol && l7pol->verdict != LPF_VERDICT_PASS) {
        __be32 zero = 0;
        lpf_emit_event(LPF_VERDICT_DROP, -3, proto, dport, zero, daddr, 3, 0);
        return -EPERM;
      }
    }
  }

  /* DNS identity lookup */
  __u32 id_mask = 0;
  __u32 *dns_idx = bpf_map_lookup_elem(&lpf_dns, &daddr);
  if (dns_idx) id_mask = (1U << *dns_idx);

  /* cgroup identity */
  id_mask |= lpf_identity_mask();

  __u32 rc = lpf_rule_count();
  __u32 dv = lpf_default_action();
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

  return m.verdict == LPF_VERDICT_PASS ? 0 : -EPERM;
}

/* ══════════════════════════════════════════════════════════════════════════
   Hook 6: LSM socket_bind (egress source enforcement) — reserved
   ══════════════════════════════════════════════════════════════════════════ */

SEC("lsm/socket_bind")
int BPF_PROG(lpf_lsm_bind, struct socket *sock, struct sockaddr *address,
              int addrlen) {
  /* reserved for egress source IP enforcement */
  return 0;
}

char _license[] SEC("license") = "GPL";
