#!/usr/bin/env python3
# In-kernel conformance matrix for the lpf XDP datapath using BPF_PROG_TEST_RUN
# (bpftool prog run). Crafts packets, configures the policy maps, runs the
# verified program in the kernel, and asserts the returned XDP verdict.
#
# XDP return codes: ABORTED=0, DROP=1, PASS=2.

import os
import json
import re
import struct
import subprocess
import sys

PIN = "/sys/fs/bpf/lpftest"
PROG = f"{PIN}/prog/lpf_ingress"
META = f"{PIN}/lpf_meta"
RULES = f"{PIN}/lpf_rules"
COUNTERS = f"{PIN}/lpf_counters"
CIDR4 = f"{PIN}/lpf_cidr4"

XDP_DROP, XDP_PASS = 1, 2
TCP, UDP, ICMP = 6, 17, 1
PASS_V, DROP_V, REJECT_V = 1, 2, 3  # verdict codes in lpf_rules

DATA_IN = "/tmp/lpf_pkt_in.bin"
DATA_OUT = "/tmp/lpf_pkt_out.bin"


def sh(args):
    r = subprocess.run(args, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def u32le(n):
    return [str((n >> (8 * i)) & 0xFF) for i in range(4)]


def map_update(path, key_bytes, value_bytes):
    rc, out = sh(["bpftool", "map", "update", "pinned", path,
                  "key", *key_bytes, "value", *value_bytes])
    if rc != 0:
        raise RuntimeError(f"map update {path} failed: {out}")


def set_meta(idx, val):
    map_update(META, u32le(idx), u32le(val))


def set_rule(i, verdict, proto, lo, hi, saddr_set=0, daddr_set=0, keep_state=0, route_gw=0, queue_id=0):
    val = (u32le(verdict) + u32le(proto) + u32le(lo) + u32le(hi)
           + u32le(saddr_set) + u32le(daddr_set) + u32le(keep_state)
           + u32le(route_gw) + u32le(queue_id))
    map_update(RULES, u32le(i), val)


def set_cidr4(prefixlen, octets, mask):
    key = u32le(prefixlen) + [str(o) for o in octets]
    map_update(CIDR4, key, u32le(mask))


def configure(default_pass, rules):
    set_meta(0, 1)                       # version
    set_meta(1, 1 if default_pass else 0)  # default action
    set_meta(2, len(rules))              # rule_count
    for i, r in enumerate(rules):
        v, p, lo, hi = r[0], r[1], r[2], r[3]
        ss = r[4] if len(r) > 4 else 0
        ds = r[5] if len(r) > 5 else 0
        ks = r[6] if len(r) > 6 else 0
        gw = r[7] if len(r) > 7 else 0
        qi = r[8] if len(r) > 8 else 0
        set_rule(i, v, p, lo, hi, ss, ds, ks, gw, qi)


def craft(proto, dport=0, ethertype=0x0800, src=(10, 0, 0, 2), dst=(10, 0, 0, 1)):
    mac = b"\x02\x00\x00\x00\x00\x01"
    eth = mac + mac + struct.pack("!H", ethertype)
    if ethertype != 0x0800:
        return eth + b"\x00" * 40
    if proto == TCP:
        l4 = struct.pack("!HH", 40000, dport) + b"\x00" * 16     # 20-byte tcphdr
    elif proto == UDP:
        l4 = struct.pack("!HHHH", 40000, dport, 8, 0)            # 8-byte udphdr
    elif proto == ICMP:
        l4 = struct.pack("!BBHHH", 8, 0, 0, 0, 0)                # icmp echo
    else:
        l4 = b"\x00" * 8
    total = 20 + len(l4)
    ip = struct.pack("!BBHHHBBH4s4s", (4 << 4) | 5, 0, total, 1, 0, 64,
                     proto, 0, bytes(src), bytes(dst))
    return eth + ip + l4


def run_prog(packet):
    with open(DATA_IN, "wb") as f:
        f.write(packet)
    rc, out = sh(["bpftool", "prog", "run", "pinned", PROG,
                  "data_in", DATA_IN, "data_out", DATA_OUT, "repeat", "1"])
    m = re.search(r"[Rr]eturn value:\s*(\d+)", out)
    if not m:
        raise RuntimeError(f"could not parse retval: {out}")
    return int(m.group(1))


def counter_packets(idx):
    rc, out = sh(["bpftool", "-j", "map", "lookup", "pinned", COUNTERS,
                  "key", *u32le(idx)])
    try:
        obj = json.loads(out)
        val = obj["value"]
        data = bytes(int(x, 16) & 0xFF for x in val)
        return int.from_bytes(data[:8], "little")
    except Exception:
        return -1


results = []


def check(desc, default_pass, rules, pkt, expected):
    configure(default_pass, rules)
    got = run_prog(pkt)
    ok = got == expected
    results.append((ok, desc, expected, got))


P = lambda proto, dport=0: craft(proto, dport)
ARP = craft(0, 0, 0x0806)

# 1. default deny / pass, no rules
check("deny: icmp", False, [], P(ICMP), XDP_DROP)
check("deny: tcp/80", False, [], P(TCP, 80), XDP_DROP)
check("deny: udp/53", False, [], P(UDP, 53), XDP_DROP)
check("pass: icmp", True, [], P(ICMP), XDP_PASS)
check("pass: tcp/80", True, [], P(TCP, 80), XDP_PASS)
check("pass: udp/53", True, [], P(UDP, 53), XDP_PASS)

# 2. allow by protocol under deny
check("allow icmp -> icmp", False, [(PASS_V, ICMP, 0, 0)], P(ICMP), XDP_PASS)
check("allow icmp -> tcp", False, [(PASS_V, ICMP, 0, 0)], P(TCP, 80), XDP_DROP)
check("allow icmp -> udp", False, [(PASS_V, ICMP, 0, 0)], P(UDP, 53), XDP_DROP)
check("allow tcp  -> tcp", False, [(PASS_V, TCP, 0, 0)], P(TCP, 80), XDP_PASS)
check("allow tcp  -> udp", False, [(PASS_V, TCP, 0, 0)], P(UDP, 80), XDP_DROP)
check("allow tcp  -> icmp", False, [(PASS_V, TCP, 0, 0)], P(ICMP), XDP_DROP)
check("allow udp  -> udp", False, [(PASS_V, UDP, 0, 0)], P(UDP, 53), XDP_PASS)
check("allow udp  -> tcp", False, [(PASS_V, UDP, 0, 0)], P(TCP, 53), XDP_DROP)

# 3. single-port allow under deny
check("allow tcp/443 -> 443", False, [(PASS_V, TCP, 443, 443)], P(TCP, 443), XDP_PASS)
check("allow tcp/443 -> 80", False, [(PASS_V, TCP, 443, 443)], P(TCP, 80), XDP_DROP)
check("allow tcp/443 -> udp443", False, [(PASS_V, TCP, 443, 443)], P(UDP, 443), XDP_DROP)
check("allow udp/53 -> 53", False, [(PASS_V, UDP, 53, 53)], P(UDP, 53), XDP_PASS)
check("allow udp/53 -> 54", False, [(PASS_V, UDP, 53, 53)], P(UDP, 54), XDP_DROP)

# 4. port range 1000-2000 under deny
rng = [(PASS_V, TCP, 1000, 2000)]
check("range tcp 1000", False, rng, P(TCP, 1000), XDP_PASS)
check("range tcp 1500", False, rng, P(TCP, 1500), XDP_PASS)
check("range tcp 2000", False, rng, P(TCP, 2000), XDP_PASS)
check("range tcp 999", False, rng, P(TCP, 999), XDP_DROP)
check("range tcp 2001", False, rng, P(TCP, 2001), XDP_DROP)
check("range tcp 1", False, rng, P(TCP, 1), XDP_DROP)

# 5. proto-any rule passes everything
anyr = [(PASS_V, 0, 0, 0)]
check("any-proto -> tcp", False, anyr, P(TCP, 12345), XDP_PASS)
check("any-proto -> udp", False, anyr, P(UDP, 7), XDP_PASS)
check("any-proto -> icmp", False, anyr, P(ICMP), XDP_PASS)

# 6. block rule under default pass
check("pass+block udp/53 -> udp53", True, [(DROP_V, UDP, 53, 53)], P(UDP, 53), XDP_DROP)
check("pass+block udp/53 -> udp54", True, [(DROP_V, UDP, 53, 53)], P(UDP, 54), XDP_PASS)
check("pass+block udp/53 -> tcp53", True, [(DROP_V, UDP, 53, 53)], P(TCP, 53), XDP_PASS)
check("pass+block tcp* -> tcp", True, [(DROP_V, TCP, 0, 0)], P(TCP, 80), XDP_DROP)
check("pass+block tcp* -> udp", True, [(DROP_V, TCP, 0, 0)], P(UDP, 80), XDP_PASS)
check("pass+block tcp* -> icmp", True, [(DROP_V, TCP, 0, 0)], P(ICMP), XDP_PASS)

# 7. multi-rule precedence (first match wins)
prec1 = [(DROP_V, TCP, 22, 22), (PASS_V, TCP, 22, 22)]
check("precedence drop-then-pass tcp/22", False, prec1, P(TCP, 22), XDP_DROP)
prec2 = [(PASS_V, TCP, 80, 80), (DROP_V, TCP, 0, 0)]
check("precedence pass80-then-dropall -> 80", False, prec2, P(TCP, 80), XDP_PASS)
check("precedence pass80-then-dropall -> 443", False, prec2, P(TCP, 443), XDP_DROP)
prec3 = [(PASS_V, ICMP, 0, 0), (DROP_V, TCP, 22, 22)]
check("mixed -> icmp pass", False, prec3, P(ICMP), XDP_PASS)
check("mixed -> tcp22 drop", False, prec3, P(TCP, 22), XDP_DROP)
check("mixed -> tcp80 default deny", False, prec3, P(TCP, 80), XDP_DROP)

# 8. reject verdict degrades to drop
check("reject tcp/23 -> 23", True, [(REJECT_V, TCP, 23, 23)], P(TCP, 23), XDP_DROP)
check("reject tcp/23 -> 24", True, [(REJECT_V, TCP, 23, 23)], P(TCP, 24), XDP_PASS)

# 9. non-IP packets pass through even under deny
check("arp under deny", False, [], ARP, XDP_PASS)
check("arp under deny + rules", False, [(DROP_V, TCP, 0, 0)], ARP, XDP_PASS)

# 10. boundary single-port via range lo==hi already; add explicit
check("single via range tcp/8080", False, [(PASS_V, TCP, 8080, 8080)], P(TCP, 8080), XDP_PASS)
check("single via range tcp/8081 drop", False, [(PASS_V, TCP, 8080, 8080)], P(TCP, 8081), XDP_DROP)

# 11. multiple allows, distinct ports
multi = [(PASS_V, TCP, 22, 22), (PASS_V, TCP, 443, 443), (PASS_V, UDP, 53, 53)]
check("multi allow tcp/22", False, multi, P(TCP, 22), XDP_PASS)
check("multi allow tcp/443", False, multi, P(TCP, 443), XDP_PASS)
check("multi allow udp/53", False, multi, P(UDP, 53), XDP_PASS)
check("multi allow tcp/80 deny", False, multi, P(TCP, 80), XDP_DROP)
check("multi allow udp/54 deny", False, multi, P(UDP, 54), XDP_DROP)
check("multi allow icmp deny", False, multi, P(ICMP), XDP_DROP)

# 12. counter accounting: 5 matching packets -> counter==5
configure(False, [(PASS_V, TCP, 443, 443)])
map_update(COUNTERS, u32le(0), ["0"] * 16)  # zero packets+bytes for rule 0
pkt = P(TCP, 443)
for _ in range(5):
    run_prog(pkt)
cnt = counter_packets(0)
results.append((cnt == 5, "counter rule0 == 5 after 5 hits", 5, cnt))

# 13. udp range
urng = [(PASS_V, UDP, 5000, 5005)]
check("udp range 5000", False, urng, P(UDP, 5000), XDP_PASS)
check("udp range 5005", False, urng, P(UDP, 5005), XDP_PASS)
check("udp range 5006 drop", False, urng, P(UDP, 5006), XDP_DROP)

# 14. per-rule SOURCE set membership (set id 1 = 10.0.0.0/8 -> bit 1 -> mask 2)
set_cidr4(8, [10, 0, 0, 0], 2)
src1 = [(PASS_V, TCP, 22, 22, 1, 0)]
check("src in set1 tcp/22", False, src1, craft(TCP, 22, src=(10, 5, 5, 5)), XDP_PASS)
check("src not in set1", False, src1, craft(TCP, 22, src=(8, 8, 8, 8)), XDP_DROP)
check("src in set1 wrong port", False, src1, craft(TCP, 80, src=(10, 5, 5, 5)), XDP_DROP)

# 15. per-rule DESTINATION set membership (reuse set 1)
dst1 = [(PASS_V, TCP, 443, 443, 0, 1)]
check("dst in set1 tcp/443", False, dst1, craft(TCP, 443, dst=(10, 1, 1, 1)), XDP_PASS)
check("dst not in set1", False, dst1, craft(TCP, 443, dst=(1, 1, 1, 1)), XDP_DROP)

# 16. set discrimination: set 2 = 192.168.0.0/16 -> bit 2 -> mask 4
set_cidr4(16, [192, 168, 0, 0], 4)
s1 = [(PASS_V, TCP, 0, 0, 1, 0)]
s2 = [(PASS_V, TCP, 0, 0, 2, 0)]
check("set2 src 192.168.x pass", False, s2, craft(TCP, 1, src=(192, 168, 1, 1)), XDP_PASS)
check("set2 src 10.x drop", False, s2, craft(TCP, 1, src=(10, 1, 1, 1)), XDP_DROP)
check("set1 src 10.x pass", False, s1, craft(TCP, 1, src=(10, 9, 9, 9)), XDP_PASS)
check("set1 src 192.168.x drop", False, s1, craft(TCP, 1, src=(192, 168, 1, 1)), XDP_DROP)

# 17. multi-membership: 172.16.0.0/24 in set1 AND set2 -> mask 2|4 = 6
set_cidr4(24, [172, 16, 0, 0], 6)
check("multimember via set1", False, s1, craft(TCP, 1, src=(172, 16, 0, 5)), XDP_PASS)
check("multimember via set2", False, s2, craft(TCP, 1, src=(172, 16, 0, 5)), XDP_PASS)

# 18. saddr_set=0 ignores membership (any source)
check("saddr_set=0 any src", False, [(PASS_V, TCP, 22, 22, 0, 0)],
      craft(TCP, 22, src=(203, 0, 113, 9)), XDP_PASS)

# 19. combined source AND destination set constraints
both = [(PASS_V, TCP, 0, 0, 1, 1)]
check("both src+dst in set1", False, both,
      craft(TCP, 1, src=(10, 1, 1, 1), dst=(10, 2, 2, 2)), XDP_PASS)
check("src in set1 dst outside", False, both,
      craft(TCP, 1, src=(10, 1, 1, 1), dst=(8, 8, 8, 8)), XDP_DROP)
check("dst in set1 src outside", False, both,
      craft(TCP, 1, src=(8, 8, 8, 8), dst=(10, 2, 2, 2)), XDP_DROP)

# 20. conntrack: keep_state creates entries, ESTABLISHED flows bypass rule scan
configure(False, [(PASS_V, TCP, 443, 443, 0, 0, 1)])  # keep_state=1
pkt_ct = craft(TCP, 443)
# Run once to create conntrack entry (via keep_state)
run_xdp(pkt_ct)
# Second run should hit ESTABLISHED fastpath and PASS
check("ct: keep_state+established pass", False, [(PASS_V, TCP, 443, 443, 0, 0, 1)],
      P(TCP, 443), XDP_PASS)
# Without keep_state — no fastpath, but rule still matches
check("ct: no-keep_state still matches rule", False, [(PASS_V, TCP, 8080, 8080)],
      P(TCP, 8080), XDP_PASS)

# ---- report ----
passed = sum(1 for r in results if r[0])
total = len(results)
for ok, desc, exp, got in results:
    if not ok:
        print(f"  FAIL: {desc} (expected {exp}, got {got})")
print(f"\nlpf datapath matrix: {passed}/{total} passed")
sys.exit(0 if passed == total else 1)
