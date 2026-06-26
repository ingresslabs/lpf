# lpf: The Next-Generation Linux Firewall

`lpf` is a single tool that replaces `iptables`, `nftables`, `tc`, and `ip route`
with a human-readable policy language, guarded deployments, explainable decisions,
formal verification, and an eBPF datapath with atomic updates.

Website: [ingresslabs.github.io/lpf](https://ingresslabs.github.io/lpf/)

---

## Why lpf?

| Problem | lpf solution |
|---|---|
| *Will my new policy lock me out?* | Guarded apply rolls back automatically if you don't confirm |
| *What does this rule actually do?* | `lpf explain` traces any packet through every rule |
| *Is my refactored policy identical?* | `lpf verify equiv` — Z3 proves equivalence for ALL packets |
| *Are any rules dead code?* | `lpf verify check` — Z3 finds every shadowed rule |
| *Can an attacker reach port 22?* | `lpf verify reachable` — Z3 proves reachable or unreachable |
| *Does the eBPF backend match nftables?* | `lpf verify backend-equiv` — formal proof of correctness |
| *How do I deploy without drops?* | Atomic eBPF map version swap — zero packet loss |
| *How do I automate this?* | Ansible role, Docker images, `--json` on every command |

---

## 5-minute quick start

```sh
# Install
opam switch create . ocaml-base-compiler.5.2.1
opam install . --deps-only --with-test
dune build && dune runtest

# Write a policy
cat > /etc/lpf.conf <<'EOF'
set default deny
table <trusted> { 10.0.0.0/8, 192.168.0.0/16 }
pass out proto tcp from any to any port { 80 443 } keep state
pass out proto udp from any to any port 53 keep state
block in from any to any
EOF

# Validate, plan, deploy
lpf check /etc/lpf.conf
lpf diff --live /etc/lpf.conf
lpf apply --confirm 60s /etc/lpf.conf
lpf confirm
```

---

## Superpower 1: Guarded Apply with Auto-Rollback

```sh
# Apply a new policy to a remote server.
# If anything goes wrong, the old state is restored in 60 seconds.
$ lpf apply --confirm 60s /etc/new_policy.lpf

# Verify your SSH still works, traffic is flowing...
$ ssh edge-router uptime

# Everything's fine — promote the change.
$ lpf confirm
```

## Superpower 2: Semantic Diffing

```sh
# See exactly what nftables, TC, and routing rules will change
$ lpf diff --live /etc/lpf.conf

# JSON output for automation
$ lpf diff --live --json /etc/lpf.conf | jq .changes_required
```

## Superpower 3: Packet Explainability

```sh
# Trace a specific packet through every rule
$ lpf explain in eth0 from 10.0.0.5 to 1.1.1.1 proto tcp port 443 /etc/lpf.conf
Packet: in eth0 proto tcp from 10.0.0.5 to 1.1.1.1 port 443
Decision: pass
Matched rule: line 4

# JSON for dashboards
$ lpf explain --json in eth0 from 8.8.8.8 to 10.0.0.1 proto tcp port 22 /etc/lpf.conf
{"packet":...","decision":"block","matching_rule":{"span":{"line":5,...}}}
```

---

## Superpower 4: Z3 Formal Verification

**No other firewall can prove properties about ALL possible packets.** lpf uses
the Z3 SMT solver to answer questions that testing can't.

### Find dead rules
```sh
$ lpf verify check policy.lpf
  line 7 (pass): shadowed by earlier rule(s)
  line 12 (block): shadowed by earlier rule(s)
2 dead rule(s) found
```

### Prove two policies are identical
```sh
$ lpf verify equiv v1.lpf v2.lpf
v1.lpf and v2.lpf differ:
  packet: 8.8.8.8:443 -> 10.0.0.1:443
  v1.lpf: block
  v2.lpf: pass
```
Equivalent → refactor with mathematical certainty.
Different → Z3 hands you the exact counterexample.

### Prove nobody can reach a port
```sh
$ lpf verify reachable --dst 10.0.0.1 --dport 22 policy.lpf
unreachable
```
Not "I tested 100 packets" — proof that zero of the 2^80 possible packets can reach port 22.

### Prove a security invariant holds
```sh
$ lpf verify invariant --dst 8.8.8.8 --dport 443 policy.lpf
invariant holds: no matching packet passes
```

### Generate tests with guaranteed edge coverage
```sh
$ lpf verify generate-tests policy.lpf > tests.lpf.test
$ lpf test tests.lpf.test
OK: 47 passed
```
Z3 produces test cases hitting CIDR low/high boundaries, port 0 and 65535,
IP 0.0.0.0 and 255.255.255.255, plus a witness packet for every rule.

### Prove the eBPF backend is correct
```sh
$ lpf verify backend-equiv --backend ebpf policy.lpf
eBPF backend is equivalent to explain engine for this policy
```

---

## Superpower 5: eBPF Datapath

Compile policy directly to BPF maps — no kernel recompile, no program reload.
Policy updates are atomic map swaps with zero packet loss.

### Compile policy to eBPF
```sh
$ lpf ebpf show fixtures/policies/ebpf-full.lpf
ebpf policy image
  version 1   default deny
  map lpf_rules type array key 4 value 36 entries 24 {
    0  => verdict=drop proto=any saddr_set=banned
    13 => verdict=pass proto=tcp dport=80 id=cgroup:webapp
    22 => verdict=pass proto=tcp dport=80 id=dns:api_gateway
  }
  map lpf_addrs type lpm_trie key 8 value 4 entries 6 { ... }
  map lpf_ports type hash key 4 value 4 entries 24 { ... }
  programs:
    lpf_xdp type xdp if eth0
    lpf_tc type tc if eth0
```

### Atomic versioned deploy (no packet loss)
```sh
$ lpf ebpf load --script policy.lpf > /tmp/deploy.sh
$ sh /tmp/deploy.sh
lpf eBPF version 2 loaded (atomic swap)
```
Maps load as `lpf_rules_v2`, then an atomic 4-byte write flips the version index.
Old version maps are cleaned up. Traffic never stops.

### Per-CPU counters at line rate
```sh
$ bpftool map dump pinned /sys/fs/bpf/lpf/lpf_counters_v2
key: 0  value: {cpu0: 1500042 7500210} {cpu1: 1493621 7468105}
key: 13 value: {cpu0: 420  1260}     {cpu1: 398  1194}
```
No lock contention. Scales to 40Gbps+.

### Ring buffer events for observability
```sh
$ cat /sys/kernel/debug/tracing/trace_pipe
{"type":"rule_match","rule_index":13,"src":"10.0.0.5","dst":"1.1.1.1","port":80,"verdict":"pass"}
{"type":"conntrack_new","src":"10.0.0.5","dst":"1.1.1.1","sport":54321,"dport":80,"proto":"tcp"}
```

### Live diff against running eBPF state
```sh
$ lpf ebpf diff --observed /sys/fs/bpf/lpf policy.lpf
no changes
```

---

## Superpower 6: Multi-Backend Compilation

One `.lpf` policy → four backends simultaneously:

```sh
$ lpf rules show policy.lpf                     # nftables
table inet lpf_filter { chain lpf_forward { ... } }

$ lpf plan --backend tc policy.lpf              # traffic shaping
tc qdisc add dev eth0 root handle 1: htb
tc class add dev eth0 parent 1: classid 1:10 ...

$ lpf plan --backend routing policy.lpf         # policy routing
ip rule add fwmark 0x1 table 100
ip route add default via 10.0.0.1 table 100

$ lpf ebpf show policy.lpf                      # eBPF datapath
map lpf_rules type array entries 24 { ... }
```

---

## Superpower 7: Automation & AI-Ready

### Every command supports `--json`
```sh
$ lpf check --json policy.lpf        # {"valid":true,"diagnostics":[]}
$ lpf plan --json policy.lpf         # {"schema":"lpf.plan.v1","checksum":"md5:..."}
$ lpf state list --json              # [{"src":"10.0.0.1","dst":"1.1.1.1",...}]
$ lpf table trusted counters --json  # [{"element":"10.0.0.0/8","bytes":...}]
```

### AI agent tool calling schemas
```sh
$ lpf tools --format openai > tools.json
$ lpf tools --format system-prompt > prompt.txt
```
LLMs can manage firewalls through structured function calls — no prompt engineering needed.

### Ansible role
```yaml
# ansible/playbooks/install.yml
- name: Deploy lpf
  hosts: firewalls
  roles:
    - lpf
  vars:
    lpf_policy_content: |
      set default deny
      pass out proto tcp from any to any port { 80 443 } keep state
      block in from any to any
```
```sh
$ make ansible          # syntax check + lint + dry-run
$ make docker           # build CI images for all 5 distros
$ make docker-feature   # run 28-step feature suite on all 5
$ make docker-ebpf      # run eBPF E2E with live traffic
```

---

## Superpower 8: Firewall Testing

Write unit tests for your firewall rules:

```sh
$ cat fixtures/tests/basic.lpf.test
test "SSH Access" {
  assert in eth0 from 10.0.0.5 to 192.168.1.1 proto tcp port 22 = pass
}

test "External Block" {
  assert in eth0 from 8.8.8.8 to 10.0.0.1 proto tcp port 22 = block
}

$ lpf test --junit evidence/junit.xml fixtures/tests/*.lpf.test
OK: 12 passed
```

JUnit XML output for CI gating.

---

## Installation

```sh
# From source (OCaml 5.1+)
opam switch create . ocaml-base-compiler.5.2.1
opam install . --deps-only --with-test
dune build && dune install

# Docker (5-distro CI images)
make docker

# Debian/RPM packages
make deb
make rpm
```

---

## Architecture

- Written in **OCaml** — memory-safe, strictly typed, no runtime crashes from null or bounds errors
- **Z3 SMT solver** for formal verification — mathematical proofs about policy behavior
- **eBPF** datapath with atomic map version swaps — no packet loss during updates
- **Multi-backend**: nftables, tc, ip route, eBPF from a single policy
- **Firecracker microVM** validated — 552-scenario E2E catalog across kernel matrix
- **Jenkins CI** with 5-distro Docker + Firecracker + Ansible pipelines
- **GitOps-native**: policy as code, diff as review, guarded deploy with auto-rollback

---

## Policy examples

<details>
<summary>Show all policy examples</summary>

- [Web server](configs/policies/web-server.lpf): public HTTP/HTTPS, restricted SSH, outbound DNS
- [Reverse proxy](configs/policies/reverse-proxy.lpf): public port redirects to internal workload
- [NAT gateway](configs/policies/nat-gateway.lpf): LAN masquerade, blocked hosts, controlled egress
- [Workstation egress](configs/policies/workstation-egress.lpf): default-deny client outbound policy
- [DNS resolver](configs/policies/dns-resolver.lpf): LAN resolver with restricted upstream DNS
- [Bastion host](configs/policies/bastion-host.lpf): operator SSH + managed-host access
- [Database segment](configs/policies/database-segment.lpf): app-to-DB access + DBA management
- [Branch router QoS](configs/policies/branch-router-qos.lpf): NAT, policy routing, traffic shaping
- [WireGuard hub](configs/policies/advanced-wireguard-hub.lpf): hub-and-spoke VPN
- [Dual-WAN routing](configs/policies/advanced-dual-wan-qos.lpf): multi-homed with QoS
- [Reverse proxy DMZ](configs/policies/advanced-reverse-proxy-dmz.lpf): DMZ with hairpin NAT

</details>

---

- [Command reference](docs/COMMANDS.md)
- [Kernel lab matrix](docs/KERNEL_LAB_MATRIX.md)
- [Project plan](docs/PLAN.md)
- [Ansible role](ansible/roles/lpf/)
- [Docker images](docker/)
