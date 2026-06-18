# lpf: The Next-Generation Linux Firewall

`lpf` brings the elegance and safety of OpenBSD's PF (Packet Filter) to Linux, supercharged with modern capabilities.

Tired of juggling `iptables`, `nftables`, `tc`, and `ip route`? `lpf` provides a single, coherent control plane with human-readable policies, guarded deployments, and explainable decisions.

But `lpf` is more than just a wrapper. It already includes a native eBPF/XDP C backend and keeps formal verification on the roadmap.

---

## Core Features

### Native eBPF / XDP Dataplane (`lpf ebpf`)
Want to drop packets before the Linux kernel even allocates memory for them? `lpf` can generate native eBPF/XDP C source from checked policy IR.

Instead of rendering only to `nftables`, `lpf` can compile policy logic into C that is suitable for `clang -target bpf` and kernel verifier testing.

```sh
# Compile the policy into eBPF C source
$ lpf ebpf /etc/lpf.conf > lpf_xdp.c
$ clang -O2 -target bpf -c lpf_xdp.c -o lpf_xdp.o
```

### Formal Verification Roadmap

`lpf prove` and Z3-backed invariant checks are planned, but they are not part
of the current CLI. Until that command lands with OCaml implementation, tests,
fixtures, and man pages, release CI does not label Z3 proof coverage as
available.

### The Market Landscape: Why Mathematical Proofs Matter

Applying mathematical formal verification to networking has recently shifted from academia to powering the world's most critical infrastructure. However, the market is highly fragmented:

1. **Cloud IAM (e.g., AWS Zelkova):** Translates IAM and S3 bucket policies into SMT formulas (using Z3) to mathematically prove a bucket isn't public. Powers AWS IAM Access Analyzer.
2. **Control Plane Simulation (e.g., Batfish):** Parses thousands of lines of BGP/OSPF configurations from physical routers to simulate the network control plane and map reachability before deployment.
3. **Enterprise Digital Twins (e.g., Forward Networks):** Commercial platforms that ingest live state from every switch and firewall in a corporate network to build a queryable mathematical model of the entire enterprise.

**The Unique Position of `lpf`:**
Historically, formal network verification required either being a massive cloud provider or purchasing six-figure enterprise software. 

`lpf` is aiming to bring Z3-backed formal verification directly to the Linux
command line, alongside a compiler that generates eBPF/XDP C source. That proof
feature remains roadmap work until the CLI, tests, fixtures, and man pages land
together.

---

## Safe & Predictable Operations

Network lockouts are a thing of the past. `lpf` is designed for bulletproof production deployments.

### Guarded Apply with Auto-Rollback
Never lock yourself out of a remote server again.

```sh
# Apply the new policy, but revert it in 60 seconds if you don't confirm
$ lpf apply --confirm 60s /etc/new_policy.lpf

# Test your SSH connection... it works!
$ lpf confirm
```

### Semantic Diffing & Explainability
Know exactly what will happen before you apply.

```sh
# See exactly what nftables/tc/routing rules will change on the host
$ lpf diff --live /etc/lpf.conf

# Ask the static evaluator what it would do with a specific packet
$ lpf explain --src 10.0.0.5 --dst 1.1.1.1 --dport 443 --tcp --in /etc/lpf.conf
```

---

## Automation & AI Ready

`lpf` is built for machine consumption. Every operational command supports structured JSON output (`--json`), making it trivial to integrate with **Ansible**, **Terraform**, or custom dashboards.

Furthermore, `lpf` natively exposes **Tool Calling Schemas** for AI Agents.

```sh
# Give an LLM the ability to manage your firewall securely
$ lpf tools --format openai > tools.json
$ lpf tools --format system-prompt > prompt.txt
```

---

## Quick Start

### 1. Install
```sh
opam switch create . ocaml-base-compiler.5.2.1
opam install . --deps-only --with-test
dune build
dune runtest
```

### 2. Write a Policy (`/etc/lpf.conf`)
```pf
set default deny

interface wan = "eth0"
interface lan = "eth1"

table <trusted> { 10.0.0.0/8, 192.168.0.0/16 }

pass out on lan proto tcp from any to any port 443 keep state
block in on wan from any to any
```

### 3. Validate & Deploy
```sh
lpf check /etc/lpf.conf
lpf diff --live /etc/lpf.conf
lpf apply --confirm 60s /etc/lpf.conf
```

---

## Advanced CLI Usage

**State Inspection & Dynamic Tables:**
Update threat feeds without reloading the firewall.
```sh
lpf table <trusted> add 203.0.113.10
lpf state list --json
lpf state kill --src 10.0.0.1 --dst 10.0.0.2
```

**Testing & CI Integration:**
Write unit tests for your firewall and output JUnit XML for your CI pipeline.
```sh
lpf test --junit evidence/junit.xml fixtures/tests/basic.lpf.test
lpf e2e run --scenario-count 552
```

See [docs/COMMANDS.md](docs/COMMANDS.md) for the full command contract.

---

## Policy Examples

Full policy examples live under [configs/policies](configs/policies). They are
kept behind this collapsed section so the README stays short.

<details>
<summary>Show policy examples</summary>

- [Web server](configs/policies/web-server.lpf): public HTTP/HTTPS, restricted SSH, outbound DNS and updates.
- [Reverse proxy](configs/policies/reverse-proxy.lpf): public port redirects to an internal application listener.
- [NAT gateway](configs/policies/nat-gateway.lpf): LAN masquerade, blocked hosts, and controlled egress.
- [Workstation egress](configs/policies/workstation-egress.lpf): default-deny client outbound policy.
- [DNS resolver](configs/policies/dns-resolver.lpf): LAN resolver with restricted upstream DNS.
- [Bastion host](configs/policies/bastion-host.lpf): operator-only SSH and managed-host access.
- [Database segment](configs/policies/database-segment.lpf): app-to-database access and DBA management.
- [Branch router QoS](configs/policies/branch-router-qos.lpf): NAT, policy routing, and traffic shaping queues.

</details>

---

## Configuration & Architecture
- `LPF_VAR_DIR` - runtime state directory (default: `/var/lib/lpf`). Used for rollback preimages and history.
- Written entirely in **OCaml** for memory safety and strict typing.
- Validated via isolated **Firecracker microVM** end-to-end tests.
