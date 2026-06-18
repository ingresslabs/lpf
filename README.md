# lpf: The Next-Generation Linux Firewall

[![CI](https://github.com/avkcode/lpf/actions/workflows/ci.yml/badge.svg)](https://github.com/avkcode/lpf/actions/workflows/ci.yml)

`lpf` brings the elegance and safety of OpenBSD's PF (Packet Filter) to Linux, supercharged with modern capabilities. 

Tired of juggling `iptables`, `nftables`, `tc`, and `ip route`? `lpf` provides a single, coherent control plane with human-readable policies, guarded deployments, and mathematically verified security.

But `lpf` is more than just a wrapper. It introduces two game-changing features to Linux networking: **Formal Verification** and a **Native eBPF/XDP Dataplane**.

---

## 🚀 Game-Changing Features

### 1. Mathematical Formal Verification (`lpf prove`)
Stop guessing if your firewall is secure. `lpf` translates your policy into a strict Intermediate Representation (IR) and uses the **Z3 SMT Solver** to mathematically prove your security invariants. 

If you assert that your database is isolated, `lpf` will either prove it mathematically or provide the exact packet headers that would bypass your rules.

```sh
# Prove that absolutely no traffic reaches the database port, unless it comes from the API servers
$ lpf prove "block in from any to <db_subnet> port 5432 unless from <api_servers>" /etc/lpf.conf
✅ Proof successful: Invariant holds against all possible packets.
```

### 2. Native eBPF / XDP Dataplane (`lpf ebpf`)
Want to drop packets before the Linux kernel even allocates memory for them? `lpf` can act as a **Generic CO-RE eBPF Engine**.

Instead of rendering to `nftables`, `lpf` compiles your policy directly into hardware-accelerated eBPF byte-code attached to the XDP (ingress) and TC (egress) hooks.

* **Line-Rate Performance:** Drops packets millions of times faster than Netfilter.
* **Hardware NAT:** Stateful NAT and Port Forwarding executed directly in the network card buffer.
* **Stateful Conntrack:** Built-in LRU Hash Maps track connection 5-tuples for instant return-traffic bypass.
* **Zero-Overhead Logging:** Blocked packets are shipped to user-space via BPF Ring Buffers.

```sh
# Compile the policy into a native C eBPF object
$ lpf ebpf /etc/lpf.conf > lpf_engine.c
$ clang -O2 -target bpf -c lpf_engine.c -o lpf_engine.o

# Instantly enforce the ruleset in the kernel
$ bpftool prog loadall lpf_engine.o /sys/fs/bpf/lpf
```

---

## 🛡️ Safe & Predictable Operations

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

## 🤖 Automation & AI Ready

`lpf` is built for machine consumption. Every operational command supports structured JSON output (`--json`), making it trivial to integrate with **Ansible**, **Terraform**, or custom dashboards.

Furthermore, `lpf` natively exposes **Tool Calling Schemas** for AI Agents.

```sh
# Give an LLM the ability to manage your firewall securely
$ lpf tools --format openai > tools.json
$ lpf tools --format system-prompt > prompt.txt
```

---

## 📖 Quick Start

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

## ⚙️ Advanced CLI Usage

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

## Configuration & Architecture
- `LPF_VAR_DIR` — runtime state directory (default: `/var/lib/lpf`). Used for rollback preimages and history.
- Written entirely in **OCaml** for memory safety and strict typing.
- Validated via isolated **Firecracker microVM** end-to-end tests.
