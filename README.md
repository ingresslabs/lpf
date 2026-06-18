# lpf: The Next-Generation Linux Firewall

`lpf` brings the elegance and safety of OpenBSD's PF (Packet Filter) to Linux, supercharged with modern capabilities.

Tired of juggling `iptables`, `nftables`, `tc`, and `ip route`? `lpf` provides a single, coherent control plane with human-readable policies, guarded deployments, and explainable decisions.

---

## Core Features

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
