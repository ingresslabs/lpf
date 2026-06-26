# lpf: The Next-Generation Linux Firewall

`lpf` replaces `iptables`, `nftables`, `tc`, and `ip route` with a single PF-style
policy language, guarded deployments, formal verification, and an eBPF datapath.

```sh
lpf check policy.lpf && lpf apply --confirm 60s policy.lpf && lpf confirm
```

| Capability | Command |
|---|---|
| Guarded apply with auto-rollback | `lpf apply --confirm 60s` |
| Packet explainability (trace any packet) | `lpf explain --json ...` |
| Z3 formal equivalence proof | `lpf verify equiv old.lpf new.lpf` |
| Dead rule detection | `lpf verify check policy.lpf` |
| Reachability proof (all packets) | `lpf verify reachable --dst 10.0.0.1 --dport 22` |
| eBPF map compilation | `lpf ebpf show policy.lpf` |
| Atomic eBPF updates (zero packet loss) | `lpf ebpf load --script policy.lpf` |
| Multi-backend (nftables+tc+routing+eBPF) | `lpf plan --backend tc policy.lpf` |
| JSON everywhere for automation | `lpf plan --json policy.lpf` |
| AI agent tool schemas | `lpf tools --format openai` |
| Firewall unit tests with JUnit CI | `lpf test --junit report.xml tests/*.lpf.test` |
| Ansible role for install + control | `ansible-playbook playbooks/install.yml` |

## Install

```sh
opam install . --deps-only --with-test && dune build && dune install
make docker    # 5-distro CI images (Debian, Ubuntu 22/24, Alpine, Fedora)
make deb rpm   # system packages
```

## Verifiable & production-grade

- **OCaml** — memory-safe, strictly typed, no null/bounds crashes
- **Z3 SMT solver** — mathematical proofs for ALL possible packets
- **eBPF datapath** — atomic map version swaps, per-CPU counters, ring buffer
- **552-scenario E2E** in Firecracker microVMs across 8+ Linux kernels
- **5-distro Jenkins CI** with Docker, Firecracker, and Ansible pipelines

[Commands](docs/COMMANDS.md) · [Policies](configs/policies) · [Ansible](ansible/roles/lpf) · [Docker](docker)
