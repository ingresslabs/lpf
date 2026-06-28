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
| Z3 formal equivalence proof | `lpf verify equivalence old.lpf --second new.lpf` |
| Dead rule detection | `lpf verify consistency policy.lpf` |
| Reachability proof (all packets) | `lpf verify reachable --action pass --constraint port=443 policy.lpf` |
| eBPF map compilation | `lpf ebpf show policy.lpf` |
| Atomic eBPF updates (zero packet loss) | `lpf ebpf load --run policy.lpf` |
| Multi-backend (nftables+tc+routing+eBPF) | `lpf plan --backend tc policy.lpf` |
| JSON everywhere for automation | `lpf plan --json policy.lpf` |
| AI agent tool schemas | `lpf tools --format openai` |
| Firewall unit tests with JUnit CI | `lpf test --junit report.xml tests/*.lpf.test` |
| Ansible role for install + control | `ansible-playbook playbooks/install.yml` |

## Z3 verification examples

The `lpf verify` command delegates to the optional `lpf-verify` binary. On a
Linux verifier host, install Z3 and make sure `lpf-verify` is on `PATH`:

```sh
sudo apt-get update
sudo apt-get install -y z3 libz3-dev
lpf-verify --help
```

Check a policy for rules that can never match:

```sh
lpf verify consistency fixtures/policies/basic.lpf
```

Prove two policies make the same decision for every possible packet:

```sh
lpf verify equivalence \
  fixtures/policies/basic.lpf \
  --second fixtures/policies/basic.lpf
```

Ask Z3 whether a packet can reach a target action under constraints:

```sh
lpf verify reachable \
  --action pass \
  --constraint proto=tcp,port=443 \
  fixtures/policies/basic.lpf
```

Run the full formal pass, including rule coverage, minimization, and eBPF
backend equivalence:

```sh
lpf verify check-all fixtures/policies/ebpf-full.lpf
```

## eBPF datapath examples

Render the typed eBPF policy image without touching the host:

```sh
lpf ebpf show fixtures/policies/ebpf-full.lpf
```

Generate the `bpftool` loader script for review or CI artifact capture:

```sh
lpf ebpf load fixtures/policies/ebpf-full.lpf > /tmp/lpf-ebpf-load.sh
```

Load the image on a BTF-capable kernel with a verified CO-RE object:

```sh
sudo env LPF_BPF_OBJECT=/opt/lpf/bpf/lpf_kern.o \
  lpf ebpf load --run fixtures/policies/ebpf-full.lpf
```

Observe counters or diff a saved image against intended policy:

```sh
sudo lpf ebpf observe
lpf ebpf diff --observed /tmp/observed-ebpf.txt fixtures/policies/ebpf-full.lpf
```

eBPF load requires root privileges, `bpftool`, bpffs mounted at `/sys/fs/bpf`,
and kernel BTF at `/sys/kernel/btf/vmlinux`.

## Install

```sh
sudo apt-get update
sudo apt-get install -y opam make gcc clang llvm bpftool libz3-dev
opam install . --deps-only --with-test
make && sudo make install
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
