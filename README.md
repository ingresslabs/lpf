# lpf

PF-style firewall control plane for Linux. Replaces nftables, tc, and ip route with a single policy language. Guarded apply, Z3 verification, eBPF datapath.

```sh
lpf check policy.lpf && lpf apply --confirm 60s policy.lpf && lpf confirm
```

| Command | Purpose |
|---|---|
| `lpf apply --confirm 60s` | Guarded apply with auto-rollback |
| `lpf plan --json` | Plan rendering (JSON) |
| `lpf explain --json` | Packet trace through policy |
| `lpf verify consistency` | Dead/shadowed rule detection |
| `lpf verify equivalence` | Prove two policies identical |
| `lpf verify reachable` | Reachability proof |
| `lpf ebpf show` | Render eBPF map image |
| `lpf ebpf load --run` | Atomic eBPF map swap |
| `lpf test --junit` | Policy unit tests, JUnit CI output |
| `lpf tools --format openai` | AI agent tool schemas |

## Install

```sh
sudo apt-get install -y opam clang llvm bpftool
opam install . --deps-only --with-test
make && sudo make install
make packages   # .deb, .rpm, binary, CNI (via Docker)
```

## Examples

```sh
# Dead rule detection
lpf verify consistency fixtures/policies/basic.lpf

# Equivalence: does the NAT gateway render the same?
lpf verify equivalence fixtures/policies/basic.lpf --second configs/policies/nat-gateway.lpf

# Reachability: can TCP/443 ever pass?
lpf verify reachable --action pass --constraint proto=tcp,port=443 fixtures/policies/basic.lpf

# Full formal pass
lpf verify check-all fixtures/policies/ebpf-full.lpf

# eBPF: render map image
lpf ebpf show fixtures/policies/ebpf-full.lpf

# eBPF: load into running kernel
sudo env LPF_BPF_OBJECT=/opt/lpf/bpf/lpf_kern.o lpf ebpf load --run fixtures/policies/ebpf-full.lpf

# eBPF: diff live state vs policy
sudo lpf ebpf observe > /tmp/observed.txt
lpf ebpf diff --observed /tmp/observed.txt fixtures/policies/ebpf-full.lpf
```

## Properties

- **OCaml** — type-safe, memory-safe, no runtime crashes
- **Z3 SMT** — mathematical proofs over all possible packets
- **eBPF datapath** — atomic map swaps, per-CPU counters, ring buffer
- **552 E2E scenarios** across 8+ Linux kernels in Firecracker microVMs
- **5-distro CI** — Debian, Ubuntu 22/24, Alpine, Fedora

[Commands](docs/COMMANDS.md) · [Policies](configs/policies) · [Ansible](ansible/roles/lpf) · [Docker](docker)
