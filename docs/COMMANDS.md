# lpf Command Contract

All `lpf` commands are implemented in OCaml. Commands may invoke Linux tools
such as `nft`, `ip`, `tc`, and `conntrack`, but only through typed OCaml
execution modules with explicit argv construction and structured result
handling.

## Command Completion Rules

Every command must include:

- parser behavior
- `--help` text
- generated man page metadata
- generated man page freshness test
- dry-run behavior where the command changes host state
- structured machine output plan for automation
- human output for operators
- OCaml tests
- policy fixtures
- error messages with actionable recovery guidance

## Commands

### `lpf check [--json] <policy>`

Parse, type-check, validate, and lower a policy into the typed intermediate
representation without touching host state.

Must detect:

- syntax errors
- duplicate object names
- undefined tables, interfaces, queues, and anchors
- shadowed rules that cannot match
- unsafe defaults
- impossible route or queue references
- unsupported backend features on the current kernel

`--json` emits machine-readable validation status and diagnostics.

### `lpf fmt [--check] [--json] <policy>`

Format policy files deterministically. This enables code review and generated
policy normalization.

`--check` fails when formatting would change the file. `--json` emits the
formatted policy text or machine-readable diagnostics.

### `lpf plan [--json] <policy>`

Lower policy into a versioned backend-neutral semantic JSON plan. The current
implementation includes typed policy semantics and a stable checksum; later
backend phases must add:

- nftables table, chain, set, map, rule changes
- NAT changes
- policy-routing changes
- route table changes
- tc qdisc/class/filter changes
- conntrack cleanup actions
- NFLOG/ulogd logging declarations
- sysctl requirements
- rollback preimage

### `lpf diff [--backend nftables|tc|routing] [--observed <path>|--live] [--json] <policy>`

Compare the generated plan with current host state. The current implementation
reads live nftables state by default through typed OCaml argv construction,
extracts only `lpf`-owned nftables tables, and compares them with rendered
intent. `--observed <path>` accepts supplied backend readback text from a file
or `-` for stdin, which keeps fixture tests deterministic. `--json` emits a
machine-readable diff status.

The tc backend compares intended HTB qdisc/class state with live `tc`
readback. The routing backend compares intended fwmark rules and route-table
defaults with live `ip rule` and `ip route` readback. Later backend phases must
extend this into conntrack cleanup, sysctl requirements, and rollback
availability.

### `lpf apply <policy> [--confirm <duration>]`

Apply policy safely. Remote-safe apply is a primary product requirement.

Required behavior:

- validate policy
- generate plan
- capture rollback preimage
- apply atomically where the backend supports it
- start confirmation timer when requested
- rollback automatically if not confirmed
- persist policy history
- emit evidence

### `lpf confirm`

Confirm a pending guarded apply and persist it as the latest known-good state.

### `lpf rollback [policy-id]`

Restore a previous policy. Rollback must cover nftables, policy routing, tc,
dynamic tables, and any sysctls owned by `lpf`.

### `lpf explain ...`

Explain how a hypothetical packet would be handled.

Planned examples:

```sh
lpf explain from 10.0.0.5 to 1.1.1.1 proto tcp port 443
lpf explain in wan from 203.0.113.10 to firewall port 22
```

Output must include:

- final decision
- matching policy rule
- backend rule references
- NAT decision
- route table decision
- queue decision
- log decision
- state behavior

### `lpf test <fixture>`

Run firewall assertions as code. Fixtures must support pass/drop decisions,
NAT expectations, route expectations, queue expectations, and table membership.

### `lpf table [--json] <name> <operation>`

Manage dynamic tables without full policy reload.

Operations:

- `add`
- `delete`
- `replace`
- `show`
- `flush`
- `counters`

`show` and `counters` can emit parsed JSON with `--json`.

### `lpf state [--json] <operation>`

Inspect and manage conntrack state.

Operations:

- `list`
- `show`
- `kill`
- `flush`

`list`, `show`, and `flush` can emit machine-readable JSON with `--json`.

### `lpf rules show [--backend nftables] <policy>`

Render deterministic read-only nftables rules from a checked policy with
source-policy annotations. This command must not inspect installed state or
change host networking state.

### `lpf rules diff [--backend nftables] --observed <ruleset> <policy>`

Compare rendered nftables intent with supplied observed ruleset text. The
current implementation extracts only `lpf`-owned nftables tables from the
observed input and reports deterministic text differences. It does not call
`nft`, inspect the live host, or change host networking state.

### `lpf rules diff [--backend nftables] --live <policy>`

Compare rendered nftables intent with the live ruleset read by `nft list
ruleset`. The command invokes `nft` through typed OCaml argv construction,
extracts only `lpf`-owned nftables tables, and reports the same deterministic
diff format as `--observed`. It is read-only and must not change host
networking state.

### `lpf ebpf <show|load|observe|rollback> [--observed <path>|--live] [--run] <policy>`

Compile policy into an eBPF datapath image of typed BPF maps and an
XDP/TC/cgroup/LSM attach plan, then load, observe, or roll it back.

Operations:

- `show` renders the map image
- `load` emits or runs the bpftool loader
- `observe` reads live per-rule counters
- `rollback` flips the active version map atomically

`--run` executes the generated bpftool loader instead of printing it.
`--observed <path>` reads an observed ebpf image from a file or `-` for stdin.
`--live` reads observed counters from the host via bpftool.

Identity-aware policy is expressed with reserved table names (`cgroup_*`,
`proc_*`, `dns_*`) referenced from rules. eBPF apply requires
CAP_BPF/CAP_NET_ADMIN and a BTF-capable kernel. The loader runs in maps-only
mode unless `LPF_BPF_OBJECT` points to a verified CO-RE object.

### `lpf history`

Show applied policy versions, operator, timestamp, checksum, test result, and
rollback availability.

### `lpf sysctl [--json] <check|diff>`

Check or diff kernel sysctl parameters required by `lpf` before policy
operations depend on them.

Operations:

- `check` reads required keys from `/proc/sys` and reports current key/value
  state
- `diff` compares observed kernel values with the required set and reports
  drift

`lpf sysctl` is read-only. `--json` emits machine-readable check or diff
results for automation and CI preflight use.

### `lpf tools [--format openai|jsonschema|system-prompt]`

Emit JSON tool-calling schemas or a compact automation prompt from the same
OCaml command metadata used for generated man pages.

This command is read-only and must not emit host inventory, credentials, or lab
identifiers.

### `lpf completion [bash|zsh|fish]`

Emit shell completion scripts generated from the same OCaml command metadata
used for command help and man pages.

`lpf completion` is read-only. The output is suitable for sourcing in an
interactive shell or installing into the host shell-completion directory.

### `lpf e2e <run|list>`

Run real end-to-end Linux networking validation inside a disposable lab
environment. The runner is intended for Firecracker VMs or equivalent throwaway
Linux guests with root/CAP_NET_ADMIN.

The default catalog contains 552 deterministic scenarios and accepts 1 to 1000
scenarios per run. Advanced CI jobs normally use 500 to 1000 scenarios per
available kernel; the generic advanced matrix uses 984 scenarios for balanced
family coverage. The catalog is split across:

- nftables accept decisions with real ICMP traffic over veth namespaces
- nftables drop decisions with observed traffic failure
- nftables logging-rule installation and readback
- nftables reject decisions with observed traffic failure and readback
- IPv6 nftables accept/drop decisions with real ICMPv6 traffic
- policy-routing table and rule installation
- tc HTB qdisc/class traffic-shaping installation
- conntrack statistics readback after traffic
- cleanup idempotency and post-remove readback
- intended-vs-observed readback diff evidence
- negative invalid-update rejection

Supported report outputs:

- `--junit <path>` for CI trend reporting
- `--allure-dir <dir>` for Allure result JSON files
- `--evidence-dir <dir>` for a sanitized run manifest, `summary.jsonl`, and
  `scenario-log.jsonl`
- `--kernel-id <id>` to attach the matrix kernel label
- `--dry-run` to render the catalog and reports without changing networking
  state

This command requires root/CAP_NET_ADMIN and must not be run in a production
network namespace.

Scenario evidence includes the intended nftables ruleset or routing/tc action,
the command argv, exit status, stdout/stderr, readback output, and cleanup or
post-remove readback where applicable. Kernel-matrix jobs must keep requested,
available, covered, and missing kernel labels separate; missing kernel images
must never be counted as covered.

### `lpf man <operation>`

Generate, check, and install man pages from OCaml command metadata.

Operations:

- `generate`
- `check`
- `install`
