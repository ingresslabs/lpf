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

### `lpf check <policy>`

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

### `lpf fmt <policy>`

Format policy files deterministically. This enables code review and generated
policy normalization.

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

### `lpf diff <policy>`

Compare the generated plan with current host state. Output must show semantic
changes, not only raw backend text.

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

### `lpf table <name> <operation>`

Manage dynamic tables without full policy reload.

Operations:

- `add`
- `delete`
- `replace`
- `show`
- `flush`
- `counters`

### `lpf state <operation>`

Inspect and manage conntrack state.

Operations:

- `list`
- `show`
- `kill`
- `flush-policy`

### `lpf rules show`

Show generated or installed backend rules with source-policy annotations.

### `lpf history`

Show applied policy versions, operator, timestamp, checksum, test result, and
rollback availability.

### `lpf import <source>`

Import existing firewall state into a readable `lpf` starting point.

Initial importers:

- `nftables`
- `iptables-save`
- `ufw`
- `firewalld`

### `lpf support-bundle`

Create a redacted diagnostic bundle. It must never include raw secrets,
private keys, full packet payloads, or unredacted host inventory.

### `lpf ui <operation>`

Operate the Bonsai/Bonsai_web UI.

Operations:

- `serve --mock`
- `serve --listen <addr:port>`
- `build`
- `test`

The UI must call typed OCaml API endpoints and must never execute backend host
commands directly from browser code.

### `lpf kernel-matrix`

Plan or run kernel compatibility validation. This command owns the five-latest
kernel rule and Lab 141 evidence contract.

### `lpf man <operation>`

Generate, check, and install man pages from OCaml command metadata.

Operations:

- `generate`
- `check`
- `install`
