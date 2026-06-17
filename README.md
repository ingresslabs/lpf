# lpf

`lpf` is a planned PF-style control plane for Linux networking.

The goal is not to port OpenBSD PF into the Linux kernel. The goal is to give
Linux a coherent firewall/router operations layer:

- readable policy files
- safe atomic apply with rollback
- packet decision explainability
- policy tests
- dynamic tables
- nftables-backed filtering and NAT
- policy routing through `ip rule` and route tables
- shaping through `tc`
- state inspection through conntrack
- structured logging through NFLOG/ulogd
- Bonsai/Bonsai_web browser UI for safe policy review and guarded apply

All product command and feature code is written in OCaml.

## Current Status

This is an early private implementation. The CLI exposes the command surface
and help text. `lpf man generate`, `lpf man check`, and `lpf man install` are
implemented from OCaml command metadata.

The first policy-language slice is implemented for `lpf check` and `lpf fmt`.
It parses and formats a small policy subset covering default actions,
interfaces, macros, tables, queues, anchors, pass/block rules, rule logging,
NAT, redirects, and route-to annotations with OCaml tests and valid/invalid
fixtures. The parser is tokenized and carries column-level spans for
actionable diagnostics.

The first typed IR slice is implemented for the Phase 1 policy surface. `lpf
check` now lowers valid policies into IR and reports shadowed-rule warnings.
`lpf plan [--json]` emits a versioned backend-neutral semantic JSON plan with a
stable checksum. Supplied nftables readback/diff input is supported for
`lpf`-owned tables, and live readback can run `nft list ruleset` for read-only
comparison. Apply, rollback, and installed networking mutation are
intentionally not implemented yet.

The first read-only nftables renderer is implemented behind `lpf rules show
<policy>`. It renders deterministic rules for review and tests, but it does not
inspect installed host state or apply changes. `lpf rules diff --observed
<ruleset> <policy>` compares rendered intent with supplied observed ruleset
text and reports only `lpf`-owned nftables table differences. `lpf rules diff
--live <policy>` uses the same diff path with live `nft list ruleset` output.
The top-level `lpf diff <policy>` command is also implemented as a read-only
live nftables diff, with `--observed` fixture input and `--json` status output.

## Planned CLI

```sh
lpf check /etc/lpf.conf
lpf plan /etc/lpf.conf
lpf diff /etc/lpf.conf
lpf apply /etc/lpf.conf --confirm 60s
lpf confirm
lpf rollback
lpf explain from 10.0.0.5 to 1.1.1.1 proto tcp port 443
lpf test policy-tests.yaml
lpf table threats add 203.0.113.10
lpf ui serve --mock
lpf man generate
lpf history
lpf support-bundle
```

See [docs/COMMANDS.md](docs/COMMANDS.md) for the command contract and
[docs/PLAN.md](docs/PLAN.md) for the implementation plan. The UI architecture
is documented in [docs/UI.md](docs/UI.md).

## Build

The intended build path is:

```sh
opam switch create . ocaml-base-compiler.5.2.1
opam install . --deps-only --with-test
dune build
dune runtest
```

## Kernel Validation

Backend-affecting features must pass the five-kernel matrix described in
[docs/KERNEL_LAB_MATRIX.md](docs/KERNEL_LAB_MATRIX.md).

## Man Pages

Generated pages live in `man/generated/` and are checked with:

```sh
lpf man check
```
