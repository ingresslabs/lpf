# lpf

`lpf` is an OCaml-first PF-style control plane for Linux networking.

The goal is to give Linux a coherent firewall/router operations layer:

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

All product command and feature code is implemented in OCaml.

## Current Status

All 15 CLI commands are implemented with OCaml handlers:

- `lpf check` / `lpf fmt` — parse, validate, and format policy files
- `lpf plan` — compile policy to typed JSON plan with stable checksums
- `lpf diff` — compare planned vs live host state (nftables, tc, routing)
- `lpf apply` / `lpf confirm` / `lpf rollback` — guarded atomic apply with rollback preimages
- `lpf explain` — static packet evaluator with shadow analysis
- `lpf test` — policy assertion fixtures with JUnit output
- `lpf rules` — render and diff backend rules (nftables, tc, routing)
- `lpf table` / `lpf state` — dynamic table and conntrack management
- `lpf history` — apply history with rollback points
- `lpf e2e` — Firecracker guest networking validation (550 default scenarios, up to 1000)
- `lpf man` / `lpf version` / `lpf help`

Backends: nftables (rendering, diff, live readback), tc (compilation, live readback), policy routing (compilation, live readback).

17 test files, 22 library modules, 18 generated man pages.

## CLI

```sh
lpf check /etc/lpf.conf
lpf plan --json /etc/lpf.conf
lpf plan --backend tc /etc/lpf.conf
lpf plan --backend routing /etc/lpf.conf
lpf diff --live /etc/lpf.conf
lpf diff --backend tc --live /etc/lpf.conf
lpf apply /etc/lpf.conf --confirm 60s
lpf confirm
lpf rollback
lpf rollback <policy-id>
lpf explain from 10.0.0.5 to 1.1.1.1 proto tcp port 443 /etc/lpf.conf
lpf test fixtures/tests/basic.lpf.test
lpf rules show /etc/lpf.conf
lpf rules diff --live /etc/lpf.conf
lpf table threats add 203.0.113.10
lpf table threats delete 203.0.113.10
lpf state list
lpf history
lpf e2e run --scenario-count 480 --junit evidence/junit.xml
lpf man generate
```

See [docs/COMMANDS.md](docs/COMMANDS.md) for the command contract and
[docs/PLAN.md](docs/PLAN.md) for the implementation plan.

## Build

```sh
opam switch create . ocaml-base-compiler.5.2.1
opam install . --deps-only --with-test
dune build
dune runtest
```

## Configuration

- `LPF_VAR_DIR` — runtime state directory (default: `/var/lib/lpf`). Set to a writable path if `/var/lib` is unavailable, e.g. `export LPF_VAR_DIR=/tmp/lpf-var`.

## Kernel Validation

Backend-affecting features must pass kernel compatibility validation as described in [docs/PLAN.md](docs/PLAN.md).

## Man Pages

Generated pages live in `man/generated/` and are checked with:

```sh
lpf man check
```
