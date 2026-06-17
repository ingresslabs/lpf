# lpf

[![CI](https://github.com/avkcode/lpf/actions/workflows/ci.yml/badge.svg)](https://github.com/avkcode/lpf/actions/workflows/ci.yml)

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

18 CLI commands with OCaml handlers, all with `--json` output for automation:

- `lpf check` / `lpf fmt` — parse, validate, and format policy files (`--json`)
- `lpf plan` — compile policy to typed JSON plan with stable checksums
- `lpf diff` — structured live diff across nftables, tc, routing backends (`--json`)
- `lpf apply` / `lpf confirm` / `lpf rollback` — guarded atomic apply with rollback preimages
- `lpf apply --dry-run` — validate and plan without touching host state
- `lpf explain` — static packet evaluator with shadow analysis (`--json`)
- `lpf test` — policy assertion fixtures with JUnit output
- `lpf rules` — render and diff backend rules (nftables, tc, routing)
- `lpf table` — dynamic table management (add, delete, replace, show, flush, counters) (`--json`)
- `lpf state` — conntrack inspection (list, show, flush, kill) (`--json`)
- `lpf history` — apply history with rollback points (`--json`)
- `lpf e2e` — Firecracker guest networking validation (552 scenarios, up to 1000)
- `lpf tools` — AI agent tool-calling schemas (OpenAI, JSON Schema, system prompts)
- `lpf man` / `lpf version` / `lpf help`

Backends: nftables (rendering, diff, live readback), tc (compilation, live readback, semantic diff), policy routing (compilation, live readback, semantic diff).

21 test files, 24 library modules, 19 generated man pages.

## Quick Start

```sh
# Install
opam switch create . ocaml-base-compiler.5.2.1
opam install . --deps-only --with-test
dune build
dune runtest

# Write and check a policy
cat > /etc/lpf.conf <<'EOF'
set default deny

interface wan = "eth0"
interface lan = "eth1"

table <trusted> { 10.0.0.0/8, 192.168.0.0/16 }

pass out on lan proto tcp from any to any port 443 keep state
block in on wan from any to any
EOF

lpf check /etc/lpf.conf
lpf fmt /etc/lpf.conf
lpf plan --json /etc/lpf.conf
lpf diff --live /etc/lpf.conf
```

## CLI

```sh
# Read-only operations
lpf check --json /etc/lpf.conf
lpf fmt --json /etc/lpf.conf
lpf plan --json /etc/lpf.conf
lpf diff --live --json /etc/lpf.conf
lpf diff --backend tc --live --json /etc/lpf.conf
lpf diff --backend routing --live --json /etc/lpf.conf
lpf explain --json from 10.0.0.5 to 1.1.1.1 proto tcp port 443 /etc/lpf.conf
lpf rules show /etc/lpf.conf
lpf test --junit evidence/junit.xml fixtures/tests/basic.lpf.test

# State mutation
lpf apply --dry-run /etc/lpf.conf
lpf apply /etc/lpf.conf --confirm 60s
lpf confirm
lpf rollback
lpf rollback <policy-id>

# Table management
lpf table threats add 203.0.113.10
lpf table threats delete 203.0.113.10
lpf table threats replace threats.txt
lpf table threats show --json
lpf table threats counters --json
lpf table threats flush

# State inspection
lpf state list --json
lpf state show --json
lpf state kill --src 10.0.0.1 --dst 10.0.0.2
lpf state flush --json

# History
lpf history --json

# E2E validation
lpf e2e run --scenario-count 552 --junit evidence/junit.xml --allure-dir allure-results
lpf e2e run --dry-run --scenario-count 100 --evidence-dir evidence

# Man pages
lpf man generate
lpf man check
lpf man install --prefix /usr/local

# AI agent tools
lpf tools --format openai
lpf tools --format jsonschema
lpf tools --format system-prompt
```

See [docs/COMMANDS.md](docs/COMMANDS.md) for the command contract and
[docs/PLAN.md](docs/PLAN.md) for the implementation plan.

## Automation & AI Agent Usage

lpf is designed for machine consumption. Every read path supports `--json`. Every write path is idempotent with rollback.

**Ansible**: Use `check --json` to validate, `diff --json` to detect drift, `apply --dry-run` to preview, `apply --confirm 60s` plus `confirm` for safe apply, `rollback` for recovery.

**Terraform**: Wraps `plan --json` (state checksum for change detection), `diff --json` (drift), `apply` (create/update), `rollback` (destroy/recovery).

**AI agents**: Use `lpf tools --format openai` to get 11 function-calling schemas, `lpf tools --format system-prompt` for agent instructions, and any `--json` command for structured results.

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
