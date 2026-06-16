# AGENTS.md: lpf

This repository is the source of truth for `lpf`, an OCaml-first PF-style
control plane for Linux networking. Agents must keep the project coherent:
readable policy language, safe remote apply, explainability, tests, and a
Linux-native backend based on nftables, policy routing, tc, conntrack, and
NFLOG.

## Non-Negotiable Language Rule

- All product commands and product feature logic MUST be implemented in OCaml.
- Do not add Bash, Python, Perl, Ruby, Go, Rust, JavaScript, or ad hoc helper
  programs for product behavior.
- Shell may appear only as unavoidable CI glue or short documentation examples.
- If a Linux operation needs to call `nft`, `ip`, `tc`, `conntrack`, or
  `ulogd`, invoke it from typed OCaml modules with explicit argument vectors.
- Every CLI command must have an OCaml parser, OCaml unit tests, command docs,
  and at least one end-to-end policy fixture before it is considered complete.

## Agent Workflow

- Inspect `git status --short --branch` before non-trivial edits.
- Keep changes atomic and commit after each verified slice when the tree is in
  a coherent state.
- Preserve unrelated user changes. Never reset or revert unrelated work.
- Update `docs/COMMANDS.md` when adding, removing, or changing a command.
- Update `docs/PLAN.md` when completing or materially changing milestone scope.
- Update `docs/KERNEL_LAB_MATRIX.md` when kernel-matrix behavior changes.
- User-visible behavior changes require a changelog entry.

## Kernel Matrix Rule

Before a feature that touches generated backend state is marked complete, it
must be validated against the latest five active kernel.org release lines.
As of 2026-06-16, the pinned initial matrix is:

- `7.1` mainline
- `7.0.12` stable
- `6.18.35` longterm
- `6.12.93` longterm
- `6.6.142` longterm

Refresh this list from https://www.kernel.org/ before a release or any claim
about "latest" kernel coverage.

## Lab 141 Rule

Kernel-matrix evidence must be collected in the
`jenkins-firecracker-cloud-plugin` lab profile identified as `141` whenever
that lab is available. Treat lab credentials and host inventory as secrets.
Do not commit private keys, tokens, raw inventories, or full support bundles.

Each lab run must record:

- lpf git commit
- OCaml compiler version
- Dune version
- kernel version under test
- nftables version
- iproute2 version
- conntrack-tools version
- command under test
- policy fixture path
- generated backend plan checksum
- apply, confirm, rollback, and cleanup result

## Feature Completion Bar

A feature is not done until it has:

- OCaml implementation
- OCaml tests
- command documentation
- policy fixture
- dry-run/plan behavior
- failure behavior
- rollback or cleanup behavior
- explain output where applicable
- kernel-matrix evidence for backend-affecting behavior

