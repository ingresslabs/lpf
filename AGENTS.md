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

## Man Page Rule

- Every operator-facing command, subcommand, option, config file format, and
  user-visible behavior change MUST update generated man page sources.
- Man pages must be generated from OCaml command/config metadata, not copied
  manually from stale Markdown.
- A command is not complete until `lpf man generate`, `lpf man check`, or the
  equivalent OCaml man-page test proves that generated man pages are current.
- Man page changes must be committed in the same slice as the command or
  behavior change that required them.

## Remote Compile/Test Rule

- Before marking a code change complete, compile and test it on the local host
  and on a remote Linux machine when one is reachable.
- The preferred remote target is the configured `hawking` SSH host or a
  project-approved replacement.
- Remote validation must run from a clean transferred checkout or fresh clone,
  not from an untracked local build directory.
- Do not commit remote logs, host inventories, SSH keys, tokens, or raw
  environment dumps. Report only sanitized command summaries and failures.
- If the remote machine is unreachable or lacks required package managers,
  state the exact blocker in the handoff.

## Bonsai UI Rule

- Browser UI MUST be implemented with Jane Street Bonsai/Bonsai_web.
- Do not introduce React, Vue, Svelte, TypeScript, plain JavaScript app logic,
  Elm, or another browser UI framework.
- The UI must reuse typed OCaml policy, plan, diff, explain, history, and
  evidence models from the CLI/backend libraries. Do not reimplement firewall
  semantics in the browser as string manipulation.
- The browser must never execute `nft`, `ip`, `tc`, `conntrack`, or host shell
  commands. All host changes go through the same OCaml plan/apply engine used
  by the CLI.
- Destructive UI actions must require a reviewed plan, an explicit operator
  confirmation, and the same rollback preimage required by `lpf apply`.
- Bonsai components must have Bonsai/OCaml tests before being marked complete.
- UI code belongs in a separate package/build target from the base CLI so the
  core firewall tool remains buildable on hosts that do not install web
  dependencies.

## Agent Workflow

- Inspect `git status --short --branch` before non-trivial edits.
- Keep changes atomic and commit after each verified slice when the tree is in
  a coherent state.
- Preserve unrelated user changes. Never reset or revert unrelated work.
- Update `docs/COMMANDS.md` when adding, removing, or changing a command.
- Update `docs/PLAN.md` when completing or materially changing milestone scope.
- Update `docs/UI.md` when adding or changing UI surfaces, UI security model,
  UI routes, or Bonsai component contracts.
- Update `docs/MANPAGES.md` when command documentation generation changes.
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
- generated man page coverage
- policy fixture
- dry-run/plan behavior
- failure behavior
- rollback or cleanup behavior
- explain output where applicable
- kernel-matrix evidence for backend-affecting behavior
