# lpf Detailed Project Plan

## Product Thesis

Linux packet policy is powerful but fragmented across `nft`, `ip rule`,
`ip route`, `tc`, conntrack, sysctls, and logging tools. `lpf` makes it feel
like one firewall again: readable policy, safe apply, explainable decisions,
testable rules, and operational rollback.

The backend is Linux-native. `lpf` does not replace nftables in the kernel and
does not port OpenBSD PF. It compiles a PF-inspired policy model to Linux
networking primitives.

## Hard Constraints

- Product implementation language: OCaml.
- Backend target: nftables first.
- No product shell scripts.
- Remote safety is a core feature, not a later enhancement.
- Operator-facing commands must have generated man pages from OCaml metadata.
- Code changes must compile and test locally and on a remote Linux machine when
  one is reachable.
- All backend-changing features must pass the five-kernel matrix.
- Lab 141 is the preferred kernel-matrix proving ground.

## Phase 0: Repository And Engineering Baseline

Tasks:

- Create OCaml/Dune skeleton.
- Define public CLI command names.
- Add agent rules.
- Add command contract.
- Add kernel-matrix evidence contract.
- Add man-page generation contract.
- Add changelog.
- Add GitHub Actions for lint/build/test once the repository is pushed.

Exit criteria:

- `dune build` works in CI.
- `dune runtest` works in CI.
- `lpf help` and `lpf version` work.
- Agent rules enforce OCaml-only feature implementation.
- Agent rules enforce generated man pages and remote Linux validation.

## Phase 1: Policy Language MVP

Goal: parse a readable policy file into a typed AST.

Tasks:

- Define lexer/parser in OCaml.
- Define AST for interfaces, tables, macros, rules, NAT, redirects, queues,
  route-to, anchors, and logging.
- Implement source spans for every AST node.
- Implement deterministic formatter.
- Implement type checker and diagnostics.
- Add fixtures for valid and invalid policies.

Exit criteria:

- `lpf check fixtures/policies/basic.lpf`
- `lpf fmt fixtures/policies/basic.lpf`
- precise diagnostics with line/column spans
- parser and formatter round-trip tests

## Phase 2: Typed Intermediate Representation

Goal: transform policy AST into a backend-neutral semantic plan.

Tasks:

- Model packet dimensions: family, interface, direction, protocol, address,
  port, user, group, mark, state, and table membership.
- Model decisions: pass, block, reject, log, NAT, rdr, queue, route-to.
- Model dynamic tables and table persistence.
- Model state behavior through conntrack.
- Add validation for contradictions and shadowed rules.

Initial implementation status:

- Typed IR now covers the Phase 1 policy surface: interfaces, tables, queues,
  NAT, redirects, anchors, logging, route-to, and pass/block rules.
- `lpf check` lowers valid policies into IR and reports shadowed-rule warnings.
- `lpf plan [--json]` emits a versioned backend-neutral semantic JSON plan.
- Plan checksums are stable across source-span changes and formatter
  normalization.
- Backend operation planning remains open for later phases.

Exit criteria:

- `lpf plan` emits a stable JSON plan.
- Shadowed rule warnings include source spans.
- Plan checksums are stable.

## Phase 3: nftables Backend

Goal: compile semantic plans to nftables with atomic updates.

Tasks:

- Generate `inet` tables for combined IPv4/IPv6 filtering.
- Generate NAT tables where required.
- Generate nft sets/maps for policy tables.
- Preserve source-policy annotations in comments.
- Implement plan rendering and install preflight.
- Implement readback parser for current nftables state owned by `lpf`.

Exit criteria:

- `lpf plan` renders nftables operations.
- `lpf diff` compares planned and installed state.
- Generated rules avoid unnecessary IPv4/IPv6 duplication.
- Snapshot tests cover set, map, filter, NAT, and redirect generation.

Initial implementation status:

- `lpf rules show <policy>` renders deterministic nftables text from the
  semantic plan without applying host changes.
- `lpf rules diff --observed <ruleset> <policy>` compares rendered intent with
  supplied observed nftables ruleset text, extracting only `lpf`-owned table
  blocks.
- `lpf rules diff --live <policy>` reads live state with `nft list ruleset`
  through a typed OCaml argv wrapper and feeds it into the same read-only diff
  path.
- `lpf diff <policy>` now provides the top-level read-only diff entry point for
  live lpf-owned nftables state, with `--observed` fixture input and `--json`
  machine-readable status.
- Golden fixtures cover basic filtering, NAT/RDR, queues, route-to, logging,
  and anchors.
- Semantic route/tc/conntrack diffing, atomic update operations, and apply
  remain open.

## Phase 4: Linux Routing, tc, And Conntrack Integration

Goal: unify the non-nftables Linux networking pieces.

Tasks:

- Add packet mark allocation strategy.
- Compile `route-to` to marks plus `ip rule` and route-table declarations.
- Compile queues to `tc` qdisc/class/filter plans.
- Add conntrack state listing and selective cleanup plans.
- Add sysctl requirement checks for forwarding, rp_filter, bridge netfilter,
  and IPv6 forwarding.

Exit criteria:

- `lpf plan` includes route and tc sections.
- `lpf diff` reports route/tc drift.
- `lpf state list` works through OCaml process execution.

## Phase 5: Safe Apply And Rollback

Goal: make remote firewall changes survivable.

Tasks:

- Capture current lpf-owned backend state before apply.
- Apply nftables changes atomically where possible.
- Sequence route/tc/sysctl changes with rollback preimages.
- Implement `--confirm <duration>`.
- Implement watchdog rollback if confirmation is missing.
- Persist policy history.

Exit criteria:

- `lpf apply policy.lpf --confirm 60s`
- `lpf confirm`
- automatic rollback when not confirmed
- explicit `lpf rollback <policy-id>`
- integration tests prove SSH-preserving rollback behavior in a network
  namespace before host-level tests are allowed.

## Phase 6: Explain Engine

Goal: explain decisions before and after apply.

Tasks:

- Implement static evaluator over typed policy IR.
- Add backend-reference annotations.
- Include NAT, route, queue, log, and state decisions.
- Add ambiguity and unknown-environment reporting.

Exit criteria:

- `lpf explain from 10.0.0.5 to 1.1.1.1 proto tcp port 443`
- output shows decision, rule, NAT, route, queue, log, and state behavior
- fixtures cover pass, block, reject, NAT, redirect, and route-to

## Phase 7: Policy Tests

Goal: make firewall behavior testable in CI.

Tasks:

- Define YAML or lpf-native test fixture schema.
- Implement expectation engine in OCaml.
- Support pass/drop/reject, NAT, route, queue, log, and table expectations.
- Emit JUnit-compatible reports from OCaml for CI.

Exit criteria:

- `lpf test fixtures/tests/basic.yaml`
- CI can block a policy change on failed assertions.

## Phase 8: Dynamic Tables

Goal: make threat/customer/allowlist tables operationally useful.

Tasks:

- Implement table add/delete/replace/show/flush/counters.
- Ensure updates do not require full policy reload.
- Add TTL support where nftables supports it.
- Add file-backed table replacement.
- Add redacted table evidence in support bundles.

Exit criteria:

- `lpf table threats add 203.0.113.10`
- `lpf table threats replace threats.txt`
- table changes are atomic and reversible.

## Phase 9: Importers

Goal: lower adoption friction.

Tasks:

- Import `nft list ruleset` output.
- Import `iptables-save` output.
- Import UFW-managed rules where recognizable.
- Import firewalld zones and services where recognizable.
- Mark untranslatable constructs explicitly instead of silently dropping them.

Exit criteria:

- `lpf import nftables`
- `lpf import iptables-save < rules.v4`
- generated policy is readable and includes TODO annotations for unresolved
  backend constructs.

## Phase 10: Observability And Support Bundles

Goal: make production debugging sane.

Tasks:

- Add structured history store.
- Add NFLOG/ulogd integration plan.
- Add counters and top-talkers view.
- Add redacted support bundle.
- Add policy ID and checksum to all generated backend objects.

Exit criteria:

- `lpf history`
- `lpf support-bundle`
- redaction tests prevent secrets and full private inventories from leaking.

## Phase 11: Bonsai UI

Goal: provide a safe browser operations surface using Bonsai/Bonsai_web.

Tasks:

- Extract shared policy, plan, diff, explain, history, support-bundle, and
  evidence models for CLI/server/UI reuse.
- Add an OCaml local API server for typed UI operations.
- Add `lpf ui serve --mock` for rootless UI development.
- Add `lpf ui serve --listen 127.0.0.1:9443` for local/SSH-forwarded use.
- Add a Bonsai Policy Workbench with editor, diagnostics, plan, diff, explain,
  and policy test panes.
- Add a Bonsai Apply Guard with plan checksum, rollback preimage, countdown,
  confirm, and rollback actions.
- Add dynamic table, conntrack, history, support bundle, and kernel evidence
  screens.
- Add Bonsai component tests and browser smoke tests.

Exit criteria:

- `lpf ui serve --mock` opens a working Bonsai UI without root.
- UI check/plan/diff/explain flows use typed mock API fixtures.
- guarded apply flow refuses changed plan checksums.
- Bonsai component tests cover workbench, explain, apply guard, rollback
  timer, and support-bundle redaction.
- the base `lpf` CLI still builds without Bonsai dependencies.

## Phase 12: Man Page Generation

Goal: keep operator docs synchronized with command metadata.

Tasks:

- Define OCaml command metadata for every command and subcommand.
- Generate `lpf(8)`, per-command man pages, `lpf.conf(5)`, and test fixture
  format pages.
- Add `lpf man generate`.
- Add `lpf man check`.
- Add tests that fail when generated man pages are stale.

Exit criteria:

- `lpf man generate`
- `lpf man check`
- generated pages exist for every operator-facing command.

## Phase 13: Kernel Matrix And Lab 141 Automation

Goal: prove backend behavior on current kernels.

Tasks:

- Implement `lpf kernel-matrix plan`.
- Implement `lpf kernel-matrix run` for lab orchestration.
- Refresh kernel.org matrix before release.
- Record redacted JSON evidence per kernel.
- Keep lab-specific logic in OCaml modules, with configuration in data files.

Exit criteria:

- evidence exists for the five latest kernel.org release lines
- each command's backend behavior is exercised per kernel
- evidence references Lab 141 when used

## Phase 14: Packaging And Release

Goal: make `lpf` easy to install and safe to operate.

Tasks:

- Build static or minimally dynamic release artifacts where practical.
- Produce deb/rpm packages.
- Add man pages generated from OCaml command metadata.
- Add signed release checksums.
- Document distro compatibility.
- Remote Linux build/test evidence is attached to release candidates.

Exit criteria:

- installable package
- reproducible release notes
- kernel-matrix evidence attached to release
