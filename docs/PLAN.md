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

## Phase 0: Repository And Engineering Baseline

Tasks:

- Create OCaml/Dune skeleton.
- Define public CLI command names.
- Add agent rules.
- Add command contract.
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

Initial implementation status:

- Sysctl module (`lib/sysctl.ml`) reads and writes kernel parameters via
  `/proc/sys`, captures snapshots for rollback preimages, and provides
  structured diffs for drift detection. Required sysctls include
  `net.ipv4.ip_forward`, `net.ipv4.conf.*.rp_filter`,
  `net.ipv6.conf.*.forwarding`, and `bridge.bridge-nf-call-ip{,6}tables`.
- `lpf apply --confirm` captures sysctl preimages alongside nftables, tc, and
  routing preimages. `lpf rollback` restores captured sysctl values.
- `lpf diff --backend sysctl` is wired into the pipeline.

Exit criteria:

- `lpf plan` includes route and tc sections and sysctl requirements.
- `lpf diff` reports route/tc/sysctl drift.
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

## Phase 8: Native eBPF / XDP Compiler Backend

Goal: bypass Netfilter entirely by compiling `lpf` IR directly to an eBPF byte-code object attached to the XDP hook.

Tasks:

- Design an OCaml-to-C or OCaml-to-eBPF compilation pipeline.
- Implement XDP program generation for basic pass/drop/log filtering.
- Implement XDP map generation for fast dynamic table lookups.
- Implement XDP forwarding/redirects for route-to and simple NAT.
- Add `lpf apply --backend ebpf` or similar command flags.
- Extend `lpf diff` to support eBPF map state comparison.

Exit criteria:

- `lpf` can generate a valid C file or eBPF object.
- The eBPF object can be loaded via libbpf or bpftool.
- XDP drops packets before the kernel allocates `sk_buff`.
- Unifies routing and firewalling into a single dataplane.

## Phase 9: Dynamic Tables

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

## Phase 10: Firecracker E2E And Kernel Matrix Evidence

Goal: prove backend-affecting behavior on real disposable Linux guests before
claiming support.

Tasks:

- Run `lpf e2e` inside Firecracker VMs, not on the host.
- Cover nftables accept/drop/logging/reject, policy routing, route-table cleanup, tc
  HTB traffic shaping, conntrack readback, and cleanup/removal paths.
- Emit JUnit, Allure, sanitized manifests, and `scenario-log.jsonl` command
  evidence for each scenario.
- Maintain a matrix contract that separates requested, available, covered, and
  missing kernel labels.
- Refuse to count a kernel as covered unless a real VM booted that kernel and
  completed the scenario suite.
- Use 500 to 1000 scenarios for advanced lab pipelines.

Initial implementation status:

- `lpf e2e run` supports up to 1000 deterministic scenarios per guest.
- Scenario evidence records command argv, exit status, stdout/stderr, applied
  state readback, cleanup, and post-remove readback where applicable.
- The catalog now includes nftables reject, IPv6 accept/drop, cleanup idempotency,
  intended-vs-observed readback, and invalid-update rejection families.
- Evidence includes `summary.jsonl` for compact per-scenario status and
  checksums in addition to the full `scenario-log.jsonl` command log.
- The advanced external lab matrix archives requested, available, covered, and
  missing kernel artifacts separately.
- The tracked kernel matrix contains requested kernel metadata only; real
  Firecracker image inventory is supplied outside the repository.

Exit criteria:

- An approved Firecracker cloud profile can run the latest kernel.org matrix
  without relabeling missing images as covered.
- Each matrix entry records commit, OCaml version, Dune version, kernel,
  nftables, iproute2, conntrack-tools, command, fixture family, plan/evidence
  checksum, apply, confirm, rollback, and cleanup result.

## Phase 12: Packaging And Release

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
