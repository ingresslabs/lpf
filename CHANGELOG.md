# Changelog

## Unreleased

### Added

- Created the initial `lpf` OCaml project skeleton.
- Added the project plan, command contract, and agent rules.
- Added man-page generation and remote Linux compile/test requirements.
- Implemented `lpf man generate`, `lpf man check`, and `lpf man install`
  using OCaml command metadata.
- Added generated `lpf(8)`, command, policy config, and policy test man pages.
- Implemented the first `lpf check` and `lpf fmt` policy-language slice in
  OCaml.
- Added valid and invalid policy fixtures for default actions, tables, rules,
  NAT, redirects, syntax errors, and unknown table diagnostics.
- Refactored policy parsing around tokenized statements with column-level
  spans for parser and validation diagnostics.
- Added formatter round-trip coverage for non-normalized policy input.
- Added policy-language parsing, formatting, validation, and fixtures for queue
  declarations and rule-level queue assignment.
- Added rule-level `route-to` parsing, formatting, validation, and malformed
  syntax diagnostics.
- Added rule-level `log`, `log (all)`, `log (matches)`, and `log (user)`
  parsing, formatting, validation, and malformed syntax diagnostics.
- Added top-level anchor parsing, formatting, validation, and valid/invalid
  fixtures for rule-only anchor blocks.
- Added Phase 1 policy-language hardening fixtures for malformed interface,
  quoted string, table, NAT, and redirect syntax plus broader formatter
  round-trip coverage.
- Added the first typed IR model for the Phase 1 policy surface and
  shadowed-rule warnings during `lpf check`.
- Implemented `lpf plan [--json]` for versioned backend-neutral semantic plan
  JSON with stable checksums.
- Added a read-only nftables renderer exposed through `lpf rules show <policy>`
  with golden fixture coverage.
- Added read-only `lpf rules diff --observed <ruleset> <policy>` comparison
  for supplied lpf-owned nftables table readback text.
- Added read-only live nftables readback through `lpf rules diff --live
  <policy>`, using an OCaml `nft list ruleset` execution wrapper.
- Implemented the first `lpf diff` top-level command for read-only comparison
  of planned policy against live host nftables state, including
  machine-readable JSON status output.
- Implemented `lpf apply` with atomic nftables updates via `nft -f`.
- Added guarded apply support with `lpf apply --confirm <duration>`, capturing
  a rollback preimage of lpf-owned nftables tables and scheduling an automatic
  watchdog rollback.
- Implemented `lpf confirm` to promote a pending guarded apply and cancel the
  rollback watchdog.
- Implemented `lpf rollback --now` for immediate restoration of the captured
  preimage.
- Added `lpf e2e run` with a 480-scenario Firecracker guest networking catalog
  plus JUnit, Allure, sanitized evidence outputs, and per-scenario apply,
  readback, remove, and cleanup logs.
- Extended `lpf e2e run` to support up to 1000 scenarios per disposable lab
  guest for advanced routing, traffic-shaping, nftables, logging, and
  conntrack coverage.
- Added an advanced Jenkins Firecracker matrix contract that records requested,
  available, covered, and missing kernel labels separately so unavailable
  kernels are never reported as covered.
- Expanded `lpf e2e run` to a balanced 550-scenario default and 990-scenario
  advanced matrix profile across nftables IPv4/IPv6, routing, traffic shaping,
  conntrack, cleanup idempotency, readback diffing, and invalid-update
  rejection.
- Added compact `summary.jsonl` E2E evidence and family coverage accounting to
  the E2E manifest.
- Added a generic tracked kernel matrix that stores requested kernel metadata
  without lab ids, real hostnames, IP addresses, or Firecracker image
  inventory.

### Refactored
- Split `lpf.ml` (780 lines) into 6 modules: `command.ml`, `manpage.ml`,
  `pipeline.ml`, `apply_guard.ml`, `history.ml`, `nft.ml`.
- Split monolithic test suite into 17 focused test files (4 integration + 13 unit).
- Removed ui, kernel-matrix, import, and support-bundle stubs with no handlers.
- Removed abandoned UI and kernel-matrix placeholders from AGENTS.md.
- Cleaned up PLAN.md of completed and abandoned phases.
- Rewrote history JSON parser with robust field extraction.
- Replaced duplicated JSON escaping in main.ml with `Json_util.string`.

### Added
- Unit tests for `Tc.ml`, `Routing.ml`, `Nft.ml`, `Conntrack.ml`, `Table.ml`.
- `--backend tc` and `--backend routing` options for `lpf plan`, `rules`, `diff`.
- `lpf diff --backend tc --live` and `lpf diff --backend routing --live` support.
- `ip.ml` typed wrapper for `ip rule` and `ip route` commands.
- TC live readback via `Tc.qdisc_show` and `Tc.class_show`.
- Multi-backend rollback preimages (nftables + tc + routing snapshots).
- `lpf rollback <policy-id>` for manual rollback by history ID.
- `lpf table show` and `lpf table counters` handlers.
- `lpf state kill` and `lpf state flush` handlers.
- `lpf e2e run --dry-run` for plan-only validation without Firecracker.
- E2E scenario catalog extends to 550 default deterministic scenarios and 990
  balanced advanced-matrix scenarios.
- `E2e.dry_run` support for config-only planning.
- `E2e.evidence_manifest` for redacted evidence summaries.

### Fixed
- `explain.ml` `shadowed_by` now populated with actual shadowing rule.
- Fixed `assert false` crash in `apply_guard.ml` replaced with proper error.
- Fixed broken `Command.usage_examples` reference in manpage generation.
- Removed unused values in `e2e.ml` (`run_ping`, `apply_ruleset`, `max_scenario_count`).
