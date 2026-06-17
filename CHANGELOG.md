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
