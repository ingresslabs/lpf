# Changelog

## 0.1.2 - 2026-06-18

### Removed

- Removed the experimental dataplane compiler command and library module from
  the active CLI surface.
- Removed `lpf e2e` command and E2e module — Firecracker guest networking
  scenario runner extracted to its own repository.
- Removed redundant `lpf state show` and `lpf table show` subcommands
  (duplicates of `lpf state list` and `lpf table counters` respectively).
- Removed 27 disposable files: diagnostic logs, Jenkins job configs and
  automation scripts, build artifacts, and credential-containing files.
- Removed unused exports from `table.mli`, `e2e.mli`, `ir_json.mli`,
  `nftables.mli`, and `apply_guard.mli`.
- Removed duplicate type redefinitions in `nft.mli`, `conntrack.mli`,
  and `ip.mli` — now references `Process` types via manifest aliases.

### Changed

- `tc.ml` uses `Process.program` instead of `Nft.program` for TC invocations.
- Man page count reduced from 20 to 18 after command removals.

### Added

- Added `configs/policies` use-case examples for web servers, reverse proxies,
  NAT gateways, workstations, DNS resolvers, bastions, database segments, and
  branch routers with QoS.

## 0.1.1 - 2026-06-18

### Added

- Hardened GitHub CI into focused workflow jobs for OCaml checks, repository
  hygiene, generated compilation coverage, dry-run catalog coverage, Linux
  namespace smoke coverage, and OCaml coverage artifacts.
- Hardened the release workflow to build and upload the static binary tarball,
  generated man pages, SBOM, checksums, Debian package, and RPM/SRPM artifacts.
- Added repository hygiene checks that reject tracked lab host literals,
  private key markers, stale generated man pages, malformed kernel matrix rows,
  and private lab helper artifacts.
- Created the initial `lpf` OCaml project skeleton with project plan, command contract, and agent rules.
- Implemented `lpf man generate`, `lpf man check`, and `lpf man install` using OCaml command metadata with generated man pages for all commands.
- Implemented `lpf check` and `lpf fmt` with policy language parsing, formatting, validation, and fixtures for rules, NAT, redirects, queues, route-to, logging, and anchors.
- Added `lpf plan [--json]` for versioned backend-neutral semantic plan JSON with stable checksums.
- Added nftables backend: `lpf rules show`, `lpf rules diff`, `lpf diff` with live readback via typed `nft list ruleset` wrapper, JSON output, and golden fixture coverage.
- Added tc backend: `lpf plan --backend tc`, `lpf diff --backend tc --live`, compilation to qdisc/class plans, and live readback via `Tc.qdisc_show` / `Tc.class_show`.
- Added routing backend: `lpf plan --backend routing`, `lpf diff --backend routing --live`, compilation to `ip rule`/`ip route` plans, and live readback via `Ip.rule_list` / `Ip.route_show`.
- Implemented `lpf apply` with atomic nftables updates, guarded apply (`--confirm <duration>`), watchdog rollback, `lpf confirm`, and `lpf rollback [--now] [<policy-id>]`.
- Added multi-backend rollback preimages (nftables + tc + routing snapshots).
- Implemented `lpf explain` with static packet evaluator, shadow analysis, and anchor rule shadow detection.
- Implemented `lpf test` with policy assertion fixtures and JUnit XML output.
- Implemented dynamic table management: `lpf table add|delete|replace|show|flush|counters [--json]`.
- Implemented conntrack management: `lpf state list|show|flush|kill [--json]`.
- Added `lpf history` for apply history with rollback points.
- Added `lpf e2e run` with a 552-scenario Firecracker guest networking catalog across 12 families (nftables IPv4/IPv6, reject, routing, tc, conntrack, cleanup, readback, negative), plus JUnit, Allure, evidence outputs, and config-only `--dry-run`.
- Added `lpf apply --dry-run` for plan-only validation without host changes.
- Added `lpf check --json` and `lpf fmt --json` for structured automation output.
- Added `lpf tools --format openai|jsonschema|system-prompt` for AI agent tool-calling schemas.
- Added `Process` module extracting shared subprocess execution from nft/ip/conntrack.
- Added `File_util` module consolidating file I/O across 5 files.
- Added unit tests for `Process`, `Json_util`, `File_util`, `Command`, `Tc`, `Routing`, `Nft`, `Conntrack`, and `Table`.
- Added `reject` action to the policy language, nftables backend, explain engine, and test engine.
- Added IPv6 table set type auto-detection in nftables rendering.
- Added TC and routing semantic live diffing with parsed observed state comparison.
- Added `summary.jsonl` E2E evidence and compact per-scenario ledger.

### Refactored

- Removed tracked private lab job templates from the repository and moved
  runner configuration artifacts behind ignore rules.
- Split monolithic `lpf.ml` (780 lines) into 6 modules: `command.ml`, `manpage.ml`, `pipeline.ml`, `apply_guard.ml`, `history.ml`, `nft.ml`.
- Split monolithic test suite into 21 focused test files.
- Removed ui, kernel-matrix, import, and support-bundle stubs with no handlers.
- Removed abandoned UI and kernel-matrix placeholders from AGENTS.md.
- Cleaned up PLAN.md of completed and abandoned phases.
- Rewrote history JSON parser with robust field extraction.
- Replaced duplicated `nft_string` JSON escaping with `Json_util.string`.
- Consolidated `ensure_dir`/`write_file`/`read_file` into `File_util` with `~strict` parameter.
- Replaced `Option.get` crash risks in `tc.ml` with `List.filter_map`.
- Removed dead code: `route_to_mark` (replaced by `mark_for_target`).

### Fixed

- `explain.ml` `find_shadow` now searches anchor rules in addition to top-level rules.
- Fixed an impossible routing backend state to fail with a descriptive error.
- Fixed broken `Command.usage_examples` reference in manpage generation.
- Fixed non-literal gateway validation in `ir.ml` (route-to gateway must be Literal).
- Removed unused values in `e2e.ml` (`run_ping`, `apply_ruleset`, `max_scenario_count`).
- Fixed `summary.jsonl` cleanup in E2E unit test (leaked file caused `rmdir` failure).
