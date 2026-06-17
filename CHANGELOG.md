# Changelog

## Unreleased

### Added

- Created the initial `lpf` OCaml project skeleton.
- Added the project plan, command contract, agent rules, and kernel-matrix
  validation requirements.
- Declared Jane Street Bonsai/Bonsai_web as the required browser UI stack and
  added the UI architecture plan.
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
