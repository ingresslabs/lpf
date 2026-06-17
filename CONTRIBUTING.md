# Contributing to lpf

## Language Rule

All product code must be OCaml. Shell scripts are only allowed as CI glue. No
Python, Ruby, Go, Rust, or JavaScript for product features.

## Development Cycle

```sh
opam switch create . ocaml-base-compiler.5.2.1
opam install . --deps-only --with-test
dune build          # build
dune runtest        # test
make check          # build + test + man pages + fixtures + diff
make remote-check   # validate on a remote Linux host (REMOTE=<host>)
```

## Feature Completion Bar

Every feature needs:

- [ ] OCaml implementation
- [ ] OCaml unit tests
- [ ] Command documentation (docs/COMMANDS.md)
- [ ] Generated man page coverage (`lpf man generate`)
- [ ] Policy fixture for the feature
- [ ] `--dry-run` or `--json` behavior for automation
- [ ] Failure behavior with actionable diagnostics
- [ ] `lpf explain` output where applicable

## Commit Guidelines

- Keep changes atomic and coherent
- Commit message format: `area: brief description`
- Prefixes: `fix:`, `feat:`, `docs:`, `refactor:`, `test:`, `ci:`
- Update man pages in the same commit as behavior changes
- Update CHANGELOG.md for user-visible changes

## Man Pages

```sh
lpf man generate --dir man/generated   # regenerates all pages
lpf man check --dir man/generated      # verifies pages are current
```

Man pages are generated from OCaml command metadata in `lib/command.ml`. A
command is not complete until its man page is current.

## Remote Validation

```sh
REMOTE=your-linux-host make remote-check
```

This builds and tests on a clean transferred checkout. Failures must be
fixed before merging.

## Pull Requests

Use the PR template. Ensure `make check` passes locally before opening.
