# Man Page Generation

`lpf` is a CLI-first firewall tool. Operator-facing behavior must be available
in man pages and those man pages must be generated from OCaml metadata so they
stay synchronized with the executable.

## Implemented Commands

```sh
lpf man generate
lpf man check
lpf man install --prefix /usr/local
```

## Required Pages

Initial page set:

- `lpf(8)` command overview
- `lpf-check(8)`
- `lpf-fmt(8)`
- `lpf-plan(8)`
- `lpf-diff(8)`
- `lpf-apply(8)`
- `lpf-confirm(8)`
- `lpf-rollback(8)`
- `lpf-explain(8)`
- `lpf-test(8)`
- `lpf-table(8)`
- `lpf-state(8)`
- `lpf-rules(8)`
- `lpf-history(8)`
- `lpf-import(8)`
- `lpf-support-bundle(8)`
- `lpf-man(8)`
- `lpf.conf(5)`
- `lpf-policy-tests(5)`

## Source Of Truth

Man page generation must consume typed OCaml command/config metadata. Markdown
docs may explain concepts, but generated man pages are the operator reference.

Each command metadata entry must provide:

- name
- section
- synopsis
- description
- options
- examples
- exit statuses
- files
- safety notes
- related commands

## Completion Rule

Any command or user-visible behavior change is incomplete until:

```sh
dune exec -- lpf man check
dune runtest
```

prove that generated man pages are current.

## Generated Artifacts

Generated man pages should live under:

```text
man/generated/
```

Do not manually edit generated pages. Edit the OCaml metadata and regenerate.

## Current Implementation

`lpf man generate`, `lpf man check`, and `lpf man install` are implemented in
OCaml. The generator emits roff pages from typed command metadata in the `lpf`
library.
