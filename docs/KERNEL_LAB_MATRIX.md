# Kernel Lab Matrix

Backend-affecting `lpf` features must be tested against the latest five active
kernel.org release lines before release.

The initial matrix was checked against https://www.kernel.org/ on 2026-06-16:

| Role | Kernel | Published |
| --- | --- | --- |
| mainline | 7.1 | 2026-06-14 |
| stable | 7.0.12 | 2026-06-09 |
| longterm | 6.18.35 | 2026-06-09 |
| longterm | 6.12.93 | 2026-06-09 |
| longterm | 6.6.142 | 2026-06-01 |

## Lab Target

Use the `jenkins-firecracker-cloud-plugin` lab profile identified as `141`
when available. The lab must be treated as private infrastructure:

- do not commit hostnames unless already public
- do not commit credentials
- do not commit private support bundles
- record redacted evidence only

## Required Test Coverage Per Kernel

Each kernel must run the same OCaml-driven validation suite:

- `lpf check` parser and type-check fixtures
- `lpf plan` backend generation fixtures
- `lpf diff` semantic diff fixtures
- `lpf apply --confirm 60s` guarded apply
- `lpf confirm` confirmation path
- `lpf rollback` explicit rollback path
- `lpf explain` representative pass/drop/NAT/route decisions
- `lpf table` dynamic add/delete/replace/show
- `lpf state` conntrack inspection and cleanup where supported
- `lpf support-bundle` redaction checks

## Evidence Schema

Each run must produce a redacted JSON evidence document containing:

```json
{
  "project": "lpf",
  "lab_profile": "141",
  "git_commit": "sha",
  "kernel": "7.1",
  "ocaml_version": "5.2.1",
  "dune_version": "3.x",
  "nft_version": "x.y.z",
  "iproute2_version": "x.y.z",
  "conntrack_tools_version": "x.y.z",
  "fixture": "fixtures/policies/basic.lpf",
  "plan_checksum": "sha256",
  "result": "pass"
}
```

## Refresh Rule

Before release, refresh the matrix from kernel.org and update this file in the
same commit as the release candidate.

