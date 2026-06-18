# Kernel Lab Matrix

`ci/kernels/kernel-matrix.tsv` is the tracked source of truth for the generic
Firecracker kernel matrix. External lab runners read this file for requested
labels unless explicit matrix parameters are supplied.

The tracked matrix intentionally does not contain lab ids, real hostnames, IP
addresses, or registered Firecracker image inventory. Supply environment-local
image mappings through private runner parameters or controller-side
configuration.

The matrix keeps these states separate:

- `requested`: every label in the manifest or `REQUESTED_KERNELS`
- `available`: labels mapped to a registered Firecracker image outside the repo
- `missing`: requested labels that do not have an available image
- `covered`: available labels that booted a Firecracker VM and completed
  `lpf e2e run`
- `failed`: available labels that booted or ran but did not complete the suite

Missing kernels are never counted as covered. A kernel is covered only when the
job archives `covered-kernel.txt`, `manifest.json`, `summary.jsonl`,
`scenario-log.jsonl`, `junit.xml`, and checksums for that exact label.

As refreshed from https://www.kernel.org/ on 2026-06-18, the active kernel.org
release lines used by the generic matrix are:

- `7.1` mainline
- `7.0.12` stable
- `6.18.35` longterm
- `6.12.93` longterm
- `6.6.142` longterm
- `6.1.175` longterm
- `5.15.209` longterm
- `5.10.258` longterm

The matrix also includes `ubuntu-mainline-daily-20260616` as an Ubuntu daily
build and `baseline-default` as an optional environment-local baseline label.
The Ubuntu daily image is not linux-next coverage and must not be reported as
`next-20260616`.

Advanced matrix runs use 984 scenarios by default: 82 scenarios in each E2E
family, covering nftables accept/drop/logging/reject, IPv6 accept/drop, policy
routing, tc HTB shaping, conntrack, cleanup idempotency, readback diffing, and
negative invalid-update rejection.
