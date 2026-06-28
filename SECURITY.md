# Security Policy

## Reporting a Vulnerability

`lpf` modifies Linux firewall, routing, and traffic-control state. A bug in `lpf` can disrupt network connectivity on production hosts.

If you discover a security vulnerability, please report it privately to the maintainer at the repository's security advisory page rather than opening a public issue.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| 0.1.x   | :white_check_mark: (release candidates) |

## Security Model

- `lpf` requires root or `CAP_NET_ADMIN` to modify host networking state.
- Read-only commands (`check`, `fmt`, `plan`, `diff`, `explain`, `rules show`, `history`, `man`) do not modify host state.
- `lpf apply --confirm <duration>` implements a guarded apply with automatic rollback if not confirmed.
- Rollback preimages are captured before any host mutation.
- No secrets or credentials are stored by `lpf`. The runtime state directory (`/var/lib/lpf`) contains only policy history, rollback preimages, and watchdog state.
- All process execution is done through typed OCaml modules with explicit construct argv arrays — no shell command injection vector.

## Best Practices

1. Always run `lpf check` and `lpf diff --live` before `lpf apply`.
2. Use `lpf apply --confirm 60s` on remote hosts so connectivity loss triggers automatic rollback.
3. Test policies with `lpf test` and CI/lab E2E dry runs before production apply.
4. Keep rollback evidence in `/var/lib/lpf/rollback` for post-incident analysis.
5. Run `lpf` inside a disposable lab (Firecracker VM or network namespace) for E2E validation.
