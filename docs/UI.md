# Bonsai UI Architecture

`lpf` uses Jane Street Bonsai/Bonsai_web for browser UI. The UI is an
operations console over the same typed policy engine used by the CLI; it is not
a separate JavaScript control plane.

References:

- https://github.com/janestreet/bonsai
- https://github.com/janestreet/bonsai_web
- https://github.com/janestreet/bonsai_web/blob/master/docs/guide/00-introduction.md

## Product Goal

The UI should make dangerous firewall work reviewable:

- edit policy
- see parser/type-check diagnostics
- review semantic plan and backend diff
- explain packet decisions before apply
- apply with guarded confirmation
- watch rollback timer
- inspect history, state, tables, and evidence
- produce redacted support bundles

The UI must never be the only place a feature exists. Every operation exposed
in Bonsai must map to a CLI command and shared OCaml library call.

## Why Bonsai

Bonsai keeps the UI in OCaml, which matters for `lpf` because policy plans,
diffs, rollback preimages, rule spans, and explain results need precise typed
models. The frontend should render typed data from the backend, not parse human
CLI output.

Bonsai also fits the product shape:

- policy diagnostics and plan rendering are incremental computations
- route state, forms, and focused panes are local UI state
- dynamic tables and conntrack views are live data
- Bonsai tests can exercise DOM behavior without manual browser clicking

## Package Layout

Keep the packages separate:

```text
lib/              core types, command registry, shared pure logic
bin/              lpf CLI
server/           privileged/local API server, later package
ui/               Bonsai_web SPA, later package
test/             base CLI and shared tests
ui_test/          Bonsai component and browser-model tests
```

Initial package split:

- `lpf`: base CLI and pure libraries
- `lpf-server`: local control API and static asset server
- `lpf-ui`: Bonsai_web app compiled with js_of_ocaml

The base `lpf` package must not depend on Bonsai. The UI package depends on
`bonsai_web`, `virtual_dom`, `js_of_ocaml`, `js_of_ocaml-ppx`, `ppx_css`, and
the Jane Street ppx stack required by Bonsai.

## Runtime Shape

The best default is local-first:

```text
operator browser
  -> http://127.0.0.1:<ephemeral-port>/
  -> lpf server process
  -> shared OCaml policy/apply engine
  -> nft/ip/tc/conntrack through typed argv modules
```

Remote operation should use SSH forwarding:

```sh
ssh -L 127.0.0.1:9443:127.0.0.1:9443 root@host
lpf ui serve --listen 127.0.0.1:9443
```

Do not bind the UI API to a public interface by default.

## Security Model

The browser is untrusted presentation code. The backend is the authority.

Required controls:

- bind to `127.0.0.1` by default
- generate a single-use session token for each `lpf ui serve`
- require the token for all mutating API calls
- reject unsafe `Origin` and `Host` headers
- use same-site cookies or explicit bearer tokens for local sessions
- expose read-only mode by default when not running as root
- require a plan checksum for apply/confirm/rollback actions
- keep rollback preimages server-side, never browser-only
- redact secrets and private inventory in all UI-visible support bundles
- log operator-visible audit events for every mutating action

## API Surface

The UI should use typed endpoints that correspond to CLI operations:

```text
GET  /api/health
POST /api/check
POST /api/format
POST /api/plan
POST /api/diff
POST /api/explain
POST /api/test
POST /api/apply/start
POST /api/apply/confirm
POST /api/rollback
GET  /api/history
GET  /api/tables
POST /api/tables/:name/add
POST /api/tables/:name/delete
POST /api/tables/:name/replace
GET  /api/state/conntrack
POST /api/state/conntrack/kill
GET  /api/kernel-matrix/evidence
POST /api/support-bundle/preview
POST /api/support-bundle/create
```

Endpoint payloads must be encoded from shared OCaml types. Do not accept raw
backend commands from the browser.

## UI Screens

### Policy Workbench

Primary screen. Dense operational layout:

- policy editor
- diagnostics gutter
- generated semantic plan
- backend diff
- packet explain panel
- test fixture panel

The first useful interaction must be `check -> plan -> diff -> explain`, not a
dashboard or marketing page.

### Apply Guard

This is the most important safety surface.

Show:

- policy checksum
- backend plan checksum
- affected interfaces
- affected nft tables/chains/sets
- route/tc/sysctl changes
- rollback preimage status
- confirmation countdown
- `confirm` and `rollback now` actions

The UI must refuse apply when the plan has changed since review.

### Dynamic Tables

Operational table editor for allowlists, deny lists, customer ranges, and
temporary quarantine sets.

Show:

- table members
- TTLs
- counters where supported
- source file if file-backed
- pending replacement diff before commit

### Explain Lab

Packet decision explorer.

Inputs:

- direction
- interface
- source/destination address
- protocol
- port
- user/group where available
- mark/state where relevant

Output:

- decision
- source policy rule
- backend rule reference
- NAT result
- route result
- queue result
- log result
- state behavior

### History And Rollback

Show applied policy versions, test results, apply operator, timestamps,
checksums, and rollback availability. Rollback must use the same guarded flow
as apply.

### Kernel Evidence

Read-only evidence view for the latest-five kernel matrix and Lab 141 results.

## Bonsai Component Boundaries

Use small components around stable typed data:

- `Policy_editor`
- `Diagnostics_panel`
- `Plan_tree`
- `Backend_diff`
- `Explain_form`
- `Explain_result`
- `Apply_guard`
- `Table_editor`
- `Conntrack_table`
- `History_timeline`
- `Kernel_matrix_view`
- `Support_bundle_preview`

Do not place firewall semantics inside these components. Components transform
typed data into VDOM and schedule typed effects.

## State Management

Recommended Bonsai state:

- route/view selection in URL state
- unsaved policy buffer in local component state
- selected diagnostic/rule/plan node in local state
- server responses as effect-driven state
- long-running apply/kernel runs as polling subscriptions

Use the backend as the source of truth for host state. Browser state is only
drafts, selections, filters, and cached views.

## Testing Strategy

Required tests:

- component tests for each Bonsai component
- workbench flow: edit invalid policy, see diagnostic, fix it, see plan
- explain flow: fill packet form, receive pass/drop result
- apply guard flow: review checksum, start apply, confirm, see history
- rollback timer flow: start apply, let timer expire, see rollback result
- redaction tests for support bundle preview

Browser/UI tests must not require a real firewall. Use mock API responses from
shared OCaml fixtures. Host-level apply remains covered by kernel-matrix tests.

## Implementation Sequence

1. Extract shared policy/plan/diff/explain types into stable OCaml modules.
2. Add an OCaml API server that serves typed mock responses.
3. Add `lpf ui serve --mock` for local UI development without root.
4. Add a Bonsai shell with route tabs and static fixture data.
5. Implement Policy Workbench against mock API.
6. Add Bonsai component tests.
7. Wire read-only host endpoints.
8. Add guarded apply endpoints.
9. Add dynamic tables, conntrack, history, support bundle, and kernel evidence.
10. Add browser smoke tests for the built SPA.

## Build And Dev Commands

Planned commands:

```sh
lpf ui serve --mock
lpf ui serve --listen 127.0.0.1:9443
lpf ui build
lpf ui test
```

The implementation may split these into `lpf-ui`/`lpf-server` binaries
internally, but the operator-facing entry point remains `lpf ui`.

The UI command must update generated `lpf-ui(8)` metadata and pass the
man-page freshness check in the same change as any UI behavior update.
