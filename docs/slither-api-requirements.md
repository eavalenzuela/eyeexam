# Slither API requirements (read-only) — what eyeexam needs

This document specifies the slither-side API surface eyeexam needs in
order to score detections programmatically. It is a *contract proposal*
written for the slither maintainers: implement the endpoints described
here and eyeexam will swap its current shim client (`internal/detector/slither.go`)
to call them — no changes to eyeexam's `Detector` interface, scoring,
or audit chain are required.

The current state of slither's read surface (as of 2026-05) is HTML +
HTMX only at `/events`, with no machine-readable JSON variant, no
bearer-token auth, and no Sigma-rule-id filter. eyeexam cannot
programmatically consume that. This doc describes what would close
the gap.

## Scope

**In scope:** read-only event consumption — eyeexam queries slither's
event store after firing a BAS test to score whether the test was
detected.

**Explicitly out of scope:** anything that turns slither's control
plane into a BAS execution channel. eyeexam's M7 (slither runner) was
retracted in 2026-05; eyeexam will *not* dispatch attack commands
through slither agents. See `IMPLEMENTATION.md` §7 M7 for rationale.
Slither stays defensive-only.

## Auth

Bearer-token (or API key) auth on a separate header from the console's
session cookie. eyeexam runs unattended (CI, scheduler under systemd) —
it cannot do an interactive `/login` flow, and it should not be sharing
operator session cookies.

Concretely:
- `Authorization: Bearer <token>` on every request.
- Tokens are issued per-eyeexam-deployment, scoped to read-only event
  search, revocable independently of operator passwords.
- 401/403 surface a JSON error body, not the HTML login page.

The console's existing argon2id password + SCS session model is fine
for humans; eyeexam needs an orthogonal machine path.

## Required endpoints

### 1. Health probe

```
GET /api/v1/healthz
```

- 200 OK + `{"ok": true}` on success.
- Unauthenticated is fine (slither's existing `/healthz` already is).
- Used by eyeexam's `Detector.HealthCheck` at config-load time, so
  operators learn about misconfigured detector connectivity at startup
  rather than mid-run.

### 2. Event search

```
POST /api/v1/events/search
Content-Type: application/json
Authorization: Bearer <token>
```

Request body:

```json
{
  "host_id":      "0d0a1c2e-...-uuid",
  "host_name":    "web-01",
  "sigma_id":     "c5e7f8a0-...-rule-uuid",
  "rule_uid":     "c5e7f8a0-...-rule-uuid",
  "tag":          "attack.t1070.003",
  "class_uids":   [2004],
  "since":        "2026-04-25T13:59:00Z",
  "until":        "2026-04-25T14:01:30Z",
  "cursor":       "<opaque-pagination-token>",
  "limit":        500
}
```

Field semantics:

| field         | required | meaning                                                        |
|---------------|----------|----------------------------------------------------------------|
| `host_id`     | one of host_id/host_name | exact-match UUID against slither's hosts table |
| `host_name`   | one of host_id/host_name | slither resolves to host_id internally |
| `sigma_id`    | optional | filter to events whose Sigma rule UID matches; AND-ed with other filters |
| `rule_uid`    | optional | alias for sigma_id; for slither-native rules whose UID is not a Sigma rule |
| `tag`         | optional | ATT&CK technique tag (e.g. `attack.t1070.003`) — see Tag matching below |
| `class_uids`  | optional | OCSF event-class filter; `[2004]` is detection events; omit for all classes |
| `since`/`until` | required | RFC3339Nano time range, inclusive on `since`, exclusive on `until` |
| `cursor`      | optional | opaque pagination token from a prior response; do not interpret on eyeexam side |
| `limit`       | optional | max rows per page; server may cap; default 500 |

Response body:

```json
{
  "hits": [
    {
      "id":           "ev-2c1f...uuid",
      "host_id":      "0d0a1c2e-...-uuid",
      "host_name":    "web-01",
      "observed_at":  "2026-04-25T14:00:12.123Z",
      "class_uid":    2004,
      "severity_id":  4,
      "rule_uid":     "c5e7f8a0-...-rule-uuid",
      "rule_name":    "history-clear-via-c-flag",
      "raw":          { /* full OCSF event JSON, opaque to eyeexam */ }
    }
  ],
  "next_cursor": "<opaque-token-or-null>"
}
```

**`id` stability is load-bearing.** eyeexam dedups detection hits on
`(expected_detection_id, hit.id)`. Re-querying the same window must
return the same `id` for the same underlying event row. The OCSF
`event_id` UUID slither already stores satisfies this.

`raw` should be the full OCSF JSON exactly as slither stores it.
eyeexam does not interpret it; it persists it into `detection_hits.raw_json`
for forensic review. Keep it under ~64KB per event if possible.

### Tag matching

eyeexam's pack expectations carry ATT&CK tags (`attack.t1070.003`).
Slither's detection events should expose ATT&CK technique IDs they fire
against. The simplest contract:

- A detection event's "tags" are the ATT&CK technique IDs declared in
  the Sigma rule's `tags:` block, normalized to lowercase
  (`attack.t1070.003`).
- The query's `tag` field is matched against any of an event's tags
  (set membership, not substring).

If slither's rule schema doesn't carry tags yet, this filter can return
empty until it does — eyeexam will fall back to `sigma_id` matching
only.

### Filter combinator

Filters AND together. Future-extension knob: a `filters: [...]` array
with explicit `op:` would let eyeexam grow OR-of-ANDs queries; not
required for v1.

## Sigma rule discovery (optional, nice to have)

```
GET /api/v1/rules?since=<rfc3339>&technique=<attack.t1070.003>
```

Returns the set of Sigma / slither-native rules currently loaded on the
server, optionally filtered by ATT&CK technique. eyeexam does not need
this at runtime, but the eyeexam matrix UI could use it to mark
"techniques with no slither rule" cells differently from "techniques
with rules but no detections" — distinct gaps deserve distinct visual
treatment.

If this is too much surface, omit. eyeexam degrades gracefully.

## What eyeexam does NOT need

So slither's maintainers don't over-build:

- **No write endpoints.** No event ingest, no rule push, no agent
  command dispatch. eyeexam never writes to slither.
- **No streaming / live tail.** eyeexam queries are after-the-fact:
  fire test → wait `WaitSeconds` → query. Polling once is enough; no
  websocket / SSE / long-poll is required.
- **No HTML / HTMX surface.** This is a separate `/api/v1/...` tree
  from the console. Operators read slither's HTML console; eyeexam
  reads the JSON API. They share the underlying ClickHouse store but
  not the wire format.
- **No multi-tenant org concept.** v1 eyeexam talks to one slither
  deployment per `detectors[]` entry. Multi-tenant is an eyeexam-side
  concern.
- **No Sigma-rule-source-of-truth.** Operators load Sigma rules into
  slither out of band (slither-rulekit). eyeexam consumes the *output*
  of those rules; it does not need to know which rules exist or which
  files they came from.

## Example: full eyeexam scoring scenario

eyeexam fires Atomic test T1070.003 on `web-01` at `14:00:00Z`. The
test's expectation declares:

```yaml
expectations:
  - sigma_id: c5e7f8a0-...-rule-uuid
    tag: attack.t1070.003
    backend: slither
    description: history-clear via -c flag
wait_seconds: 90
```

After `WaitSeconds`, eyeexam calls slither:

```
POST /api/v1/events/search
Authorization: Bearer <token>
Content-Type: application/json

{
  "host_name": "web-01",
  "sigma_id":  "c5e7f8a0-...-rule-uuid",
  "tag":       "attack.t1070.003",
  "since":     "2026-04-25T13:59:00Z",
  "until":     "2026-04-25T14:01:30Z"
}
```

Slither replies with one hit (the rule fired). eyeexam:

1. Records the hit in `detection_hits` with `raw_json = response.hits[0].raw`.
2. Marks `expected_detections.state = 'caught'`, `detector_name = 'slither'`.
3. Sets `executions.detection_state = 'caught'`.
4. Writes an audit-log `event:"test_executed"` record with the run id +
   the detector that adjudicated.
5. The matrix UI paints T1070.003 green for that engagement.

If the response is empty after the wait, eyeexam marks the expectation
`missed`. If the request errors or returns 5xx, eyeexam marks it
`uncertain` with a reason and lets the operator re-investigate.

## How this maps to slither's existing internals

For the slither implementer, the wire shape above maps cleanly onto
existing types:

- `EventFilter` in `server/internal/store/ch/search.go` already covers
  `class_uids`, `host_id`, `severity_id`, `since`, `until`. Adding
  `rule_uid` and `tag` filters is a WHERE-clause extension on the
  ClickHouse side.
- `EventRow` / `EventDetail` already carry the projected columns; the
  JSON response is `EventDetail` minus the HTML-pretty-printed copy.
- `Cursor` already exists for the HTML pagination; reuse the same
  encoding.
- The console's `eventsList` handler in `server/internal/console/events.go`
  can be the model for the new JSON handler — same store calls,
  different output renderer.
- Auth: a new bearer-token middleware wired only on `/api/v1/*` keeps
  the console's session model untouched.

## Versioning

The v1 prefix is a hint for slither: this is a stable contract. eyeexam
reads `/api/v1/...`. If slither needs to evolve the shape, use `/api/v2/`
and we'll dual-target during the migration window.

## Status

eyeexam currently ships a stub client at `internal/detector/slither.go`
that targets a fictional `/api/v1/query` shim. When the endpoints
described here exist on slither's side, eyeexam's PR is ~1 file
(rewriting the client to match) plus a docs update. Until then, the
slither detector is non-functional against any real slither deployment;
operators querying slither's event store should use Loki/Elastic/Splunk
on the same logs in the meantime.
