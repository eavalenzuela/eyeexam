# Slither detector — current shim contract (M3 stub)

eyeexam's M3 slither detector currently targets a small JSON-over-HTTP
shim. The shim is fictional: as of 2026-05 slither's only read surface
is its HTML/HTMX console at `/events`, which eyeexam cannot consume
programmatically. The slither detector therefore does not run against
any real slither deployment today.

> **Looking to ship the real API on the slither side?** See
> [`slither-api-requirements.md`](./slither-api-requirements.md) — that
> is the authoritative contract proposal for slither maintainers.
> This file documents only what eyeexam *currently sends* (the stub
> wire format); the requirements doc describes what eyeexam *needs*.

## Endpoints

### `GET /api/v1/health`

200 OK on success. Anything else → unhealthy.

### `POST /api/v1/query`

Request body:

```json
{
  "query": "process.name:\"history\" AND process.args:\"-c\"",
  "sigma_id": "c5e7f8a0-...",
  "tag": "attack.t1070.003",
  "backend": "slither",
  "host_hint": "web-01",
  "window_from": "2026-04-25T13:59:00Z",
  "window_to":   "2026-04-25T14:01:30Z"
}
```

Any of `query` / `sigma_id` / `tag` may be set; the server picks the most
specific. `host_hint` is the eyeexam-side hostname for correlation; the
server may translate it to `host_id` internally.

Response body:

```json
{
  "hits": [
    {
      "id": "ck-43a91-2-77",
      "at": "2026-04-25T14:00:12.123Z",
      "host": "web-01",
      "event": { /* full slither event payload, opaque to eyeexam */ }
    }
  ]
}
```

`id` must be stable per (rule, host, time, payload) — eyeexam dedups on
`(expected_id, hit_id)` and re-querying the same window must return the
same `id` for the same underlying event.

## Auth

Optional. If set, eyeexam sends `Authorization: Bearer <api-key>` from the
configured environment variable (`detectors[].options.api_key_env`).

## Migration notes

When slither's real read API ships:

1. Update `internal/detector/slither.go` to call the real endpoint.
2. Keep `Detector.Supports` semantics the same (sigma_id / tag / query;
   `backend != "slither"` → unsupported).
3. Keep `Hit` mapping the same shape so the runlife/score layers don't
   change.
4. Bump this doc with the new endpoint shape and remove the "stub" note.

The eyeexam test fixtures in `internal/detector/slither_test.go` use the
shim contract above; rewrite those when the API changes.
