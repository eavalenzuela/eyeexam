# Reports

`eyeexam report ...` produces engagement-scoped summaries from
already-collected run data. Reports are the readout surface — what you
hand to a stakeholder, paste into a ticket, or attach to a quarterly
coverage review. They're not real-time observability; eyeexam is a
periodic-batch tool, and the natural shape of its output is a report,
not a dashboard.

The reports are read-only over the SQLite store. No agents are
contacted, no tests fire. Safe to run while a scheduler or run is in
flight.

## `report coverage`

```bash
eyeexam report coverage \
    --engagement HOMELAB-2026 \
    --since 30d \
    --format md > coverage-2026-Q2.md
```

Produces a Markdown (or JSON) document with these sections:

- **Summary** — run count by phase, total executions, caught / missed
  / uncertain counts with percentages, refused-test count from the
  hard-refuse list.
- **Technique coverage** — one row per ATT&CK technique exercised in
  the window, with caught / uncertain / missed counts and the most
  recent state. Empty techniques (never tested) aren't listed.
- **Regressions in window** — techniques whose latest state is
  strictly worse than their previous different state, in the
  detection-state ordering `caught < uncertain < missed`. Most recent
  regression first. Only emitted for techniques with at least one
  state change.
- **Destructive-run authorizations** — every
  `destructive_run_authorized` audit record in the window, with actor
  and run id. Pulled from the audit log mirror.
- **Unsigned pack loads** — every `pack_loaded_unsigned` audit record
  in the window. If this section is non-empty for a serious
  engagement, that's a finding worth flagging.

### Flags

| flag           | default                        | meaning                                |
|----------------|--------------------------------|----------------------------------------|
| `--engagement` | `config.engagement.id`         | engagement to report on                |
| `--since`      | `720h` (30 days)               | lookback window                        |
| `--format`     | `md`                           | `md` or `json`                         |
| `--out`        | stdout                         | write to file instead of stdout        |

## When to use which

- **Quarterly coverage review.** `eyeexam report coverage --since 90d`
  Markdown output, paste into a doc, narrate around the regressions
  section.
- **Post-incident readout.** `--since 7d`, focus on
  Destructive-run authorizations and any unsigned pack loads.
- **Pipeline / scripted ingestion.** `--format json` and parse with
  `jq` or feed into another tool.
- **Real-time monitoring.** Reports are not built for this — use the
  scheduler's drift alerts (webhook / ntfy / Discord, configured per
  schedule) for "fire now when something changes" needs.

## What the data is sourced from

| section                   | source                                                          |
|---------------------------|-----------------------------------------------------------------|
| Run / phase counts        | `runs` table filtered by `engagement_id` + `started_at` window  |
| State counts              | `executions.detection_state` rolled up                          |
| Technique coverage        | `executions.attack_technique` aggregated per technique          |
| Regressions               | per-technique state-change walk (chronological)                 |
| Destructive authorizations | `audit_log` filtered to `event=destructive_run_authorized`     |
| Unsigned pack loads       | `audit_log` filtered to `event=pack_loaded_unsigned`            |
| Refused-test counts       | `runs.plan_json.refused`                                        |

If you suspect a report doesn't reflect reality, run `eyeexam audit
verify` — the audit-log sections trust the SQLite mirror, and the
mirror is reconciled against the file at every audit.Open. A
post-tamper run on the report would surface as
`audit verify FAILED at seq N`.

## Future reports (not yet shipped)

- **`report audit`** — audit timeline focused on a specific actor or
  event class.
- **`report packs`** — which packs contributed which tests across
  recent runs, and whether any were loaded unsigned.

Both are obvious follow-ons; they share the `internal/report`
framework with `coverage`. File an issue if you want one prioritized.
