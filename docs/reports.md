# Reports

`eyeexam report ...` produces engagement-scoped readouts from
already-collected run data as standalone HTML or JSON files. Reports
are the readout surface — attach to a ticket, scp to a shared dir,
hand to a stakeholder, ingest with `jq`. They are not real-time
observability; eyeexam is a periodic-batch tool whose natural output
is a file.

There is no `eyeexam serve`. The original M5 milestone shipped a
read-only HTTP viewer; it was retracted post-M9 once reports
covered the same ground without the daemon footprint. See
[`IMPLEMENTATION.md`](../IMPLEMENTATION.md) §7 M5 for the rationale.

All three subcommands are read-only over the SQLite store. Safe to
run while a scheduler or run is in flight.

## Formats

- `--format html` (default) — single self-contained `.html` file with
  inlined CSS. Open with `xdg-open`, attach to a ticket, or render
  with any browser. No JS framework, no external assets, no
  cross-origin loads.
- `--format json` — indented JSON for `jq` filters and downstream
  tooling. Wire shapes are stable; consumers may rely on field names.

`--out <path>` writes to a file; otherwise output goes to stdout.

## `report coverage`

Engagement-scoped summary:

```bash
eyeexam report coverage \
    --engagement HOMELAB-2026 \
    --since 30d \
    --out coverage-2026-Q2.html
```

Sections:

- **Summary** — run count by phase, total executions, caught /
  missed / uncertain counts (rendered as colored stat cards),
  refused-test count from the hard-refuse list.
- **Technique coverage** — one row per ATT&CK technique exercised in
  the window, with caught / uncertain / missed counts and the most
  recent state.
- **Regressions in window** — techniques whose latest state is
  strictly worse than their previous different state, in the
  detection-state ordering `caught < uncertain < missed`. Most
  recent regression first. Each row links (in HTML) to the
  per-run report for the run that contained the regression.
- **Destructive-run authorizations** — every
  `destructive_run_authorized` audit record in the window, with
  actor and run id (HTML row links to the per-run report).
- **Unsigned pack loads** — every `pack_loaded_unsigned` audit
  record in the window. Non-empty in a serious engagement is a
  finding worth flagging.

### Flags

| flag           | default                | meaning                              |
|----------------|------------------------|--------------------------------------|
| `--engagement` | `config.engagement.id` | engagement to report on              |
| `--since`      | `720h` (30 days)       | lookback window                      |
| `--format`     | `html`                 | `html` or `json`                     |
| `--out`        | stdout                 | write to file instead of stdout      |

## `report run`

Per-run detail — the page that used to live at `/runs/<id>`:

```bash
eyeexam report run r-01HXX… --out r-01HXX.html
```

Sections:

- **Run metadata** — engagement, phase, max_dest, authorized_by,
  app_user (if set), started, finished, seed.
- **Executions** — per-execution table with exec_id, host, test id,
  exit code, detection / cleanup / verify states (colored cells).
- **Expected detections** — per-expectation state, detector that
  adjudicated, reason for `uncertain`.
- **Audit events** — every record in the audit log filtered to this
  run, ordered by seq, with actor and payload. Pulled from the
  SQLite mirror; run `eyeexam audit verify` to confirm chain
  integrity.

### Flags

| flag        | default | meaning                          |
|-------------|---------|----------------------------------|
| `--format`  | `html`  | `html` or `json`                 |
| `--out`     | stdout  | write to file instead of stdout  |

## `report matrix`

ATT&CK heatmap as a grid of colored cells:

```bash
eyeexam report matrix --engagement HOMELAB-2026 --out matrix.html
```

Without `--engagement`, the matrix is cross-engagement (every run in
the window contributes to its technique cell). With
`--engagement <id>`, only runs in that engagement count — useful for
"how does this specific BAS engagement look against the matrix?"

The HTML rendering shows tactics as columns, parent techniques as
cells under each tactic, with subtechniques rolled up into the
parent state (worst-case across the children). A "Recent
regressions" section lists drift entries (techniques whose state
went strictly worse in the window vs. before it).

### Flags

| flag           | default          | meaning                               |
|----------------|------------------|---------------------------------------|
| `--engagement` | empty            | scope to one engagement (omit for cross-engagement) |
| `--since`      | `720h` (30 days) | lookback window                       |
| `--format`     | `html`           | `html` or `json`                      |
| `--out`        | stdout           | write to file instead of stdout       |

## When to use which

- **Quarterly coverage review.** `report coverage --since 90d`
  (HTML), narrate around regressions section.
- **Per-incident readout.** `report run <run-id>` HTML, attach to
  the ticket. Audit-events section gives you the destructive-auth
  + test-executed timeline already linked.
- **Coverage-over-techniques visual.** `report matrix --out
  matrix.html` for the at-a-glance grid; great for slide-deck
  screenshots.
- **Pipeline / scripted ingestion.** `--format json` and `jq` /
  parse with another tool.
- **Real-time monitoring.** Reports are not built for this — use
  the scheduler's drift alerts (webhook / ntfy / Discord,
  configured per schedule) for "fire now when something changes."

## What the data is sourced from

| section                    | source                                                            |
|----------------------------|-------------------------------------------------------------------|
| Run / phase counts         | `runs` table filtered by `engagement_id` + `started_at` window    |
| State counts               | `executions.detection_state` rolled up                            |
| Technique coverage         | `executions.attack_technique` aggregated per technique            |
| Regressions                | per-technique state-change walk (chronological)                   |
| Destructive authorizations | `audit_log` filtered to `event=destructive_run_authorized`        |
| Unsigned pack loads        | `audit_log` filtered to `event=pack_loaded_unsigned`              |
| Refused-test counts        | `runs.plan_json.refused`                                          |
| Run-detail audit events    | `audit_log` filtered to `run_id`                                  |
| Matrix tactics + names     | embedded MITRE ATT&CK STIX bundle (with operator override path)   |

If you suspect a report doesn't reflect reality, run `eyeexam audit
verify` — the audit-log sections trust the SQLite mirror, and the
mirror is reconciled against the file at every audit.Open. A
post-tamper run on the report would surface as
`audit verify FAILED at seq N`.

## Future reports (not yet shipped)

- **`report audit`** — audit timeline focused on a specific actor or
  event class, beyond the per-run filtered view.
- **`report packs`** — which packs contributed which tests across
  recent runs, and whether any were loaded unsigned.

Both are obvious follow-ons; they share the `internal/report`
framework with the existing three. File an issue if you want one
prioritized.
