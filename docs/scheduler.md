# Scheduler & drift alerts

`eyeexam scheduler run` is a foreground daemon that fires schedules on a
cron expression, runs them through the same `runlife` engine the CLI
uses, and dispatches alerts when a technique regresses against the
previous run.

## Authoring a schedule

```bash
eyeexam schedule add \
    --name nightly-linux \
    --cron "0 3 * * *" \
    --pack builtin \
    --tag linux \
    --max-dest low \
    --webhook https://hooks.example/eyeexam \
    --ntfy https://ntfy.sh \
    --ntfy-topic eyeexam-soc \
    --discord https://discord.com/api/webhooks/.../...
```

Operators must run `schedule add` themselves — the schedule's
`authorized_by` field captures the OS user at add time and that identity
is used as the actor on every subsequent fire. There is no
"un-authorize"; remove + re-add to rotate ownership.

## Listing & removing

```bash
eyeexam schedule list
eyeexam schedule remove nightly-linux
```

## Running the daemon

```bash
eyeexam scheduler run --interval 30s
```

The scheduler:

1. Re-reads enabled schedules from SQLite at every tick.
2. Computes the next-fire time per schedule from its cron expression.
3. Fires due schedules in their own goroutines: `Plan → Execute → cleanup
   → score`, identical to a CLI-driven run.
4. After each scheduled run, compares it to the prior `reported` run for
   the same engagement and emits a `Regression` per technique whose
   `detection_state` got worse (caught → uncertain → missed).
5. Delivers the regression bundle to every configured sink. Sink
   failures are logged and do not fail the run.

The scheduler **uses the schedule's stored authorization**, not the OS
user running the daemon. This lets you run the scheduler under a
non-interactive system account while having the audit log show the
human who originally authorized the schedule.

## Audit-log markers

Every scheduled run emits an `event:"run_start"` record with payload:

```json
{"schedule":"nightly-linux","trigger":"schedule","prior_run":"r-...","engagement":"HOMELAB-2026"}
```

When regressions are detected, an additional `event:"drift_alerted"`
record is appended with the full regression list.

## Alert sinks

| sink    | shape                                          | failure mode                |
|---------|------------------------------------------------|-----------------------------|
| webhook | POST application/json `Bundle{}` to URL        | non-2xx → log, no retry     |
| ntfy    | POST plain-text body to `<URL>/<topic>`         | non-2xx → log, no retry     |
| discord | POST `{embeds:[{...}]}` to webhook URL          | non-2xx → log, no retry     |

The webhook payload is the `alert.Bundle` JSON shape; consumers should
key on `schedule`, `run_id`, and the per-`Regression` `technique_id`.

## Limitations (v1)

- No retry. If your downstream is down, the alert is dropped — the
  audit log still records the regression, so post-hoc reconciliation is
  possible.
- No per-sink deduplication. If a technique has been failing for a
  week, every nightly fire of the schedule sends an alert.
- Schedules pre-authorize their own destructiveness. Operators
  approving a `--max-dest medium` schedule are accepting that every
  fire after that uses the same authorization until the schedule is
  removed.

## Audit chain verification

The scheduler runs a periodic chain-integrity check on the audit log
in a background goroutine. Default cadence is 1 hour; configurable
via `--audit-verify-interval` (set to `0` to disable):

```bash
eyeexam scheduler run --interval 30s --audit-verify-interval 15m
```

Each tick walks `audit.log` from genesis, recomputes hashes, and
cross-checks the `audit_log` SQLite mirror. On failure the daemon:

1. Logs an `ERROR` line via slog with the first bad seq + reason —
   pipe this into your usual log pipeline; this is the alert.
2. Appends an `audit_chain_broken` audit record (which extends the
   live chain past the break — the broken section stays broken;
   the next verify still reports it).
3. Keeps running. Refusing to fire schedules on transient corruption
   would be worse than the alternative; an attacker who could mute
   the scheduler that way already has bigger options. See
   `docs/audit-log.md` for the threat-model rationale.

Sig verification (ed25519 against `audit.key.pub`) is skipped in the
daemon loop — chain integrity is the high-value check. Run
`eyeexam audit verify` manually for full sig verification when
investigating a flagged chain break.

`/loop` (the periodic-task helper in this CLI) is **not** the scheduler
— `/loop` is a developer-facing meta-feature; eyeexam's scheduler is
the production one.
