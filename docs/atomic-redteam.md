# Atomic Red Team support

eyeexam can run tests authored in the [Atomic Red Team][art] YAML format,
but **eyeexam never clones, vendors, or pulls Atomic Red Team itself.** The
operator manages the clone; eyeexam reads from it.

[art]: https://github.com/redcanaryco/atomic-red-team

## Operator workflow

```bash
# 1. Clone Atomic Red Team somewhere you control. Pin a revision —
#    test-id stability depends on the upstream YAML order.
git clone https://github.com/redcanaryco/atomic-red-team.git \
    ~/.local/share/eyeexam/packs/atomic-red-team
cd ~/.local/share/eyeexam/packs/atomic-red-team
git checkout <pinned-tag-or-sha>

# 2. Register it with eyeexam. The atomics/ subdirectory is the YAML root.
eyeexam pack add atomic ~/.local/share/eyeexam/packs/atomic-red-team/atomics \
    --source atomic

# 3. Plan / run as usual. Atomic tests appear with id
#    "atomic-<technique>-<index>", e.g. atomic-T1059.004-1.
eyeexam pack list
eyeexam plan --pack atomic --hosts localhost --max-dest medium
```

To update later, `git pull` your clone yourself — eyeexam does not do this.

## Test-id scheme

Each `atomic_tests:` entry becomes a single eyeexam test. The id is
`atomic-<technique>-<index>`, where `<index>` is the 1-based position of
the test in the upstream YAML. This is a stable wire identifier between
eyeexam and your sidecar / refuse-list entries — but it shifts if upstream
re-orders within a technique file. The mitigations are:

- **Pin a revision.** A pinned tag or sha makes the order stable.
- **Sidecars are addressed by id**, not by name, so a re-order silently
  re-routes expectations. Re-validate sidecars after every Atomic update
  (`eyeexam pack list` shows the current id ↔ name mapping).

## Sidecar expectations

Atomic YAML lacks `expected_detections` and `destructiveness`. eyeexam
reads them from sidecar files at:

```
<atomics-root>/expectations/atomic-<technique>-<index>.yaml
```

Example sidecar:

```yaml
expected_detections:
  - sigma_id: c5e7f8a0-...
  - tag: attack.t1070.003
  - query: 'process.name:"history" AND process.args:"-c"'
    backend: slither
wait_seconds: 60
destructiveness: low      # overrides loader default (medium)
```

Without a sidecar, atomic tests run with destructiveness `medium`, no
expectations (so the score phase reports `uncertain` with reason "no
detector configured for this expectation"), and `wait_seconds=60`.

The runlife layer marks `cleanup_verify_state=warned_atomic` for any
atomic test that has no `verify_cleanup` (Atomic format does not carry
one) — surfaced in `runs show` so operators don't accumulate residual
state silently.

## Refuse list

eyeexam ships with a built-in refuse list (`internal/pack/builtin_refuse.go`)
that blocks dangerous Atomic tests at plan time:

- Domain-controller modification (Skeleton Key, DCSync, Golden Ticket).
- EDR-disable techniques (T1562.001 family, T1562.002, T1562.004 when
  used to blackhole the SIEM).
- Bootloader / firmware modification (T1542.001, T1542.003).

Refused tests are listed in the plan output and emit a `test_refused`
audit-log record. To add an id locally, edit `builtin_refuse.go` and
recompile — a future milestone may move this to config.

## Skipped executors

The Atomic format supports several executors that eyeexam does not run on
Linux v1:

- `command_prompt` (Windows-only).
- `powershell` (works via `pwsh` but adds a runtime dep we don't ship).
- `manual` (defeats automation).

Tests with these executors load as `skipped` with a reason and never enter
the executions table. `eyeexam pack add atomic ...` prints them to stderr
on first registration.

## Pinning workflow

When you `git pull` your Atomic clone, run:

```bash
eyeexam pack list           # surfaces the post-pull id list
diff <prev list> <new list> # spot-check that ids you have sidecars for
                            # still point to the same tests
eyeexam plan --pack atomic --hosts localhost --max-dest low --dry-run
```

If a sidecar's underlying test moved to a new index, rename the sidecar
file. A future milestone may add an `eyeexam pack drift` command to do
this checksum diff automatically.
