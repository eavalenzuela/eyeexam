# Running against live-EDR hosts

Running eyeexam against a host with an active EDR (CrowdStrike Falcon,
SentinelOne, Defender for Endpoint, etc.) has a failure mode the default
lifecycle doesn't: **the EDR can detect and kill a test mid-run.** If that
happens after a file-modifying test has run but before its cleanup, the
modification — an appended `~/.ssh/authorized_keys` key, a marker crontab
entry, a `.bashrc` alias — is left on the host.

eyeexam has three mechanisms for this, plus pacing controls to keep a run
from tripping burst/velocity heuristics. None change behavior unless you opt
in (except the always-on graceful abort), so existing runs are unaffected.

## 1. Staged cleanup (`--cleanup-mode eager`)

By default (`deferred`) every test executes, then the run waits, queries the
SIEM, scores, and only then runs all cleanups. On a live-EDR host that means
every executed test's changes sit on the box until the whole run finishes.

`eager` mode runs each test's cleanup **immediately after that test
executes**, before the next test starts:

```bash
eyeexam run --pack persistence --hosts prod-1 \
    --authorized --engagement ENG --max-dest medium --yes \
    --cleanup-mode eager
```

Now the window in which any change is live shrinks to a single test's
duration — an EDR killing a *later* test cannot strand an *earlier* test's
change. Set it permanently in config:

```yaml
cleanup:
  mode: eager
```

**Tradeoff:** eager cleanup runs the revert *inside* the detection query
window, so the cleanup's own file events (e.g. rewriting `authorized_keys`
back to the original) can land in the window. For file-write detections this
only ever biases toward `caught` (the original write already fired the rule),
never toward a false `missed`. If you need the cleanest possible detection
scoring on file-write tests, keep `deferred`; if you're prioritising
residue-avoidance on a production EDR host, use `eager`.

## 2. Recovery after a hard kill (`eyeexam runs cleanup`)

A SIGKILL can't be trapped. When the EDR (or an OOM kill, or power loss)
terminates eyeexam outright, the executions it had run are left with
`cleanup_state = pending` in the datastore. Drain them later:

```bash
eyeexam runs cleanup <run-id>        # revert one interrupted run
eyeexam runs cleanup --all-pending    # revert every run with pending cleanup
```

This re-runs each pending test's `cleanup` + `verify_cleanup` independently of
the wait/query/score phases. It is idempotent — already-cleaned executions are
skipped — so it is safe to run more than once, and safe to run after a
`resume`. `eyeexam runs show <run-id>` shows which executions are still
pending.

The self-cleaning packs make this reliable: each file-modifying pack stages
its undo (saves the original, or records that it created the file) *before*
touching anything, so cleanup reverts correctly even if the test was killed
part-way through execution.

## 3. Graceful abort (Ctrl-C / SIGTERM)

`run` and `runs resume` trap SIGINT and SIGTERM. On the first signal the run
is cancelled and cleanup is drained on a fresh context, so in-flight changes
are reverted before the process exits. A second signal restores default
handling and hard-kills (recover with `runs cleanup`). Many EDRs and
orchestrators send SIGTERM before SIGKILL, so this catches the common case.

## 4. Pacing and step bounds

A tight burst of look-alike-malicious commands is exactly what velocity
heuristics flag. Spread the run out and bound any command the EDR might
silently block:

```bash
eyeexam run ... --pace 30s --jitter 15s --step-timeout 2m
```

| flag             | meaning                                                        |
|------------------|----------------------------------------------------------------|
| `--pace`         | minimum delay between test executions                          |
| `--jitter`       | extra uniform-random `[0, jitter)` added to each pace gap       |
| `--step-timeout` | per-step wall-clock cap; the local runner kills the whole      |
|                  | process group on expiry so a blocked command can't hang the run |

Config equivalents:

```yaml
limits:
  inter_test_pace: 30s
  inter_test_jitter: 15s
  step_timeout: 2m
```

Flags override config; config overrides the defaults (all zero = original
burst-y behavior). `--step-timeout` is independent of the SSH runner's own
`command_timeout` — set both when running over SSH.

## Recommended live-EDR profile

```yaml
cleanup:
  mode: eager
limits:
  global_tests_per_second: 0.2   # ~1 test / 5s ceiling
  per_host_concurrency: 1
  inter_test_pace: 30s
  inter_test_jitter: 15s
  step_timeout: 2m
```

Then run normally. If a test is killed anyway, `eyeexam runs cleanup
--all-pending` reverts whatever was left behind.
