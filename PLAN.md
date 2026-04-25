# eyeexam

A breach-and-attack simulation runner that **closes the detection loop**:
schedule TTPs against your own hosts, wait, query your SIEM/EDR, score
whether the detection actually fired. Atomic Red Team supplies the
techniques; eyeexam runs them, asks the SIEM what it saw, and produces an
ATT&CK coverage heatmap.

## Scope

**In scope**: scheduled execution of Atomic Red Team (and eyeexam-native)
tests against a known host inventory; wait-and-query loop against
configured SIEM/EDRs to score caught / missed / uncertain; ATT&CK coverage
matrix over time; cleanup verification; deterministic, replayable runs.

**Out of scope**: writing detection rules (that lives in the SIEM, e.g.
slither-rulekit); offensive tooling for use against systems you don't own;
post-exploitation frameworks (we run individual atomic techniques, not
chained adversary emulation — Caldera does that); a SIEM of its own (we
query existing ones).

## Non-negotiables

- **Single Go binary.** No agent. Remote execution via SSH or via the
  target's existing telemetry agent (slither-agent module hook).
- **Authorized use only.** Refuses to start without `--authorized` and a
  config-declared `engagement.id` written into every record.
- **Cleanup is verified, not assumed.** A test that doesn't cleanly revert
  is a failed test, not a passed one.
- **Seeded and reproducible.** Same seed + same test pack + same
  inventory = same execution order. Re-run a single past test by id.
- **Honest scoring.** A test is `caught`, `missed`, or `uncertain`. No
  silent third state. `uncertain` means the SIEM query returned ambiguous
  results (no detection found, but ingestion lag exceeded the wait window,
  for example) — surfaced loudly, never collapsed into `caught`.
- **Destructiveness gating.** Every test carries a `destructiveness:
  low|medium|high` rating. Anything above `low` requires an explicit
  per-run flag and is logged with the operator id.

## Architecture

```
eyeexam/
  cmd/eyeexam/main.go     # CLI entrypoint (cobra)
  internal/
    config/               # YAML config loader, validation, engagement metadata
    pack/                 # test pack loader (Atomic Red Team + native YAML)
    inventory/            # host inventory loader, tag selectors
    runner/
      ssh.go              # SSH executor (default)
      slither.go          # optional: dispatch via slither-agent module
      local.go            # localhost executor (dev / single-box)
    detector/             # SIEM connector interface + implementations
      slither.go
      wazuh.go
      elastic.go
      splunk.go
      loki.go
    score/                # caught/missed/uncertain logic, dedup, aggregation
    cleanup/              # cleanup execution + verification
    matrix/               # ATT&CK heatmap renderer (HTML + JSON)
    store/                # SQLite: runs, executions, scores, cleanup state
    audit/                # append-only signed audit log
  ui/                     # minimal templ + HTMX read-only run viewer
  packs/                  # bundled native test packs (smoke / sanity)
```

Default datastore is SQLite. Findings, run history, and the ATT&CK matrix
are all queries over it. No external DB required for the homelab case.

## Test packs

Two formats supported, normalized to a common internal schema:

**Atomic Red Team YAML** — consumed as-is from
`https://github.com/redcanaryco/atomic-red-team`. eyeexam vendors a pinned
revision into `packs/atomic/` and updates via a separate `eyeexam pack
update` command (no auto-update; pinning is part of reproducibility).

**eyeexam-native YAML** — a thin format with explicit detection-expectation
fields that Atomic Red Team lacks:

```yaml
id: eye-001-bash-history-clear
attack:
  technique: T1070.003
  tactic: TA0005
name: Clear bash history
description: Common cleanup behavior; blue should detect a wipe.

destructiveness: low      # low | medium | high
platforms: [linux]

inputs:
  user:
    type: string
    default: $(whoami)

execute:
  - shell: bash
    command: |
      cat /dev/null > ~/.bash_history && history -c

cleanup:
  - shell: bash
    command: |
      echo "" > ~/.bash_history     # idempotent — no state to restore
verify_cleanup:
  - shell: bash
    command: |
      test ! -s ~/.bash_history

expected_detections:
  - sigma_id: c5e7f8a0-...      # match a Sigma rule by id
  - query: 'process.name:"history" AND process.args:"-c"'
    backend: slither             # backend-specific query, optional
  - description: "any rule tagged attack.t1070.003"
    tag: attack.t1070.003

wait_seconds: 60               # detector-query window; default 60
```

For Atomic Red Team tests, expected detections are kept in a
**sidecar file** (`packs/atomic/expectations/<atomic-id>.yaml`) so the
upstream pack stays unmodified. Missing expectation file = test runs but
scoring returns `uncertain` with a clear "no expectation defined" reason.

## Inventory

```yaml
hosts:
  - name: web-01
    address: web-01.lab
    transport: ssh
    user: eyeexam
    key: ~/.ssh/eyeexam_ed25519
    tags: [linux, web, prod]
  - name: build-01
    address: 10.0.5.12
    transport: slither     # dispatch via slither-agent
    agent_id: <agent-uuid>
    tags: [linux, build]

tags:
  prod:
    max_destructiveness: low   # tag-level cap on what may run here
```

Selectors used at run time: `--hosts web-01`, `--tag linux`,
`--tag-not prod`. Selector evaluation is logged into the run record.

## Runner

The runner interface:

```go
type Runner interface {
    Name() string
    Capabilities() []string  // e.g. "shell:bash", "shell:powershell"
    Execute(ctx context.Context, host Host, step ExecuteStep) (Result, error)
}
```

- **ssh** — opens a session per step; never reuses for unrelated tests.
  Uses an `eyeexam` user with sudo limited to the explicit set of commands
  tests need (the deployment doc walks through the sudoers stanza).
- **slither** — only available if the host is a slither agent. Dispatches
  the command through a signed control message over the existing gRPC
  channel. Output and exit code returned the same way. Adds an extra
  audit trail on the slither side.
- **local** — `exec.Cmd` on the host eyeexam itself runs on. Intended for
  dev and single-box homelabs.

Every execution captures `{stdout, stderr, exit_code, duration_ms,
started_at, host_id, runner}` into the store *before* moving to the next
step. A killed eyeexam process leaves a complete partial record.

## Detector

The detector interface:

```go
type Detector interface {
    Name() string
    Query(ctx context.Context, q ExpectationQuery, window TimeWindow) ([]Hit, error)
}
```

Each `expected_detection` is translated into the detector's native query
form. eyeexam waits `wait_seconds` after execution finishes (covers
ingestion lag), then queries the configured detector for hits inside
`[exec_started, exec_finished + wait_seconds + grace]`. A hit is correlated
to a specific test execution by host + time window; multiple hits dedup
into one detection record.

Shipped detectors:

- **slither** — queries ClickHouse via the slither server's read API.
- **wazuh** — queries the Wazuh indexer (OpenSearch).
- **elastic** — queries an Elasticsearch / Elastic Security cluster.
- **splunk** — queries via the search REST API.
- **loki** — queries Loki via LogQL (covers homelabs whose "SIEM" is
  Grafana + Loki + Promtail).

A detector returning *zero* hits when an expectation exists is `missed`. A
detector failing to respond, or returning hits but with metadata that
doesn't allow correlation back to this test execution, is `uncertain` —
never silently `caught`.

## Scoring

For each `(execution, expected_detection)` pair:

- **caught** — at least one detector hit correlated to this execution.
- **missed** — detector returned no hits within the window.
- **uncertain** — detector errored, ingestion lag visibly exceeded the
  window, expectation file absent, or correlation ambiguous.

Test-level score is the worst pair-level score (one missed → test missed).
Run-level reporting breaks out per-test detail; the matrix view rolls up
across runs over time.

## Cleanup verification

After `execute:` finishes, eyeexam runs `cleanup:` and then
`verify_cleanup:`. Verification is mandatory in native packs; for Atomic
Red Team tests without explicit verification, eyeexam runs Atomic's
`cleanup_command` and warns in the run record that no verification
existed. Cleanup or verification failure marks the test execution
`cleanup_failed` (separate from detection score) and is surfaced
prominently in the run summary so operators don't accumulate residual
state.

## Safety rails

- `--authorized` and matching `engagement.id` are required to start.
- Per-host `max_destructiveness` cap; per-tag cap; per-run `--max-dest`
  flag. The lowest cap wins.
- `--dry-run` prints the resolved plan (host × test × expected detection)
  and the destructiveness summary; executes nothing.
- `--allow-tests` / `--deny-tests` accept globbed test ids.
- Hard refuse list (built-in, not configurable): tests that require
  domain-controller modification, that disable EDR, or that modify boot
  loaders. These exist in Atomic Red Team and are inappropriate for
  scheduled BAS.
- Concurrency cap per host (default 1, configurable). Two tests never run
  on the same host simultaneously.
- Global rate limit (default 1 test/second across the fleet) to keep
  scheduled runs from looking like a real attack to oncall.

## ATT&CK matrix

Rendered server-side as HTML using the standard MITRE ATT&CK matrix
layout. Each cell carries a count and a status color:

- **green** — at least one test for this technique was run in the window
  and was caught.
- **yellow** — tests exist and are running but most recent result is
  `uncertain`.
- **red** — tests exist for this technique and the most recent result is
  `missed`.
- **grey** — no test for this technique in the configured packs.

Toggle: per-host, per-tag, per-time-window. Click a cell → list of recent
executions and their scores. Export the matrix as JSON for embedding into
other dashboards. Drift view: "techniques that were green last month and
are red now" is the highest-value report and lives on the dashboard
homepage.

## Audit log

Append-only file `audit.log`, signed with an ed25519 key. Every line:

```json
{"ts":"2026-04-25T14:02:11Z","actor":"alice","engagement":"HOMELAB-2026",
 "event":"run_start","run_id":"r-001","tests":["T1070.003","T1059.004"],
 "hosts":["web-01"],"max_dest":"low","sig":"<base64>"}
```

Verify with `eyeexam audit verify`. The signing key is generated on first
init and lives at `~/.config/eyeexam/audit.key`. Loss of the key
invalidates future verification of historical entries — documented and
intentional.

## Run lifecycle

```
plan → confirm (or --yes) → execute → wait → query → score → cleanup-verify → report
```

Each phase is a separate transaction in SQLite, so a crash mid-run leaves
the run resumable from the last completed phase. `eyeexam runs resume
<run-id>` re-enters at the next phase. Already-executed tests are not
re-executed; eyeexam picks up at `wait` for the in-flight tests.

## CLI surface

```
eyeexam version
eyeexam init                                  # scaffold config + audit key
eyeexam pack list
eyeexam pack update [--ref <git-ref>]        # update bundled atomic pack
eyeexam inventory list
eyeexam plan   --pack <name> --tag <t> [--hosts ...] [--tests ...]
eyeexam run    --pack <name> --tag <t> [--hosts ...] [--tests ...] \
               --authorized --engagement <id> \
               [--max-dest low|medium|high] [--dry-run] [--seed N] [--yes]
eyeexam runs   list
eyeexam runs   show   <run-id>
eyeexam runs   resume <run-id>
eyeexam matrix [--since 30d] [--tag <t>] [--out matrix.html]
eyeexam audit  verify
eyeexam serve  [--listen :8088]              # read-only web UI for runs + matrix
```

## Packaging & deps

- Go 1.23+. `go.mod` pinned. `make build` produces a CGO-free static
  binary; `make dist` cross-compiles linux/amd64, linux/arm64, darwin/arm64.
- Runtime deps: `cobra`, `sqlx` + `mattn/go-sqlite3` (CGO-free build via
  `modernc.org/sqlite`), `gopkg.in/yaml.v3`, `golang.org/x/crypto/ssh`,
  `templ`, `htmx` (vendored asset), MITRE ATT&CK STIX bundle (vendored).
- Dev deps: `golangci-lint`, `gofumpt`, `gotestsum`.

## Testing

- `tests/fixtures/packs/` — small native pack with low-destructiveness
  tests that touch only `/tmp` and a known `eyeexam_test` user.
- `tests/fakedetector/` — in-process detector that returns scripted hits
  to drive scoring tests without standing up a real SIEM.
- `tests/sshd/` — dockerized OpenSSH for end-to-end runner tests.
- Integration test: `plan → run → wait → query (fake) → score → cleanup
  verify`. Asserts the `caught/missed/uncertain` distribution exactly
  matches a known scripted scenario.

## Milestones

1. **M1 — local runner + native pack format.** `eyeexam run` against
   `localhost`, native YAML tests, no detector, results stored.
2. **M2 — SSH runner + inventory.** Multi-host execution with selectors,
   per-host concurrency cap, audit log.
3. **M3 — detector interface + slither/loki backends.** Wait-and-query
   loop, scoring (caught / missed / uncertain), cleanup verification.
4. **M4 — Atomic Red Team support + sidecar expectations.** Vendored
   pack, `pack update`, expectation sidecar layout.
5. **M5 — ATT&CK matrix + read-only UI.** HTML matrix, run viewer, drift
   view on the homepage.
6. **M6 — additional detectors.** Wazuh, Elastic, Splunk.
7. **M7 — slither runner.** Dispatch via slither-agent, end-to-end signed
   control plane.
8. **M8 — schedule + drift alerts.** Cron-style scheduling, alert sinks
   (ntfy/Discord/webhook) when previously-caught techniques regress.

## Still open

- **Windows support.** Out of scope for v1 (matches slither). Native
  pack format already includes a `platforms:` field so Windows tests can
  ship later without schema churn.
- **PowerShell test execution under Atomic Red Team.** Most Atomic tests
  on Linux are bash; PowerShell-on-Linux works but is an extra runtime
  dependency. Initial release skips PS-only tests with a clear marker.
- **Adversary chains.** Caldera owns this category. eyeexam may grow a
  thin "ordered playlist" feature later (run T1078 → T1059.004 → T1070.003
  in sequence, scoring the chain) but is not an emulation framework.

## Legal / ethics guard

Clear README: BAS is not a license to attack. Tests run only against
hosts in the configured inventory; `--authorized` and `engagement.id` are
mandatory; the audit log records who ran what against where, when. Built-in
hard refuse list blocks the worst techniques from ever being scheduled.
