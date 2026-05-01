# eyeexam — Implementation Plan

Companion to `PLAN.md`. PLAN.md is the product spec; this document fleshes out
the engineering plan: foundational decisions, data model, package contracts,
and a per-milestone build plan detailed enough to execute one milestone per
working session.

This document is the authoritative planning artifact. Decisions captured here
override anything in PLAN.md that turned out to be ambiguous (the noted
inconsistencies are listed in §2.7).

---

## Status (M1–M8 shipped; M7 retracted)

| ms | scope                                              | status     | notable plan deviations                              |
|----|----------------------------------------------------|------------|------------------------------------------------------|
| M1 | local runner, native pack, store, audit, CLI       | shipped    | none                                                 |
| M2 | SSH runner, inventory check, audit richness        | shipped    | docker-compose sshd → in-process `tests/sshfx` (§7 M2 notes) |
| M3 | detector iface, loki + slither stub, scoring       | shipped    | slither read API is a JSON-over-HTTP shim (§8.1 + `docs/slither-detector.md`) |
| M4 | Atomic Red Team support, sidecar expectations      | shipped    | eyeexam never clones; operators manage the clone (`docs/atomic-redteam.md`) |
| M5 | ATT&CK matrix + read-only UI                       | shipped    | `templ` + htmx → stdlib `html/template` (§2.3.1)      |
| M6 | Wazuh + Elastic + Splunk detectors                 | shipped    | docker-compose harness → `httptest`-based parity test |
| M7 | ~~slither runner via signed control plane~~        | retracted  | scope withdrawn — slither stays defensive-only (§7 M7) |
| M8 | schedule + drift alerts                            | shipped    | none                                                 |
| M9-A | `--actor-app` flag, schedules.app_user column    | shipped    | none                                                 |

The deviations listed are intentional substitutions documented in this file
or in `docs/`. Each one preserves the original interface contract; swapping
back to the planned dependency (templ, gRPC, etc.) is mechanical and does
not change runlife / score / audit.

**M7 was retracted in 2026-05.** The slither runner shipped as a JSON-over-HTTP
shim and was then removed entirely: turning slither's defensive control plane
into a BAS execution channel conflicts with slither's defensive scope and
roadmap. The slither *detector* (read-only event consumption, M3) remains
supported. See §7 M7 for the retraction notes; the offensive direction is
not on the roadmap.

The per-milestone scopes in §7 below remain accurate as the build records.
Operator-facing documentation lives under `docs/`:

- `docs/deploy-ssh.md` — eyeexam OS user, sudoers stanza, hostkey pinning.
- `docs/atomic-redteam.md` — operator clone workflow, sidecar layout.
- `docs/detectors.md` — per-backend config reference.
- `docs/scheduler.md` — schedule authoring + drift alerts.
- `docs/slither-detector.md` — shim contract + swap target for when
  slither's read API stabilizes.
- `docs/actor-app.md` — `--actor-app` operator guide.

---

## 1. Build approach

Eight milestones (M1 → M8), one session per milestone. Each milestone:

- Has a self-contained scope. Compiles, tests pass, `eyeexam` binary works
  end-to-end for the slice it covers.
- Adds new packages but does not rewrite existing ones unless explicitly
  called out in the per-milestone plan.
- Has a "definition of done" checklist plus a suggested manual smoke test.

The first milestone (M1) lays down the project skeleton — module, build,
config loader, pack loader, store, local runner, CLI — even if the runner is
the only one wired. Subsequent milestones plug new implementations into
already-defined interfaces, so the skeleton is not re-done.

---

## 2. Foundational decisions

### 2.1 Module & repo

- Module path: `github.com/eavalenzuela/eyeexam` (standalone repo, separate
  from slither).
- Companion repo for native attack scripts (decided this session, replacing
  PLAN.md's "vendor Atomic Red Team into packs/atomic"):
  `github.com/eavalenzuela/eyeexam-attackpacks`. eyeexam ships with a
  `packs/builtin/` directory of small smoke tests; the attackpacks repo is
  the curated catalog and is loaded via `eyeexam pack add <git-url>` rather
  than vendored into eyeexam's tree. Atomic Red Team support is retained
  (M4) — its loader points at an external clone the operator manages.

### 2.2 Go version & toolchain

- `go 1.23`.
- `golangci-lint`, `gofumpt`, `gotestsum` as dev deps (installed via
  `make tools`).
- `templ` codegen runs as part of `make build` (`templ generate` before
  `go build`).
- All go files formatted with `gofumpt`. CI fails on lint or unformatted code.

### 2.3 Runtime dependencies (locked)

| Purpose             | Choice                                         |
|---------------------|------------------------------------------------|
| CLI                 | `github.com/spf13/cobra`                       |
| Config binding      | `github.com/spf13/viper`                       |
| YAML                | `gopkg.in/yaml.v3`                             |
| SQLite (CGO-free)   | `modernc.org/sqlite` + `github.com/jmoiron/sqlx` |
| Migrations          | `github.com/pressly/goose/v3` (embedded SQL)   |
| SSH                 | `golang.org/x/crypto/ssh`                      |
| HTML templates      | `html/template` (stdlib) — see §2.3.1           |
| HTMX                | not bundled in v1; UI is server-rendered (§2.3.1) |
| MITRE ATT&CK STIX   | downloaded once at build, vendored under `packs/attack/` |
| Logging             | `log/slog` (stdlib), JSON to stderr            |
| ed25519             | `crypto/ed25519` (stdlib)                      |
| Test assertions     | `github.com/stretchr/testify`                  |

`mattn/go-sqlite3` is **not** used. (Resolves PLAN.md §"Packaging & deps"
inconsistency.)

#### 2.3.1 templ + htmx → stdlib swap (M5)

The original plan called for `templ` (codegen) + a vendored htmx.min.js. In
M5 we landed the read-only UI on stdlib `html/template` instead, with no
htmx dependency:

- **No codegen step.** `templ generate` would have added a tool-install
  prerequisite to `make build` and a generated-file-in-PR review burden;
  stdlib templates ship as plain text, embedded via `//go:embed`.
- **No htmx for v1.** The viewer is read-only — every page is a plain
  GET. There is no live update, no partial reload. We can layer htmx in
  later (drift cell → runs popover, etc.) without changing the routes.
- **Per-page parsed templates.** Because every page defines a `content`
  block, parsing them all into one `*template.Template` causes the last
  parsed file to win. `ui/handlers.go` parses each page independently
  (base.html + that page's file), keyed by name. This costs negligible
  memory and avoids template-namespace collisions.

The htmx vendoring task is reopened only if a future milestone needs
interactive cells. The Detector / Score / runlife layers are unchanged.

### 2.4 Repo layout (final, supersedes PLAN.md sketch)

```
eyeexam/
  cmd/eyeexam/
    main.go
    cmd_root.go             # cobra root; global flags
    cmd_init.go
    cmd_pack.go             # pack list / add / remove / update
    cmd_inventory.go
    cmd_plan.go
    cmd_run.go
    cmd_runs.go             # runs list / show / resume
    cmd_matrix.go
    cmd_audit.go
    cmd_serve.go
    cmd_version.go
  internal/
    config/                 # YAML config loader, validation, engagement metadata
    pack/                   # internal pack model + loaders
      loader_native.go      # eyeexam-native YAML
      loader_atomic.go      # Atomic Red Team YAML (M4)
      expectations.go       # sidecar expectations + builtin refuse list
      builtin_refuse.go     # hard-refuse test ids
    inventory/              # host inventory loader, tag selectors
    runner/
      runner.go             # interface + Result type
      local.go              # localhost executor (M1)
      ssh.go                # SSH executor (M2)
    detector/
      detector.go           # interface + ExpectationQuery / Hit types
      fake.go               # in-process fake (test fixture)
      slither.go            # ClickHouse via slither read API (M3)
      loki.go               # LogQL (M3)
      wazuh.go              # OpenSearch (M6)
      elastic.go            # Elasticsearch (M6)
      splunk.go             # Splunk REST (M6)
    score/                  # caught/missed/uncertain logic, dedup, aggregation
    cleanup/                # cleanup execution + verification orchestration
    matrix/                 # ATT&CK heatmap renderer (HTML + JSON)
    store/
      store.go              # sqlx wrapper, transactions, models
      migrations/           # goose SQL files, embed.FS
      runs.go
      executions.go
      detections.go
    audit/                  # ed25519 append-only signed audit log
    runlife/                # run lifecycle state machine (plan→…→report, resume)
    rate/                   # global rate limiter + per-host semaphore
    attack/                 # MITRE ATT&CK STIX bundle reader (technique → name/tactic)
    version/                # build-time version info
  ui/
    server.go               # HTTP server, routing, auth-less localhost-only
    handlers/
    templates/              # *.templ source
    static/                 # htmx.min.js, css
  packs/
    builtin/                # smoke / sanity tests (low destructiveness, /tmp only)
    attack/                 # vendored MITRE ATT&CK STIX bundle (read-only)
  tests/
    fixtures/
      packs/
      inventories/
    fakedetector/           # alias for internal/detector/fake (re-exported)
    sshd/                   # docker-compose for end-to-end SSH runner tests
    e2e/                    # plan→run→score→cleanup-verify integration test
  Makefile
  go.mod
  go.sum
  README.md
  PLAN.md
  IMPLEMENTATION.md
  LICENSE                   # Apache-2.0 (matches slither neighbor)
```

### 2.5 Config & state directories

- Config: `${EYEEXAM_HOME:-$XDG_CONFIG_HOME/eyeexam}/config.yaml`.
- Audit key: `${EYEEXAM_HOME:-$XDG_CONFIG_HOME/eyeexam}/audit.key` (ed25519
  private key, 0600). Public key co-located as `audit.key.pub`.
- SQLite DB: `${EYEEXAM_DATA:-$XDG_DATA_HOME/eyeexam}/eyeexam.db`.
- Runs artifacts (per-execution stdout/stderr if oversized, matrix exports):
  `${EYEEXAM_DATA:-$XDG_DATA_HOME/eyeexam}/artifacts/<run-id>/...`.
- Pack registry (eyeexam-attack-scripts and any other added packs are cloned
  here): `${EYEEXAM_DATA:-$XDG_DATA_HOME/eyeexam}/packs/<name>/`.

`--config <path>`, `EYEEXAM_HOME`, and `EYEEXAM_DATA` override defaults.

### 2.6 Audit-log actor identity

Actor identity is captured as **two fields**, both written to every audit
record. The OS-user field is always derived from `os/user.Current()`; the
application-user field is optional and populated when the operator passes
`--actor-app <name>` to `eyeexam run` or to `eyeexam schedule add`. The
flag exists so that runs invoked by a service account (CI, scheduler under
systemd) can still attribute actions to the human who authorized them. A
future frontend with session-based login would also write into this same
field — the schema doesn't change.

```json
{
  "actor": {
    "os_user": "ealey",        // os/user.Current().Username + uid
    "os_uid":  1000,
    "app_user": null            // populated by future frontend auth
  }
}
```

`audit.Record.Actor` struct mirrors this. Helpers in `internal/audit`:

```go
func ActorFromOS(ctx context.Context) (Actor, error) // os/user.Current
func (a Actor) String() string                       // "ealey(uid=1000)"
```

When an app-layer caller exists later, it populates `Actor.AppUser` before
calling `audit.Append`. v1 always passes the OS-only actor.

### 2.7 PLAN.md inconsistencies resolved

- SQLite driver: `modernc.org/sqlite` only.
- Atomic Red Team vendoring: not committed; loaded from operator-managed
  external clone (M4). eyeexam-attack-scripts is the curated native pack
  catalog and is also operator-managed (clone-on-add).
- "Single Go binary" + templ: templ generates `_templ.go` files at build time
  that are committed (deterministic codegen), so the final binary still has
  no runtime template engine.
- Audit `"actor":"alice"` example in PLAN.md is rewritten to the structured
  form in §2.6.

---

## 3. Data model (SQLite schema)

Schema lives in `internal/store/migrations/` as goose SQL files. All
timestamps are `TEXT` ISO-8601 UTC. Foreign keys ON.

### 3.1 Tables

```sql
-- 0001_init.sql

CREATE TABLE schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE engagements (
  id          TEXT PRIMARY KEY,         -- e.g. "HOMELAB-2026"
  description TEXT,
  created_at  TEXT NOT NULL
);

CREATE TABLE runs (
  id              TEXT PRIMARY KEY,     -- "r-" + ulid
  engagement_id   TEXT NOT NULL REFERENCES engagements(id),
  seed            INTEGER NOT NULL,
  max_dest        TEXT NOT NULL CHECK (max_dest IN ('low','medium','high')),
  selector_json   TEXT NOT NULL,        -- captured selectors at plan time
  plan_json       TEXT NOT NULL,        -- resolved (host x test) plan
  phase           TEXT NOT NULL CHECK (phase IN
                    ('planned','executing','waiting','querying',
                     'scoring','cleanup','reported','failed')),
  authorized_by   TEXT NOT NULL,        -- os_user(uid)
  app_user        TEXT,                 -- nullable (v1 always null)
  started_at      TEXT,
  finished_at     TEXT
);

CREATE TABLE hosts (
  id          TEXT PRIMARY KEY,         -- ulid
  name        TEXT NOT NULL UNIQUE,
  inventory_json TEXT NOT NULL          -- snapshot of inventory entry at run time
);

CREATE TABLE executions (
  id              TEXT PRIMARY KEY,     -- "x-" + ulid
  run_id          TEXT NOT NULL REFERENCES runs(id),
  host_id         TEXT NOT NULL REFERENCES hosts(id),
  test_id         TEXT NOT NULL,        -- pack test id
  test_source     TEXT NOT NULL,        -- 'native' | 'atomic'
  test_yaml_sha256 TEXT NOT NULL,       -- exact pack content hash
  attack_technique TEXT,                -- e.g. "T1070.003"
  attack_tactic   TEXT,                 -- e.g. "TA0005"
  destructiveness TEXT NOT NULL CHECK (destructiveness IN ('low','medium','high')),
  runner          TEXT NOT NULL,        -- 'local' | 'ssh' (legacy rows may carry 'slither' before M7 retraction)
  started_at      TEXT NOT NULL,
  finished_at     TEXT,
  exit_code       INTEGER,
  duration_ms     INTEGER,
  stdout_path     TEXT,                 -- artifact path if > inline limit
  stdout_inline   TEXT,                 -- otherwise inlined
  stderr_path     TEXT,
  stderr_inline   TEXT,
  cleanup_state   TEXT NOT NULL DEFAULT 'pending'
                    CHECK (cleanup_state IN
                      ('pending','succeeded','failed','no_cleanup_defined')),
  cleanup_verify_state TEXT NOT NULL DEFAULT 'pending'
                    CHECK (cleanup_verify_state IN
                      ('pending','succeeded','failed','not_defined','warned_atomic')),
  detection_state TEXT NOT NULL DEFAULT 'pending'
                    CHECK (detection_state IN
                      ('pending','caught','missed','uncertain','no_expectation'))
);

CREATE TABLE expected_detections (
  id              TEXT PRIMARY KEY,     -- ulid
  execution_id    TEXT NOT NULL REFERENCES executions(id),
  expectation_json TEXT NOT NULL,       -- normalized ExpectationQuery
  wait_seconds    INTEGER NOT NULL,
  state           TEXT NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending','caught','missed','uncertain')),
  detector_name   TEXT,                 -- which detector adjudicated this
  reason          TEXT                  -- present for uncertain
);

CREATE TABLE detection_hits (
  id              TEXT PRIMARY KEY,
  expected_id     TEXT NOT NULL REFERENCES expected_detections(id),
  hit_id          TEXT NOT NULL,        -- detector-native id (dedup key)
  hit_at          TEXT NOT NULL,
  raw_json        TEXT NOT NULL,
  UNIQUE (expected_id, hit_id)
);

CREATE TABLE audit_log (
  seq             INTEGER PRIMARY KEY AUTOINCREMENT,
  ts              TEXT NOT NULL,
  actor_json      TEXT NOT NULL,        -- §2.6 Actor
  engagement_id   TEXT,
  run_id          TEXT,
  event           TEXT NOT NULL,
  payload_json    TEXT NOT NULL,
  prev_hash       TEXT NOT NULL,        -- chain hash, hex-encoded
  hash            TEXT NOT NULL,
  signature       TEXT NOT NULL         -- ed25519, base64
);

CREATE INDEX idx_executions_run    ON executions(run_id);
CREATE INDEX idx_executions_host   ON executions(host_id);
CREATE INDEX idx_executions_tech   ON executions(attack_technique);
CREATE INDEX idx_expected_exec     ON expected_detections(execution_id);
CREATE INDEX idx_audit_run         ON audit_log(run_id);
```

The audit log lives both in SQLite (queryable) and in `audit.log` (file).
The **file is authoritative**; the SQLite `audit_log` table is a
queryable mirror.

Append ordering:

1. Compute hash + signature, holding the Logger mutex.
2. Write the JSON line to the file and `Sync()` (fsync) — at this
   point the record is durable and signed.
3. INSERT the same record into `audit_log`. A failure here is logged
   loudly but does not fail the Append: the file already has the
   record, and the row will be backfilled on the next `audit.Open`.

Open-time reconciliation walks the file; for any seq present in the
file but missing from `audit_log`, the row is backfilled. If the DB
holds a seq beyond what the file contains (file truncated, DB-side
tampering), `Open` refuses to start.

`audit.VerifyWithMirror` cross-checks the two stores: it walks the
hash chain in the file (the same as `audit.Verify`), then asserts
that every (seq, hash) pair in `audit_log` matches the file. The
file wins on conflict; divergence is reported with the first bad seq.

### 3.2 Phase state machine

`runs.phase` values map to phases that each commit their own results:

```
planned → executing → waiting → querying → scoring → cleanup → reported
                                                         ↓
                                                       failed (terminal)
```

`eyeexam runs resume <run-id>` reads `phase`, replays from the next phase.
Already-completed executions inside a phase are skipped (idempotency keys =
`execution_id`). Phase transitions are wrapped in a single SQL transaction
that updates `runs.phase` plus any phase-specific rows.

---

## 4. Internal package contracts

These types and interfaces are landed in M1 (or earliest milestone needing
them) and never broken in subsequent milestones. They're the integration
surface between layers.

### 4.1 `internal/pack`

```go
type Test struct {
    ID              string                 // pack-unique id
    Source          Source                 // SourceNative | SourceAtomic
    YAMLSHA256      string                 // hash of source bytes
    Name            string
    Description     string
    Attack          AttackRef              // technique + tactic
    Destructiveness Dest                   // low|medium|high
    Platforms       []string               // "linux", "darwin", "windows"
    Inputs          map[string]InputSpec
    Execute         []Step
    Cleanup         []Step
    VerifyCleanup   []Step
    Expectations    []Expectation
    WaitSeconds     int                    // detector window
}

type Step struct {
    Shell   string                         // "bash", "powershell", ...
    Command string                         // template, $(input.X) substitution
}

type Expectation struct {
    SigmaID     string                     // optional
    Tag         string                     // ATT&CK or arbitrary tag
    Query       string                     // detector-native query
    Backend     string                     // limits which detector handles it
    Description string
}

type Loader interface {
    Load(ctx context.Context, root string) ([]Test, error)
    Source() Source
}

type Pack struct {
    Name   string
    Path   string
    Tests  []Test
    Source Source
}

type Registry struct { /* ... */ }
func (r *Registry) Add(name, path string, source Source) error
func (r *Registry) List() []Pack
func (r *Registry) Resolve(testIDs []string) ([]Test, error)
```

Atomic Red Team expectations are pulled from
`<pack-root>/expectations/<atomic-id>.yaml` (sidecar). Native packs put
expectations inline.

### 4.2 `internal/inventory`

```go
type Host struct {
    Name      string
    Address   string
    Transport string                       // "ssh"|"local"
    User      string
    KeyPath   string
    Tags      []string
    MaxDest   Dest                         // optional per-host cap
}

type Inventory struct {
    Hosts []Host
    Tags  map[string]TagPolicy
}

type TagPolicy struct {
    MaxDestructiveness Dest
}

type Selector struct {
    Hosts    []string
    Tags     []string
    NotTags  []string
    Tests    []string                      // glob
    NotTests []string
}

func (i *Inventory) Apply(s Selector) ([]Host, []string /* warnings */, error)
```

### 4.3 `internal/runner`

```go
type ExecuteStep struct {
    Shell   string
    Command string                         // already-substituted final command
    Stdin   io.Reader                      // usually nil
    Env     map[string]string
    Timeout time.Duration
}

type Result struct {
    ExitCode int
    Stdout   []byte
    Stderr   []byte
    Started  time.Time
    Finished time.Time
}

type Runner interface {
    Name() string                          // "local"|"ssh"
    Capabilities() []string                // shells available
    Execute(ctx context.Context, host inventory.Host, step ExecuteStep) (Result, error)
    Close() error
}
```

The runner does **not** know about pack semantics, expectation queries, or
scoring — only "run this command on this host, capture output". The
lifecycle layer in `internal/runlife` owns sequencing and persistence.

### 4.4 `internal/detector`

```go
type ExpectationQuery struct {
    Expectation pack.Expectation
    HostID      string
    HostName    string
    HostAddress string
    Window      TimeWindow
    ExecutionID string
}

type TimeWindow struct {
    Start time.Time
    End   time.Time
}

type Hit struct {
    ID         string                      // detector-native id
    At         time.Time
    HostHint   string                      // host correlation hint
    Raw        json.RawMessage
}

type Detector interface {
    Name() string
    Supports(e pack.Expectation) bool      // backend filtering
    Query(ctx context.Context, q ExpectationQuery) ([]Hit, error)
    HealthCheck(ctx context.Context) error
}

type Registry struct { /* ... */ }
func (r *Registry) For(e pack.Expectation) []Detector  // all detectors that Support(e)
```

Multiple detectors can claim the same expectation (e.g. both slither and
elastic ingesting from the same host); a hit from any detector is enough
for `caught`. Lack-of-hits across **all** claiming detectors is `missed`.
If any detector errored and others returned no hits, the result is
`uncertain` with a reason listing the failing detectors.

### 4.5 `internal/score`

```go
type ExpectationOutcome struct {
    ExpectationID string
    State         State                    // caught|missed|uncertain
    Reason        string
    Hits          []detector.Hit
    DetectorName  string                   // first detector to produce caught, else ""
}

type ExecutionOutcome struct {
    ExecutionID string
    Per         []ExpectationOutcome
    Worst       State                      // worst across Per (or no_expectation)
}

func ScoreExecution(ctx context.Context, ex Execution,
    rs []ExpectationOutcome) ExecutionOutcome
```

Worst-state ranking: `caught < uncertain < missed`. `no_expectation` is its
own terminal state — never folded into `caught`. Cleanup state is independent
of detection state.

### 4.6 `internal/cleanup`

```go
type Outcome struct {
    CleanupRan      bool
    VerifyRan       bool
    CleanupErr      error
    VerifyErr       error
    State           State                  // succeeded|failed|not_defined|warned_atomic
}

func RunCleanup(ctx context.Context, r runner.Runner, host inventory.Host,
    t pack.Test) Outcome
```

If `verify_cleanup` is missing on a native test, this is a **load-time**
validation error (rejected by the loader). For Atomic Red Team tests, no
verify is permitted; outcome state is `warned_atomic` and the run report
flags it.

### 4.7 `internal/audit`

```go
type Actor struct {
    OSUser  string `json:"os_user"`
    OSUID   int    `json:"os_uid"`
    AppUser *string `json:"app_user,omitempty"`
}

type Record struct {
    Seq        int64                       // assigned by Append
    TS         time.Time
    Actor      Actor
    Engagement string
    RunID      string
    Event      string                      // "run_start"|"run_finish"|"test_skip"|...
    Payload    json.RawMessage
    PrevHash   []byte                      // 32B sha256
    Hash       []byte                      // sha256(prev_hash || canonical_json(rec))
    Signature  []byte                      // ed25519 of Hash
}

type Logger struct { /* ... */ }
func Open(path string, key ed25519.PrivateKey, db *sqlx.DB) (*Logger, error)
func (l *Logger) Append(ctx context.Context, r Record) error
func (l *Logger) Verify(ctx context.Context, pub ed25519.PublicKey) error
```

Hash chain: `Hash[n] = sha256(Hash[n-1] || canonical-JSON-without-{Hash,Signature}(rec[n]))`.
`Hash[0]` covers genesis sentinel. Tampering with any record breaks the
chain at that point onwards; `Verify` reports the first divergent seq.

### 4.8 `internal/runlife`

```go
type Phase string
const (
    PhasePlanned    Phase = "planned"
    PhaseExecuting  Phase = "executing"
    PhaseWaiting    Phase = "waiting"
    PhaseQuerying   Phase = "querying"
    PhaseScoring    Phase = "scoring"
    PhaseCleanup    Phase = "cleanup"
    PhaseReported   Phase = "reported"
    PhaseFailed     Phase = "failed"
)

type Engine struct { /* runners, detectors, store, audit, rate limiter */ }

func (e *Engine) Plan(ctx context.Context, p PlanRequest) (RunID, error)
func (e *Engine) Execute(ctx context.Context, runID RunID) error  // runs full pipeline
func (e *Engine) Resume(ctx context.Context, runID RunID) error
```

`Execute` is idempotent at phase granularity. Each phase either fully
completes and advances, or marks the run `failed` with a reason.

### 4.9 `internal/rate`

Two limiters in series:

- Global token bucket (default 1 test/sec, configurable). Rate-limits
  *test starts*, not steps within a test.
- Per-host semaphore (default 1, configurable). Two tests never run
  concurrently on the same host.

Both are in-process; `eyeexam run` is a single-shot CLI invocation, not a
daemon, so no cross-process coordination is needed for v1. The scheduler in
M8 will be a separate daemon mode that respects the same limiters.

---

## 5. Configuration schema

Single YAML file. Validated against an embedded JSON schema for clear errors.

```yaml
engagement:
  id: HOMELAB-2026
  description: Homelab BAS — quarterly coverage review

state:
  data_dir: ~/.local/share/eyeexam       # overridable
  database: eyeexam.db                   # under data_dir

audit:
  key_path: ~/.config/eyeexam/audit.key
  log_path: ~/.local/share/eyeexam/audit.log

runner:
  ssh:
    default_user: eyeexam
    default_key: ~/.ssh/eyeexam_ed25519
    connect_timeout: 10s
    command_timeout: 5m
  local:
    enabled: true                        # explicit opt-in for safety
    # localhost is fully capable of destructive runs; gated by --max-dest +
    # the destructive-confirmation prompt described in §6.1.

detectors:
  - name: slither
    type: slither
    server: grpc.slither.lab:7443
    ca: /etc/slither/ca.pem
  - name: loki
    type: loki
    url: http://loki.lab:3100
    tenant: homelab
    label_host: host
  - name: elastic                        # M6
    type: elastic
    hosts: [https://es.lab:9200]
    api_key_env: EYEEXAM_ELASTIC_API_KEY
    index_pattern: filebeat-*

inventory:
  path: ./inventory.yaml                 # may also be inlined here

packs:
  - name: builtin
    path: ./packs/builtin                # ships with eyeexam
    source: native
  - name: eyeexam-attackpacks
    path: ~/.local/share/eyeexam/packs/eyeexam-attackpacks
    source: native
  - name: atomic                         # optional, M4
    path: ~/.local/share/eyeexam/packs/atomic-red-team
    source: atomic

limits:
  global_tests_per_second: 1
  per_host_concurrency: 1

ui:
  listen: 127.0.0.1:8088                 # never bind public by default
```

---

## 6. CLI surface (final)

Matches PLAN.md but adds pack management commands needed by §2.1:

```
eyeexam version
eyeexam init                                    # scaffold config + audit key + db
eyeexam pack list
eyeexam pack add    <name> <path-or-git-url>    # registers / clones a pack
eyeexam pack update <name> [--ref <git-ref>]    # git-pull pinned ref
eyeexam pack remove <name>
eyeexam inventory list
eyeexam inventory check                          # lints inventory + ssh reachability
eyeexam plan   --pack <name> [--tag <t>] [--hosts ...] [--tests ...] [--seed N]
eyeexam run    --pack <name> [...same...] \
               --authorized --engagement <id> \
               [--max-dest low|medium|high] [--dry-run] [--seed N] [--yes] \
               [--actor-app <name>]              # populates audit Actor.AppUser + runs.app_user
eyeexam runs   list   [--engagement <id>] [--since <dur>]
eyeexam runs   show   <run-id> [--json]
eyeexam runs   resume <run-id>
eyeexam matrix [--since 30d] [--tag <t>] [--out matrix.html|matrix.json]
eyeexam audit  verify [--from-seq N] [--to-seq M]
eyeexam serve  [--listen :8088]                  # read-only UI
```

Global flags: `--config`, `--data-dir`, `--log-level`, `--no-color`.

### 6.1 Destructive-run confirmation

Any `eyeexam run` whose resolved plan contains a test with `destructiveness >
low` requires **all** of the following before execution begins:

- `--authorized` flag is present.
- `--max-dest medium` (or `high`) is explicitly passed; the run is rejected
  if the plan exceeds `--max-dest`.
- The lowest applicable cap (per-host `max_destructiveness`, per-tag
  `max_destructiveness`, run-level `--max-dest`) is computed and printed.
- **Interactive confirmation prompt** showing: engagement id, host count,
  list of tests above `low` with their destructiveness rating, and the
  affected hosts. Operator must type the engagement id verbatim to proceed.
  `--yes` skips the prompt only when accompanied by `--i-really-mean-it`
  for runs containing `high` destructiveness; `medium` accepts plain
  `--yes`. The localhost runner has no special exemption — same gating
  applies — but is also not specially refused.
- An audit-log `event:"destructive_run_authorized"` record is written with
  the actor, the test ids, and the resolved max destructiveness, **before**
  the first test executes.

Non-interactive contexts (CI, scheduler) must use
`--yes --i-really-mean-it` for `high` runs; the scheduler in M8 stores
this pre-authorization per-schedule and writes the same audit record on
each scheduled fire.

---

## 7. Per-milestone plan

Each milestone has: scope, files added, key dependencies on prior milestones,
definition of done, smoke test.

### M1 — Local runner + native pack format

**Scope.** Build the skeleton and prove the bones end-to-end on `localhost`.

**Files added.**

- `cmd/eyeexam/main.go`, `cmd_root.go`, `cmd_init.go`, `cmd_version.go`,
  `cmd_pack.go` (list/add only), `cmd_inventory.go` (list only),
  `cmd_plan.go`, `cmd_run.go`, `cmd_runs.go` (list/show only).
- `internal/config/{config.go,schema.json,validate.go}`.
- `internal/pack/{pack.go,loader_native.go,registry.go,builtin_refuse.go,
  expectations.go}`.
- `internal/inventory/{inventory.go,selector.go}`.
- `internal/runner/{runner.go,local.go}`.
- `internal/store/{store.go,migrations/0001_init.sql,runs.go,executions.go}`.
- `internal/audit/{audit.go,actor.go,verify.go}` — full hash-chain
  implementation, even though only a small set of events emit yet.
- `internal/runlife/{engine.go,phase_plan.go,phase_execute.go,
  phase_cleanup.go,phase_report.go}` — only phases that don't need a
  detector wired (waiting/querying/scoring are stubbed: skipped if no
  detectors configured, marking detection_state = `no_expectation` when
  expectation list is empty, `pending` otherwise — never `caught`).
- `internal/rate/{rate.go,host_sem.go}`.
- `internal/version/version.go`.
- `packs/builtin/eye-001-tmp-touch.yaml`,
  `packs/builtin/eye-002-bash-history-clear.yaml`,
  `packs/builtin/eye-003-fake-curl-attacker.yaml` (all destructiveness:
  low, /tmp-only, idempotent cleanup).
- `tests/fixtures/...`.
- `tests/e2e/local_smoke_test.go`.
- `Makefile` targets: `tools`, `lint`, `test`, `build`, `dist`.
- `README.md` (minimal: what it is, how to run M1 smoke).

**Key behaviors locked.**

- `eyeexam init` creates the data dir, generates ed25519 key, scaffolds a
  config with a placeholder engagement id, applies migrations, prints the
  next-step instructions.
- `eyeexam run --authorized --engagement HOMELAB-2026 --pack builtin
  --hosts localhost --max-dest low` runs the three smoke tests against
  localhost and writes a complete run record.
- `eyeexam runs show <id>` prints the run summary (per-test outcomes,
  cleanup states) as a plain table; `--json` emits the full record.
- Without `--authorized` the binary refuses to do anything destructive,
  including `run`. `plan` and `runs show` are allowed without it.
- Hard refuse list is enforced in M1 (it's just a string-set check on test
  ids and on certain cleanup-script patterns).

**Definition of done.**

- `make test` green.
- `make lint` green (golangci-lint with project config).
- `eyeexam init && eyeexam run ...` produces a run row with three executions,
  each with `cleanup_state=succeeded`, `cleanup_verify_state=succeeded`,
  `detection_state=no_expectation`. Audit log has 5 entries (`init`,
  `run_start`, 3× `test_executed`, `run_finish`) and verifies clean.
- `eyeexam audit verify` returns OK.
- README walks a fresh user from `make build` to first run in <5 minutes.

**Smoke test (manual).**

```
make build && ./bin/eyeexam init
./bin/eyeexam pack list
./bin/eyeexam plan --pack builtin --hosts localhost
./bin/eyeexam run  --pack builtin --hosts localhost \
   --authorized --engagement HOMELAB-2026 --max-dest low --yes
./bin/eyeexam runs list
./bin/eyeexam runs show <id>
./bin/eyeexam audit verify
```

### M2 — SSH runner + inventory + audit log richness

**Scope.** Multi-host execution with selectors, full audit-log event coverage,
inventory linting, per-host concurrency cap, reachability check.

**Files added/changed.**

- `internal/runner/ssh.go` — opens a session per step, no reuse across
  unrelated tests. Supports key-only auth (no passwords), known_hosts
  pinning required, optional `sudoers_check` on connect.
- `internal/inventory/`: `reachability.go`, `inventory check` subcommand.
- `internal/audit/`: add structured payloads for `host_skipped`,
  `expectation_skipped`, `cleanup_failed`.
- `cmd/eyeexam/cmd_inventory.go`: add `check`.
- `tests/sshd/`: docker-compose for an OpenSSH server with a pre-seeded
  `eyeexam` user and the sudoers stanza from the deployment doc.
- `tests/e2e/ssh_smoke_test.go`.
- `docs/deploy-ssh.md`: sudoers stanza, ssh-key provisioning script.

**Definition of done.**

- Run against the dockerized sshd successfully; selectors `--tag linux`,
  `--tag-not prod` work.
- Per-host concurrency cap enforced (test: 5 tests on 1 host complete
  serially even though `--parallel` would normally allow more).
- Global rate limit enforced (test: 5 tests across 5 hosts respect
  `global_tests_per_second: 1`).
- `eyeexam inventory check` reports per-host SSH reachability + auth status.
- Audit log richness: every host-level skip / cap-hit / cleanup-failure
  emits a record; `audit verify` clean.

### M3 — Detector interface + slither + loki + scoring

**Scope.** Wait-and-query loop, scoring (caught/missed/uncertain), cleanup
verification gating into the report.

**Files added.**

- `internal/detector/{detector.go,registry.go,fake.go,loki.go,slither.go}`.
  - `slither.go`: HTTP/JSON read API client. Pointed at slither server's
    read endpoint; for now uses a thin client (slither's read API design is
    still in flux per `../slither/PROJECT.md`). The detector accepts a query
    string + time window, returns hits. **Decision deferred:** see §8.
- `internal/score/{score.go,worst.go}`.
- `internal/cleanup/cleanup.go` (verify gate becomes mandatory and visible
  in `runs show`).
- `internal/runlife/{phase_wait.go,phase_query.go,phase_score.go}` —
  replace stubs from M1.
- `tests/fakedetector/` — re-exports `internal/detector.NewFake`.
- `tests/e2e/full_pipeline_test.go` — plan→run→wait→query(fake)→score→
  cleanup-verify, asserts exact `caught/missed/uncertain` distribution
  against a scripted scenario.

**Definition of done.**

- Native test with explicit expectations runs against fake detector and
  produces correct caught/missed/uncertain depending on scripted hits.
- Loki detector queries a local Loki container with seeded log lines, and
  produces a real `caught`.
- An expectation with no detector that `Supports` it produces `uncertain`
  with reason `"no detector configured for backend=X"`.
- `runs show` prints per-expectation outcomes and cleanup-verify state.
- Worst-state aggregation matches the truth table in `internal/score`.

### M4 — Atomic Red Team support + sidecar expectations

**Scope.** Load Atomic Red Team YAML from an operator-managed external clone.
Implement sidecar expectations layout. Hard-refuse list grows to cover the
problematic Atomic tests called out in PLAN.md §"Safety rails".

**Files added/changed.**

- `internal/pack/loader_atomic.go` — handles Atomic's
  `atomics/<technique>/<technique>.yaml` layout, executor selection, input
  arg substitution differences.
- `internal/pack/expectations.go` — sidecar resolution:
  `<pack-root>/expectations/<atomic-id>.yaml`.
- `cmd/eyeexam/cmd_pack.go` — add `update` (git pull at pinned ref),
  `remove`.
- `internal/pack/builtin_refuse.go` — populate concrete refused ids. The
  list is decided in this milestone (not pre-committed); candidate
  categories per PLAN.md §"Safety rails" are domain-controller
  modification, EDR-disable, bootloader-modify. Final list is reviewed
  with the operator before merge.
- `docs/atomic-redteam.md` — operator setup: `git clone redcanaryco/...`
  to `~/.local/share/eyeexam/packs/atomic-red-team`, `eyeexam pack add
  atomic ./atomic-red-team --source atomic`, pinning workflow.

**Definition of done.**

- A real Atomic test (e.g. T1070.003 atomics on Linux) loads, runs, scores
  via the sidecar expectation, and cleans up.
- Refused tests are blocked at plan time with a clear error and an audit
  record (`event:"test_refused"`).
- `eyeexam pack update atomic` does a fast-forward pull and refuses if the
  new tip would change the hash of any test that's currently in an active
  run plan.

### M5 — ATT&CK matrix + read-only UI

**Scope.** HTML matrix, run viewer, drift homepage.

**Files added.**

- `internal/attack/{stix.go,matrix.go}` — read MITRE ATT&CK STIX bundle
  vendored at `packs/attack/enterprise-attack.json`, build technique →
  tactic mapping, full matrix grid.
- `internal/matrix/{matrix.go,html.go,json.go}`.
- `ui/server.go`, `ui/handlers/{home.go,runs.go,run_detail.go,matrix.go}`.
- `ui/templates/*.templ` — base layout, matrix grid, run list, run detail,
  drift view.
- `ui/static/{htmx.min.js,style.css}`.
- `cmd/eyeexam/cmd_serve.go`, `cmd_matrix.go` — `matrix` exports HTML/JSON
  to a path; `serve` runs the read-only HTTP server.
- `make build` wires `templ generate`.

**Definition of done.**

- `eyeexam matrix --out matrix.html` produces a standalone HTML file with
  green/yellow/red/grey cells over real run data.
- `eyeexam serve` exposes `/`, `/runs`, `/runs/<id>`, `/matrix`. Default
  bind is `127.0.0.1:8088` and refuses to bind a non-loopback address
  without an explicit `--listen` and `--insecure-public` confirmation flag.
- Drift view ranks techniques by green→red regression in the configured
  window.

### M6 — Wazuh + Elastic + Splunk detectors

**Scope.** Three more `Detector` implementations. No interface changes.

**Files added.**

- `internal/detector/wazuh.go` — OpenSearch search API.
- `internal/detector/elastic.go` — Elasticsearch / Elastic Security; API key
  auth.
- `internal/detector/splunk.go` — search REST API (sync search, with
  configurable polling interval for long searches).
- `tests/integration/detectors/` — docker-compose harnesses for all three
  with seeded events.

**Definition of done.**

- Each detector passes a parity test: identical seeded event in each
  backend, identical expectation, all produce `caught`.
- HealthCheck reports auth/connectivity issues clearly at startup, not
  silently at query time.

### M7 — slither runner *(retracted 2026-05)*

**Original scope.** Dispatch test commands via the slither agent's signed
control plane, with a `BasExecuteRequest`/`BasExecuteResponse` proto
extension on slither's side.

**Retracted.** eyeexam will not use slither agents to run code on hosts.
Turning slither's defensive control plane into a BAS execution channel
conflicts with slither's own scope (its roadmap is detection rules + canned
response actions, not arbitrary command execution). Operators wire eyeexam
through the local or SSH runners; sites that already run slither agents do
not get a dual-purpose convenience.

**What was removed.**

- `internal/runner/slither.go` and its test, `tests/e2e/slither_smoke_test.go`.
- `runner.slither` config block, `inventory.Host.AgentID`, the
  `transport: "slither"` validator branch.
- `docs/slither-runner.md`.
- The proto-extension proposal above; eyeexam is not asking slither to add
  a BAS execute surface.

**What remains supported.**

- The slither *detector* (M3, `internal/detector/slither.go`,
  `docs/slither-detector.md`) is read-only event consumption and stays.
  It's no different in posture from Loki/Elastic/Splunk/Wazuh.

**If this is ever revisited:** the local + SSH runners cover every host
eyeexam should be reaching. A "slither runner" would only re-enter scope
if slither itself adopts a first-class BAS execute surface (which is not
on its roadmap).

### M8 — Schedule + drift alerts

**Scope.** Cron-style scheduling daemon, alert sinks for regressions.

**Files added.**

- `cmd/eyeexam/cmd_schedule.go` — `eyeexam schedule add|list|remove`,
  `eyeexam scheduler run` (foreground daemon).
- `internal/scheduler/{scheduler.go,store.go}` — schedule rows in SQLite,
  cron expressions, last-run tracking.
- `internal/alert/{alert.go,ntfy.go,discord.go,webhook.go}` — drift alert
  delivery.
- `internal/score/drift.go` — green→red regression detection per technique.

**Definition of done.**

- `eyeexam schedule add --pack builtin --tag linux --cron "0 3 * * *"
  --engagement HOMELAB-2026 --max-dest low` enrolls a daily run.
- Scheduler-driven runs are indistinguishable from CLI-driven runs in the
  store except for an `audit.event:"run_start"` field `trigger:"schedule"`.
- Drift alert: simulated regression (toggle a fake-detector script from
  caught → missed) fires a webhook within one scheduled cycle.

---

## 8. Open questions / deferred decisions

1. **slither read API shape.** PLAN.md says the slither detector queries
   "ClickHouse via the slither server's read API". As of 2026-05
   slither's only read surface is its HTML/HTMX console at `/events`,
   which eyeexam cannot consume programmatically (no JSON variant, no
   bearer-token auth, no Sigma-rule-id filter). The slither detector
   therefore does not run against a real slither today. The detector
   stub stays in tree as a placeholder; the authoritative
   contract-proposal-for-slither lives at
   `docs/slither-api-requirements.md` — that is what we hand to
   slither maintainers when they're ready to build the read API.
   `docs/slither-detector.md` documents only the current stub wire
   format. (This is the *read* direction only — see §7 M7 for why the
   *write* direction was retracted.)
2. **PowerShell on Linux.** Initial release skips PS-only Atomic tests
   with a clear marker (PLAN.md "Still open"). Implementation: in M4,
   `loader_atomic.go` tags PS-only tests with `Skipped: "powershell-not-available"`,
   `eyeexam plan` shows them in a "skipped" section, and they never enter
   `executions`.
3. **Windows hosts.** Out of scope for v1 (PLAN.md). The schema's
   `Test.Platforms` field already supports `"windows"`, so Windows pack
   loaders/runners can land later without schema churn.
4. **MITRE ATT&CK STIX bundle update cadence.** Vendored on each release;
   refresh is a manual `make refresh-attack` that re-downloads from MITRE
   and commits the new JSON. (Not auto-updated — we want bundle changes to
   show up in PRs.)
5. **Pack signing.** Future work; not in scope for v1. eyeexam-attackpacks
   should grow signed releases later.
6. **Hard-refuse list contents.** Resolved in M4. Mechanism landed in M1
   (`internal/pack/builtin_refuse.go`, plan-time rejection, audit
   `event:"test_refused"`); the curated id set was populated alongside
   Atomic Red Team support and now covers domain-controller modification,
   EDR-disable, and bootloader/firmware categories. Operators extend the
   list by editing the file in their fork; moving it to config is a
   future consideration.

---

## 9. Cross-cutting conventions

- **Errors.** Use `%w` wrapping; sentinel errors only for cross-package
  contracts (e.g. `pack.ErrTestRefused`). No `errors.New("...")` returned
  to callers without context — always wrap with the operation that failed.
- **Context.** Every IO function takes `ctx context.Context`. Run-level
  cancellation propagates to detectors and runners; per-step timeouts are
  derived from config + per-test override.
- **Logging.** `slog` JSON to stderr. Standard fields: `run_id`,
  `execution_id`, `host`, `test_id`, `phase`. Operator-facing CLI output
  goes to stdout in human-readable form; logs go to stderr. `--log-level`
  controls slog level; default `info`.
- **No global state.** All long-lived objects (`Engine`, `Logger`, `Store`,
  detectors, runners) are constructed in `cmd/eyeexam` and threaded
  explicitly. No package-level vars beyond compile-time constants.
- **Determinism.** `--seed N` seeds host-order shuffling and any
  randomized input substitution. Same seed + same pack content (by sha256)
  + same inventory snapshot = identical `executions` row order and
  identical command bytes.
- **Authorization scope.** `--authorized` covers a single CLI invocation.
  The scheduler in M8 stores a per-schedule pre-authorization, but each
  scheduled run is still recorded with explicit `authorized:true` and the
  scheduling operator's identity.

---

## 10. What lands first this session vs. later

This document — and only this document — is the deliverable for this
session. Code, scaffolding, `go.mod`, and `make` targets land in M1,
which we'll do in the next session.
