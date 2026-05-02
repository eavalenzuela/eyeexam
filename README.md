# eyeexam

A breach-and-attack simulation runner that **closes the detection loop**:
schedule TTPs against your own hosts, wait, query your SIEM/EDR, score
whether the detection actually fired. Atomic Red Team supplies the
techniques; eyeexam runs them, asks the SIEM what it saw, and produces
an ATT&CK coverage heatmap.

> **Status: shipped.** Local + SSH runners; loki + wazuh + elastic +
> splunk detectors (slither stub pending upstream API); ed25519 pack
> signing; cron scheduler with drift alerts; HTML/JSON reports for
> coverage, per-run detail, and the ATT&CK matrix. See
> [`IMPLEMENTATION.md`](./IMPLEMENTATION.md) for the per-milestone build
> log.

## Quick start

```bash
make build

./bin/eyeexam init --engagement HOMELAB-2026

./bin/eyeexam pack list
./bin/eyeexam inventory list
./bin/eyeexam plan --pack builtin --hosts localhost

./bin/eyeexam run --pack builtin --hosts localhost \
    --authorized --engagement HOMELAB-2026 --max-dest low --yes

./bin/eyeexam runs show <run-id>
./bin/eyeexam report run <run-id> --out run.html      # eye-candy HTML
./bin/eyeexam report matrix --out matrix.html         # ATT&CK heatmap
./bin/eyeexam report coverage --engagement HOMELAB-2026 --out coverage.html
./bin/eyeexam audit verify
```

eyeexam outputs files, not a server. There is no `eyeexam serve` —
`report ...` produces standalone HTML documents with inlined CSS that
render anywhere (`xdg-open`, scp to a shared dir, attach to a ticket).
JSON output (`--format json`) is for ingestion by other tooling.

The bundled `builtin` pack — three smoke tests, low destructiveness,
`/tmp`-only, verify_cleanup enforced — is **embedded into the binary**.
No separate clone needed; `eyeexam run --pack builtin` works against a
fresh install. Source lives under `internal/pack/embedded/builtin/`.

## What it does

```
plan → confirm → execute → wait → query → score → cleanup-verify → report
```

Every test execution captures `{stdout, stderr, exit_code, duration,
host_id, runner}` into SQLite **before** moving to the next step. A
killed eyeexam process leaves a complete partial record. Every phase
transition is its own SQL transaction, so `eyeexam runs resume <id>`
re-enters at the next phase without re-executing finished work.

Detection scoring is honest: a test is `caught`, `missed`, or
`uncertain` per expectation. `uncertain` means the detector errored or
returned ambiguous results — it is **never** silently collapsed into
`caught`. Test-level state is the worst across all expectations.

## Capabilities

| layer        | implementations                                         |
|--------------|---------------------------------------------------------|
| Runners      | `local`, `ssh`                                         |
| Detectors    | `loki`, `slither`, `wazuh`, `elastic`, `splunk`         |
| Pack formats | eyeexam-native YAML, Atomic Red Team YAML (sidecar exp.) |
| Alert sinks  | `webhook`, `ntfy`, `discord`                            |
| Reports      | standalone HTML or JSON: `report coverage` / `report run` / `report matrix` |
| Audit        | append-only ed25519-signed JSONL chain (`audit verify`) |

## CLI surface

```
eyeexam version
eyeexam init [--engagement <id>]
eyeexam pack list | add <name> <path> --source native|atomic | remove <name>
eyeexam inventory list | check
eyeexam plan --pack <name> [--tag <t>] [--hosts ...] [--tests ...]
eyeexam run  --pack <name> --authorized --engagement <id> \
             [--max-dest low|medium|high] [--dry-run] [--seed N] [--yes]
eyeexam runs list [--engagement <id>] | show <run-id> [--json] | resume <run-id>
eyeexam audit verify | show [--run <id>] [--event <name>] [--actor <substr>] [--since <dur>] [--json]
eyeexam report coverage [--engagement <id>] [--since 30d] [--format html|json] [--out <path>]
eyeexam report run     <run-id>                 [--format html|json] [--out <path>]
eyeexam report matrix  [--engagement <id>]      [--since 30d] [--format html|json] [--out <path>]
eyeexam schedule add | list | remove
eyeexam scheduler run [--interval 30s] [--audit-verify-interval 1h]
```

## Topic-by-topic docs

- **SSH deployment** — `docs/deploy-ssh.md`
- **Atomic Red Team support** — `docs/atomic-redteam.md`
- **Detector backends** — `docs/detectors.md`
- **Scheduler & drift alerts** — `docs/scheduler.md`
- **Slither integration (read-only detector)** — `docs/slither-detector.md`
- **Actor identity (`--actor-app`)** — `docs/actor-app.md`
- **Audit log model + verification** — `docs/audit-log.md`
- **Pack signing** — `docs/pack-signing.md`
- **Reports** — `docs/reports.md`
- **Project spec** — `PLAN.md`
- **Engineering plan & milestone log** — `IMPLEMENTATION.md`

## Layout

```
cmd/eyeexam/         CLI (cobra)
internal/
  alert/             webhook / ntfy / discord sinks
  attack/            MITRE ATT&CK STIX bundle + embedded fallback
  audit/             ed25519-signed append-only audit log
  config/            YAML config loader
  detector/          Detector iface + 5 backends
  idgen/             sortable opaque ids
  inventory/         hosts + selectors
  pack/              native + atomic loaders + refuse list + signing
    embedded/        binary-embedded builtin pack (//go:embed)
    signature/       ed25519 manifest verifier
  rate/              per-host semaphore + global rate limiter
  report/            HTML + JSON renderers for coverage/run/matrix
  runner/            Runner iface + local/ssh
  runlife/           plan → execute → wait → query → score → cleanup → report
  scheduler/         cron-driven daemon
  score/             caught/missed/uncertain + drift detection
  store/             SQLite + embedded migrations
  version/
tests/
  e2e/               integration tests (local, ssh, full pipeline, scheduler drift)
  fixtures/          atomic + native test fixtures
  sshfx/             in-process SSH server fixture
docs/                operator-facing topic docs
```

## Development

```bash
make tools     # install golangci-lint, gofumpt, gotestsum
make fmt       # gofumpt
make lint      # golangci-lint
make test      # go test -race -count=1 ./...
make build     # CGO-free static binary in bin/eyeexam
make dist      # cross-compile linux/amd64, linux/arm64, darwin/arm64
```

The build is CGO-free (`modernc.org/sqlite`); the binary is
self-contained. Every test runs without docker — the SSH runner uses an
in-process `golang.org/x/crypto/ssh` server fixture; the SIEM detectors
use `httptest.Server` fakes; the scheduler is driven via an injectable
`Now()` clock.

## Safety rails

eyeexam refuses to do anything destructive without **all** of:

- `--authorized` flag
- `--engagement <id>` matching `config.engagement.id`
- `--max-dest` covering the plan's destructiveness
- For `medium`/`high`: an interactive confirmation that types the
  engagement id, or `--yes` (medium) / `--yes --i-really-mean-it` (high)

The localhost runner is fully capable of destructive runs but follows
the same gating. The scheduler stores its pre-authorization once at
schedule-add time and uses it on every fire — `eyeexam schedule list`
shows you who authorized what.

A built-in **hard-refuse list** blocks Atomic Red Team tests that are
inappropriate for BAS regardless of any other config: domain-controller
modification (Skeleton Key, DCSync, Golden Ticket), EDR-disable
techniques, and bootloader / firmware modification. See
`internal/pack/builtin_refuse.go`.

Every run records the resolved plan, the operator (OS user + uid), the
selectors used, refused/skipped tests, host failures, and any
destructive-run authorization to the signed audit log. `eyeexam audit
verify` walks the hash chain and reports the first divergent sequence
on any tamper.

## License

Apache-2.0. See `LICENSE`.
