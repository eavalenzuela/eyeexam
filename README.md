# eyeexam

A breach-and-attack simulation runner that **closes the detection loop**:
schedule TTPs against your own hosts, wait, query your SIEM/EDR, score
whether the detection actually fired.

See [`PLAN.md`](./PLAN.md) for the product spec and
[`IMPLEMENTATION.md`](./IMPLEMENTATION.md) for the engineering plan and
per-milestone roadmap.

> **Status: M1 — local runner + native pack format.** Plans, executes, and
> cleanup-verifies tests against `localhost`. Detector / scoring / SSH /
> matrix land in M2–M8.

## Quick start (M1 smoke)

```bash
# 1. Build
make build

# 2. Initialise config + audit key + SQLite DB
./bin/eyeexam init --engagement HOMELAB-2026 --builtin-packs "$PWD/packs/builtin"

# 3. Inspect the pack and inventory
./bin/eyeexam pack list
./bin/eyeexam inventory list

# 4. Plan against localhost (no execution)
./bin/eyeexam plan --pack builtin --hosts localhost

# 5. Run for real
./bin/eyeexam run --pack builtin --hosts localhost \
    --authorized --engagement HOMELAB-2026 --max-dest low --yes

# 6. Inspect results + verify the audit chain
./bin/eyeexam runs list
./bin/eyeexam runs show <run-id>
./bin/eyeexam audit verify
```

The bundled `packs/builtin/` smoke tests touch only `/tmp` and clean up after
themselves; verify_cleanup is enforced.

## Layout

```
cmd/eyeexam/      CLI (cobra)
internal/
  audit/          ed25519-signed append-only audit log
  config/         YAML config loader
  inventory/      hosts + selectors
  pack/           native pack model + loader
  rate/           per-host semaphore + global rate limiter
  runner/         runner interface + local executor
  runlife/        run lifecycle engine (plan → execute → cleanup → report)
  store/          SQLite + embedded migrations
packs/builtin/    bundled smoke tests
tests/e2e/        end-to-end smoke
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

## Safety

eyeexam refuses to do anything destructive without **all** of:

- `--authorized` flag
- `--engagement <id>` matching the configured engagement
- `--max-dest` covering the plan's destructiveness
- For `medium`/`high`: an interactive confirmation typing the engagement id,
  or `--yes` (medium) / `--yes --i-really-mean-it` (high)

Every run records the resolved plan, the operator (OS user + uid), and any
destructive-run authorization in the signed audit log.

## License

Apache-2.0. See `LICENSE`.
