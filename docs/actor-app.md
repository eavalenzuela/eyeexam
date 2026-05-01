# Actor identity: `--actor-app`

eyeexam records two identities on every audited action:

- **OS user** — always derived from `os/user.Current()` on the host
  invoking the binary. Always populated.
- **App user** — optional human identity declared by the operator via
  `--actor-app <name>`. Only populated when the flag is passed.

This split exists because eyeexam is frequently invoked by a service
account: a CI runner, a systemd unit, the scheduler under a non-login
user. The OS user in those contexts says nothing about which human
authorized the action. `--actor-app` carries that human identity into
the audit chain.

## When to use it

- **CI / scheduled pipelines.** The job runs as `gha-runner` or
  `eyeexam-bot`, but the change was approved by a person. Pass
  `--actor-app alice@example.com` so audit records attribute to the
  approver, not the runner.
- **Schedules under a system account.** `eyeexam scheduler run` is
  typically a systemd unit owned by `eyeexam-svc`. The schedule was
  created by a human via `eyeexam schedule add`; pass `--actor-app` at
  add time so every subsequent fire carries that identity.
- **Shared workstations.** Two analysts share a kiosk account; passing
  `--actor-app` distinguishes their actions in the audit log.

When eyeexam is invoked by a known human at a known terminal, the OS
user is enough — `--actor-app` is unnecessary noise.

## Where it appears

Set `--actor-app alice@example.com` and the value flows into:

| destination                | column / field           |
|----------------------------|--------------------------|
| `runs` table               | `runs.app_user`          |
| `schedules` table          | `schedules.app_user` (when set on `schedule add`) |
| `audit.log` records        | `actor.app_user` on every record emitted by that invocation |
| `Actor.String()` rendering | `alice@example.com/svc(uid=1001)` |

The audit-log hash chain covers the actor field, so tampering with
`app_user` after the fact breaks `eyeexam audit verify`.

## Allowed values

- 1–64 characters
- alphanumerics plus `.` `_` `-` `@` `+`
- no whitespace, no control characters, no non-ASCII
- in particular, **no `/`** — the renderer uses it as a separator

Invalid values are rejected at flag-parse time. The validator is
`audit.ValidateAppUser`.

## CLI usage

### One-off run

```bash
eyeexam run \
    --pack builtin \
    --hosts localhost \
    --authorized \
    --engagement HOMELAB-2026 \
    --max-dest low \
    --actor-app alice@example.com \
    --yes
```

### Scheduled run

`--actor-app` is recorded on the schedule row at `schedule add` time.
Every fire of that schedule then carries the same value — the scheduler
daemon's OS user is irrelevant.

```bash
eyeexam schedule add \
    --name nightly-linux \
    --cron "0 3 * * *" \
    --pack builtin \
    --tag linux \
    --max-dest low \
    --actor-app alice@example.com
```

To rotate the human identity on an existing schedule, remove and re-add:

```bash
eyeexam schedule remove nightly-linux
eyeexam schedule add --name nightly-linux ... --actor-app bob@example.com
```

There is no in-place edit; rotation is intentionally a delete-plus-add
so the audit log shows a clean handover.

## CI example (GitHub Actions)

```yaml
- name: Run eyeexam smoke
  env:
    ACTOR: ${{ github.event.pull_request.user.login || github.actor }}
  run: |
    eyeexam run \
      --pack builtin \
      --hosts ci-target \
      --authorized \
      --engagement CI-${{ github.run_id }} \
      --max-dest low \
      --actor-app "${ACTOR}@github" \
      --yes
```

The `@github` suffix is a convention; pick whatever your audit reviewers
will recognize. Keep it stable so audit queries can group by it.

## systemd example (scheduler)

The scheduler reads the `--actor-app` value off each schedule row, so
the unit file itself doesn't need to know:

```ini
[Service]
Type=simple
User=eyeexam-svc
ExecStart=/usr/local/bin/eyeexam scheduler run --interval 30s
```

Operators add schedules from their own shells with their own
`--actor-app`. The daemon picks each up and synthesises the right Actor
on every fire.

## Verifying the chain

```bash
eyeexam audit verify
```

Walks the entire audit log and checks chain hash + signature on every
record. If a record was edited to swap `app_user` after the fact, the
first divergent sequence number is reported.

## Future work

A web frontend with session-based login is out of scope for v1. When it
lands, sessions will write into the same `Actor.AppUser` field — the
schema and audit chain don't change. The CLI flag stays as the
non-interactive escape hatch (CI, scheduler, scripted harnesses).
