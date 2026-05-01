# Audit log

The audit log records every authorization decision, run lifecycle
event, host skip, refused test, and detector adjudication eyeexam
makes. It is the answer to "who ran what, on which hosts, when, with
whose authority, and what did the SIEM say about it" — the single
investigation surface when something goes sideways.

This doc covers the model, how to verify integrity, how to query, and
the operational practices that keep the chain trustworthy. It also
takes an explicit position on pruning (we don't ship it; see below).

## Model: two stores, file authoritative

The audit log lives in two places:

| store               | path                                                         | purpose                                  |
|---------------------|--------------------------------------------------------------|------------------------------------------|
| **JSONL file**      | `${EYEEXAM_DATA}/audit.log` (default `~/.local/share/eyeexam/audit.log`) | authoritative, signed, append-only       |
| **SQLite mirror**   | `audit_log` table inside `${EYEEXAM_DATA}/eyeexam.db`        | queryable mirror for `audit show` + UI   |

The file is the source of truth. Every record is signed with the
deployment's ed25519 key (`${EYEEXAM_HOME}/audit.key`), and each
record's `prev_hash` field chains it to the previous record. Tampering
with any record breaks the chain at that point onwards; the public
key (`audit.key.pub`) lets a third party verify without needing the
private key.

The SQLite mirror is convenience — eyeexam queries it for `audit show`
and the per-run UI panel. It can be wiped and rebuilt from the file
at any time; the file cannot.

### Append semantics

Every audit record goes through a single `audit.Logger.Append` call
under a mutex:

1. Compute `Hash = sha256(prev_hash || canonical_json(record_minus_hash_and_sig))`.
2. Sign the hash with the ed25519 private key.
3. Write the JSON line to the file and `Sync()` (fsync). At this
   point the record is durable + signed.
4. INSERT the same record into `audit_log`. **Best-effort.** A DB
   failure here logs a warning but does not fail the Append — the
   row is backfilled on next `audit.Open`.

The fsync before the DB write is the load-bearing guarantee: a power
loss during step 3 leaves a partial-line in the file (caught by Verify
as "unparseable") or no line at all (chain unaffected). A power loss
during step 4 leaves the file complete and the DB one row behind, and
the next `audit.Open` reconciles automatically.

### Open-time reconciliation

Every time a Logger opens (every CLI invocation that writes audit
events: `run`, `schedule add`, `scheduler run`, `runs resume`):

1. Scan the file from the start. Recover `lastSeq` + `lastHash`.
2. For any seq present in the file but missing from `audit_log`,
   backfill the row.
3. Refuse to start if the DB has rows past the file's last seq —
   that means the file was truncated or the DB was tampered with,
   and is not safely recoverable without operator inspection.

Step 3 is why "just delete the audit.log file to reset" doesn't work
and shouldn't. If you need to start fresh, delete *both* the file
and the audit_log rows.

## Verifying integrity

```bash
eyeexam audit verify
```

Two-phase check:

1. **Chain walk.** Walks the file from genesis forward. Recomputes
   each `Hash`, checks `prev_hash` continuity, verifies the ed25519
   signature against `audit.key.pub`. Stops at the first failure
   and reports `FirstBadSeq` plus a reason (`unparseable line`,
   `non-monotonic seq`, `prev_hash mismatch`, `hash mismatch`,
   `bad signature`).
2. **Mirror cross-check.** Compares every `(seq, hash)` pair from
   `audit_log` against the file. Any divergence is reported as the
   first bad seq with reason `db hash diverges from file hash` or
   `file has N records but db has M`.

A clean run prints `audit verify OK (N records, file ↔ db mirror
match)`.

Run this:

- After any unplanned eyeexam shutdown.
- Before/after backups, restores, host migrations.
- As a periodic sanity check (cron / systemd timer).

### Interpreting failures

| Verify says…                         | What probably happened                                                          |
|--------------------------------------|---------------------------------------------------------------------------------|
| `unparseable line` at seq N          | Crash mid-write left a partial JSONL line. Truncate the file at seq N-1.        |
| `prev_hash mismatch` at seq N        | Record N-1 was edited or removed. Restore from backup.                          |
| `hash mismatch` at seq N             | Record N's body was edited. Restore from backup.                                |
| `bad signature` at seq N             | The ed25519 key changed, or the record was forged. Compare `audit.key.pub`.     |
| `db hash diverges from file hash`    | Mirror tampering OR file truncation. File wins; rebuild DB from file.           |
| `db has seq N but file ends at M < N`| File was truncated, OR DB has stale rows from a prior deployment. Investigate.  |

If you genuinely just want to rebuild the mirror from a known-good
file: stop eyeexam, `DELETE FROM audit_log`, restart any eyeexam
command — Open will backfill.

## Querying with `audit show`

```bash
eyeexam audit show --run r-01HXXXXXXX
eyeexam audit show --since 24h
eyeexam audit show --event destructive_run_authorized --since 30d
eyeexam audit show --actor alice@example.com --json | jq .
```

Filters: `--run`, `--engagement`, `--event`, `--actor` (substring),
`--since` (lookback duration), `--limit` (default 200), `--json`.
Reads from the SQLite mirror; if you suspect tampering use `verify`
first and trust the file.

Common events to know about:

| event                          | when emitted                                       |
|--------------------------------|----------------------------------------------------|
| `run_planned`                  | `eyeexam plan` / start of `run`                    |
| `destructive_run_authorized`   | before first test, when plan exceeds `low`         |
| `test_executed`                | per-execution, with exit code + runner_extra       |
| `test_refused`                 | hard-refuse list match                             |
| `test_skipped`                 | platform / destructiveness cap / glob              |
| `host_skipped`                 | host-level failure mid-run (dial, auth, sudo)      |
| `cleanup_failed`               | verify_cleanup didn't return zero                  |
| `run_finished`                 | terminal — phase=reported                          |
| `drift_alerted`                | scheduler regression delivered to alert sinks      |

The full set lives in `internal/audit` call sites; grep for
`Event:` to enumerate.

## Per-run UI panel

`/runs/<id>` shows an "Audit events" panel listing every record for
that run, ordered by seq, with the actor formatted the same way the
CLI shows it (`alice@example.com/svc(uid=1000)` when AppUser is set).
Hidden when the run has no records (legacy runs from before the
mirror landed).

This is the same data `eyeexam audit show --run <id>` produces, just
in a viewer.

## Pruning is intentionally not a feature

eyeexam does not ship `audit prune`, `audit rotate`, or any other
"delete old records" command. **By design.** This is a security
tool; selective deletability of the audit log is a footgun an
attacker can use against you.

The threat model: someone roots the eyeexam host (or compromises an
operator's account). With pruning available, they:

1. Authorize and run a destructive test against your infrastructure.
2. Run `eyeexam audit prune --before <today>` to erase the
   `destructive_run_authorized` record + the run history.
3. Optionally prune the prune itself.

The chain is now intact past the cut and `audit verify` reports OK.
You have no way to know it happened. With no prune command in the
binary, the attack costs more — they have to either (a) leave the
chain visibly broken (which `audit verify` catches and any
periodic check exposes), or (b) replace the entire signed log,
which requires the private signing key.

The cost of not pruning is unbounded growth. The actual numbers:

- Each record is ~500 bytes JSONL, ~600 bytes in SQLite.
- A scheduler firing hourly produces ~9k records/year per schedule.
- Three schedules at hourly cadence for five years: ~135k records,
  ~80 MB on disk.

SQLite handles millions of rows without trouble; JSONL is cheap.
Most deployments never hit a real ceiling, and the few that do are
either large managed-service deployments (where the cost of
forensic completeness is exactly what's wanted) or have specific
retention-compliance requirements (which is a separate problem —
see below).

### If you genuinely need rotation

Three reasons might surface a real need:

1. **Disk pressure.** SQLite `eyeexam.db` is on a tiny volume.
   Solution: move the data dir (`EYEEXAM_DATA`) to bigger storage,
   not prune.
2. **Retention compliance.** Policy mandates "destroy audit data
   older than 7 years." Solution: an out-of-band process moves the
   prefix of `audit.log` to cold storage, then truncates. This
   leaves the live file unverifiable from genesis but verifiable
   from the new genesis-after-truncation; eyeexam's chain restarts
   from the next Append. Not built in; if you need this, file an
   issue with concrete requirements.
3. **Forensic archival without compliance.** You want online query
   to be fast but don't want to lose history. Solution: snapshot
   `audit.log` and `eyeexam.db` to cold storage periodically, keep
   the live versions intact. eyeexam's growth doesn't actually hurt
   query performance until you're at 7+ figures of records.

The common thread: rotation/archival is an *operations* problem with
*operations* tooling, not a feature of the BAS binary. Treating it
that way keeps the tool's defensive posture intact.

## Operational practices

### Safe

- **Back up the file + DB together.** `audit.log` and `eyeexam.db`
  must be backed up as a pair so file ↔ DB cross-check works on
  restore. Atomic snapshot of the data dir is fine; a `rsync` of
  both files in flight is not (the DB may be in WAL mode and the
  file may be mid-fsync).
- **Verify after restore.** Run `eyeexam audit verify` immediately
  after restoring from backup.
- **Keep `audit.key.pub` separate from the host.** If the signing
  key is stolen, having `audit.key.pub` checked into a separate
  repository or stored on a different host means an attacker
  forging records still has to publish a *new* public key, which
  is detectable.
- **Periodic verify in CI / cron.** A nightly `eyeexam audit verify`
  that pages on failure catches tampering early. The verify is
  read-only and safe to run while eyeexam is also running.
- **`/healthz`-style monitoring.** If you graph BAS metrics, also
  graph `audit_log` row count over time. A drop is a red flag.

### Unsafe — never do this

- **Never edit `audit.log` in place.** Even with care, you'll break
  the chain. If you need to "fix" something, append a new record
  documenting the correction.
- **Never delete rows from `audit_log` directly without also
  truncating the file at the same seq.** The next Open will refuse
  to start (DB ahead of file is the symptom, but the diagnosis is
  "file behind DB").
- **Never roll the signing key without keeping the old public key
  available.** Old records remain signed by the old key; if you
  lose the old `audit.key.pub`, those records become unverifiable
  forever.
- **Never share `audit.key`.** Treat it like an SSH private key.
  Mode `0600`, never in CI secrets, never committed.

## Internals (for the curious)

- Hash construction: `sha256(prev_hash_bytes || canonical_json(rec_minus_hash_sig))`.
  Genesis `prev_hash` is 32 zero bytes hex-encoded.
- Canonical form for hashing strips the `hash` and `sig` fields and
  serializes in a fixed field order (see `internal/audit/audit.go`
  `canonicalForHash`).
- `seq` is 1-based and contiguous; `audit_log.seq` is `INTEGER PRIMARY KEY
  AUTOINCREMENT` and matches the file line number 1:1.
- The Logger is mutex-protected and safe for concurrent Append
  from multiple goroutines within one process. It is **not** safe
  across processes: the file is opened `O_RDWR|O_CREATE` (not
  `O_APPEND`) and two processes writing to the same file can
  interleave bytes. Operationally: don't run two eyeexam writers
  against the same data dir simultaneously. Read-only commands
  (`audit verify`, `audit show`, `runs show`, `serve`) are safe to
  run alongside writers.
