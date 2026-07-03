# eyeexam — Planned Improvements & Feature Roadmap

Scoping document only. Nothing here is an implementation; each item is a
tracked line of engineering work with a one-line rationale. Framed as an
engineering roadmap for a defensive/dual-use security tool: correctness,
robustness, test coverage, performance, configuration/UX, reporting,
packaging/CI, documentation, and — first-class for this tool —
authorization/safety guardrails, audit integrity, and responsible-use
controls. Capability areas are referenced at a high level only; no
offensive payloads, evasion techniques, or attack instructions belong in
this repo.

Status baseline: M1–M8 shipped (M7 retracted); local + SSH runners;
loki/wazuh/elastic/splunk detectors (slither read-API stub pending);
ed25519 signed audit chain; cron scheduler with drift alerts; standalone
HTML/JSON reports.

## Improvements

1. **Deepen config validation.** `config.Validate()` checks only a handful
   of required fields; restore the embedded JSON-schema validation that
   IMPLEMENTATION.md §5 promised and add typed per-detector option
   validation, limits-range checks, and duration-string parsing — so
   misconfiguration fails loudly at startup instead of surfacing as runtime
   errors or spurious `uncertain` scores.

2. **Make detectors resilient to transient SIEM/EDR faults.** Add bounded
   retry with backoff, gate startup on `HealthCheck` for every configured
   detector, and propagate the run-level context deadline into the fixed
   per-request HTTP timeouts — a single network blip should not collapse a
   real detection into `uncertain` and erode trust in the coverage matrix.

3. **Harden the SSH runner connection lifecycle.** The per-host client is
   dialed once and reused for the runner's lifetime with no keepalive or
   reconnect; add keepalive plus reconnect-on-broken-pipe so an idle
   disconnect mid-run does not cascade-fail every remaining test on that
   host during long scheduled sweeps.

4. **Add a secrets-handling guardrail with centralized redaction.** Require
   detector credentials to come from env/file references (refuse inline
   API keys/tokens in config) and route all output through one redactor so
   secrets never reach slog, the audit payload, or report artifacts — a
   security tool must not leak the SIEM/EDR credentials it holds.

5. **Unify runner/scoring semantics across local and SSH.** The
   PowerShell-missing path differs (host-level skip vs. bare exit 127
   depending on runner), producing inconsistent scores for the same test;
   converge on one canonical "host-skipped with actionable reason" behavior
   and document it, so identical tests score identically regardless of
   transport.

6. **Raise execution↔detection correlation fidelity.** Correlation today is
   host + time-window only, so an unrelated alert landing inside the wait
   window can be miscounted as `caught`; correlate on an injected benign
   run marker (a defensive detection-engineering technique) to cut
   false-positive `caught` scoring and keep the coverage matrix honest.

7. **Add cross-process run safety via a datastore lease.** §4.9 notes the
   rate limiter and per-host semaphore are in-process only; a manual `run`
   and a scheduler fire can overlap and jointly exceed the intended
   blast-radius and rate caps — add a SQLite-backed global lease so
   destructive plans cannot execute concurrently across processes.

8. **Instrument test coverage and fuzz the untrusted-input surface.** Add a
   coverage gate to CI and fuzz targets for the native and Atomic Red Team
   YAML loaders, which parse operator-supplied third-party pack content and
   are currently exercised only by example-based tests — the loaders are
   the tool's largest untrusted-parsing surface.

9. **Harden the supply chain and cross-target builds in CI.** CI runs only
   lint/test/build on one OS; add `govulncheck`, dependency review, and an
   SBOM step, actually build and test the darwin/arm64 + linux/arm64 targets
   `make dist` claims to ship, and move toward reproducible, signed release
   artifacts — a distributed offensive-capable binary needs verified build
   integrity of its own.

10. **Give the audit log a rotation and off-box durability story.** Loss of
    `audit.key` currently invalidates all historical verification and the
    signed chain lives only on the box that could be tampered; add
    documented signing-key rotation with chain re-anchoring, optional
    append-only off-box shipping (syslog/WORM), and a companion threat-model
    + responsible-use policy doc that states the tamper-evidence guarantees
    explicitly.

## New Features

1. **Approved-plan binding.** Hash the resolved plan (hosts × tests ×
   max-dest) and require an executed run to match a reviewer-approved plan
   hash, with `high` destructiveness optionally gated behind a
   second-approver token carrying a TTL — ties authorization to an exact,
   reviewed blast radius instead of a bare `--authorized` flag.

2. **Standardized findings export (SARIF + versioned JSON).** Emit coverage
   gaps and detection drift as SARIF and a schema-versioned JSON so results
   flow into CI gates, ticketing, and security dashboards — makes eyeexam a
   first-class pipeline input rather than a terminal HTML artifact.

3. **Run lifecycle controls (`runs cancel` / graceful abort).** Complement
   the existing phase-resume with a clean stop that still runs
   cleanup-verify for in-flight tests and marks the run terminal — a stuck
   or mistaken run currently has no safe abort that preserves the
   cleanup-is-verified guarantee.

4. **Coverage-gap ("what's untested") reporting.** Map configured packs
   against the ATT&CK matrix to surface techniques with no test at all
   (the grey cells) and export a prioritized gap list — the matrix scores
   existing tests but does not help operators see where they have no
   coverage to begin with.

5. **Detector normalization layer + broader read-only backend coverage.**
   Introduce one documented hit-normalization schema and adapter contract,
   then broaden read-only detector coverage behind it (including finishing
   the slither read-API detector once its contract stabilizes) — lowers the
   per-backend query-quirk cost and improves cross-backend scoring parity
   across a heterogeneous SOC.
