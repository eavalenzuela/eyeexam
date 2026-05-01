# eyeexam docs

Topic-by-topic operator documentation. The top-level
[`README.md`](../README.md) covers install, quick start, and CLI surface;
this directory holds the deeper material.

| topic                              | start here                                |
|------------------------------------|-------------------------------------------|
| Deploying eyeexam over SSH         | [`deploy-ssh.md`](./deploy-ssh.md)        |
| Using Atomic Red Team tests        | [`atomic-redteam.md`](./atomic-redteam.md) |
| Configuring SIEM/EDR detectors     | [`detectors.md`](./detectors.md)          |
| Scheduling runs + drift alerts     | [`scheduler.md`](./scheduler.md)          |
| Slither integration (read-only detector) | [`slither-detector.md`](./slither-detector.md) |
| Actor identity (`--actor-app`)     | [`actor-app.md`](./actor-app.md)          |

Two cross-cutting reads worth the time:

- [`../PLAN.md`](../PLAN.md) — product spec: scope, non-negotiables,
  scoring rules, safety rails.
- [`../IMPLEMENTATION.md`](../IMPLEMENTATION.md) — engineering plan:
  data model, package contracts, per-milestone build records and
  documented plan deviations.
