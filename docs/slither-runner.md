# Slither runner — BAS dispatch contract (M7 stub)

eyeexam's M7 slither runner targets a JSON-over-HTTP shim. As of this
writing the slither project (`../slither`) does not yet expose a stable
BAS-dispatch RPC. When it does — see IMPLEMENTATION.md §7 M7 pre-work
for the proto definitions — swap this implementation behind the same
`Runner` interface; eyeexam's runlife / audit / score layers don't
change.

## Endpoints

### `GET /api/v1/bas/health`

200 OK on success. eyeexam's `inventory check` calls this for every host
with `transport: slither`.

### `POST /api/v1/bas/execute`

Dispatch one shell command to one slither agent, synchronously.

Request body:

```json
{
  "control_id": "x-000037e... (eyeexam execution_id)",
  "operator_id": "ealey(uid=1000)",
  "engagement_id": "HOMELAB-2026",
  "agent_id": "<slither-agent-uuid>",
  "shell": "bash",
  "command": "echo hi",
  "timeout_seconds": 300
}
```

- `control_id` is supplied by eyeexam and equals the `executions.id`
  row id. Slither must echo it (or assign its own and return it for the
  cross-reference).
- `operator_id` is `audit.Actor.String()` from eyeexam's audit-key OS
  user identity.
- `engagement_id` gates dispatch on slither's side: the server must
  reject any request whose engagement is not in the operator's allowlist.
- `agent_id` selects the target — comes from `inventory.Host.AgentID`.
- `timeout_seconds` is advisory; slither should kill the agent-side
  process and return a non-zero exit if it elapses.

Response body:

```json
{
  "control_id": "ck-43a91...",
  "exit_code": 0,
  "stdout_b64": "...",
  "stderr_b64": "...",
  "error": ""
}
```

- `control_id` may be slither-assigned; eyeexam stores both the original
  (eyeexam execution id) and the returned control id in the audit log
  under `slither_control_id` so the two sides cross-reference.
- `stdout_b64` / `stderr_b64` are base64 because eyeexam may run
  commands that produce arbitrary bytes.
- `error` is set when slither itself rejected dispatch (auth, agent
  offline, BAS not enabled). On non-empty `error`, eyeexam treats the
  step as a runner error (exit_code = -1).

## Auth

`Authorization: Bearer <api-key>` from `EYEEXAM_SLITHER_KEY` env var.

## Agent-side gating

The slither agent must default `accept_bas_execute: false`. Operators
explicitly enable it on hosts under test. Agents that haven't opted in
return 4xx-level rejections so the operator sees them clearly in the
inventory check or run output.

## Audit cross-reference

eyeexam's audit log records every test_executed event with a
`runner_extra` field. For slither-runner steps, this contains:

```json
{
  "slither_control_id": "ck-43a91...",
  "slither_agent_id":   "uuid-..."
}
```

Pair this with slither's own audit record (which logs the same
`control_id`) to walk a single dispatch from eyeexam → slither server →
slither agent → response → eyeexam scoring.

## Migration to gRPC

When slither ships the real RPC (sketch in IMPLEMENTATION.md §7):

```protobuf
message BasExecuteRequest {
  string control_id = 1;
  string operator_id = 2;
  string engagement_id = 3;
  string shell = 4;
  string command = 5;
  uint32 timeout_seconds = 6;
}
message BasExecuteResponse {
  string control_id = 1;
  int32 exit_code = 2;
  bytes stdout = 3;
  bytes stderr = 4;
  string error = 5;
}
```

eyeexam swaps to the gRPC client; the SlitherRunner's external surface
(`Run`, `HealthCheck`, `Result.Extra` keys) stays the same.
