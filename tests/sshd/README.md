# tests/sshd

eyeexam's M2 plan called for a docker-compose-based OpenSSH fixture. We
landed on something simpler that runs anywhere `go test` runs: an
**in-process SSH server**, implemented with `golang.org/x/crypto/ssh` in
test-server mode.

Entry points:

- `internal/runner/ssh_test.go` — the fakeSSHServer + key-pair helpers used
  by the SSH-runner unit tests.
- `tests/e2e/ssh_smoke_test.go` — end-to-end run against the same fake
  server, asserting per-host concurrency cap and global rate limit.

The server accepts public-key auth from a configured signer and handles
`exec` requests by running the command through `bash -c` on the test
machine. This is enough fidelity for the runner's contract; we intentionally
do not test sshd-specific behavior (sftp, port-forward, banners) since the
runner doesn't use them.

If you ever need a real sshd (e.g. to test sudoers / pam interactions), drop
a docker-compose here that boots an `eyeexam` user with the sudoers stanza
from `docs/deploy-ssh.md`. The runner contract doesn't change.
