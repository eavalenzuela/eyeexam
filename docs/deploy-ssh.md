# Deploying eyeexam via SSH

eyeexam's SSH runner connects to each target host as a dedicated `eyeexam`
service user, dispatches `bash -c <command>` per step, and captures stdout /
stderr / exit code back into the run record. This document walks through
provisioning that user safely.

## Principles

- **Key-only auth.** Passwords are not supported. The runner aborts if a
  password prompt is encountered.
- **Hostkey pinning.** The runner verifies host keys against
  `~/.ssh/known_hosts` (or `runner.ssh.known_hosts` from config). Unknown
  hosts cause the dial to fail; populate `known_hosts` in advance.
- **Dedicated service user.** Use a non-shared `eyeexam` user, not your
  personal account. Tests that need elevated privileges go through a
  scoped sudoers stanza, never NOPASSWD: ALL.

## Provisioning script (one host)

Run as root on each target:

```bash
useradd --create-home --shell /bin/bash --comment "eyeexam BAS" eyeexam

install -d -m 0700 -o eyeexam -g eyeexam /home/eyeexam/.ssh
install -m 0600 -o eyeexam -g eyeexam /dev/stdin /home/eyeexam/.ssh/authorized_keys <<'PUBKEY'
ssh-ed25519 AAAA…  eyeexam-controller
PUBKEY
```

Replace the public key line with the contents of `<eyeexam-host>:~/.ssh/eyeexam_ed25519.pub`.

## Sudoers stanza

The runner needs sudo only for tests that explicitly require it. The default
posture is "no sudo" — tests must opt in by running their own
`sudo <specific-cmd>` lines. Add an exact-match sudoers fragment under
`/etc/sudoers.d/eyeexam`:

```
# eyeexam: scope sudo to the exact commands tests need.
# DO NOT use NOPASSWD: ALL.

eyeexam ALL=(root) NOPASSWD: /usr/bin/auditctl -l
eyeexam ALL=(root) NOPASSWD: /usr/sbin/iptables -L
eyeexam ALL=(root) NOPASSWD: /usr/bin/journalctl -u sshd --since=*

Defaults:eyeexam !lecture
Defaults:eyeexam env_keep += "EYEEXAM_*"
```

Validate with `visudo -cf /etc/sudoers.d/eyeexam` before saving.

If a test needs a command not in the stanza, the test fails — that is the
correct outcome. Update the stanza after reviewing what the test actually
runs.

## Hostkey pinning

On the eyeexam controller host:

```bash
ssh-keyscan -t ed25519 web-01.lab build-01.lab >> ~/.ssh/known_hosts
```

Or, if you manage host keys via configuration management, install the
target's `/etc/ssh/ssh_host_ed25519_key.pub` into the controller's
`known_hosts` directly to avoid trust-on-first-use.

## Verifying

```bash
eyeexam inventory check
```

prints one row per host with `ok`/`fail`/`skipped` and the failure reason
when applicable. Re-run after fixing each issue until every row is `ok`.

## Cleanup posture

eyeexam tests are required to define `verify_cleanup`. The runner reports
cleanup state independently from detection state, so you can tell at a
glance from `eyeexam runs show <id>` whether residual state was left on a
host. Don't suppress cleanup failures — they're how we keep target hosts
in a known state across BAS runs.
