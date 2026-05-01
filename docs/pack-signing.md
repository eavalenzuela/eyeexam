# Pack signing

eyeexam refuses to load disk-resident packs unless they ship a valid
ed25519 signature over a deterministic manifest of every file in the
pack. This is the "authorized use only" non-negotiable from `PLAN.md`
applied to the test catalog: an operator who clones a pack repo
controls only what their trusted signing keys say is acceptable.

The binary-embedded `builtin` pack does not pass through this code
path — its trust boundary is the eyeexam binary itself, not a disk
file.

## Wire format

A signed pack ships two files at the pack root:

- `MANIFEST` — a deterministic text record of every YAML file in the
  pack and its sha256.
- `MANIFEST.sig` — a raw ed25519 signature over the bytes of
  `MANIFEST`.

The manifest is plain text so operators can `cat MANIFEST` to see
what was signed. Example:

```
version: 1
pack: eyeexam-attackpacks
created: 2026-05-01T22:30:00Z
signer: eyeexam-attackpacks-2026-key1
files:
  eye-001-tmp-touch.yaml  sha256:abc123…
  eye-002-bash-history-clear.yaml  sha256:def456…
  expectations/eye-001-tmp-touch.yaml  sha256:789…
```

Field rules (enforced by the parser):

- `version: 1` — only version 1 is currently understood.
- `pack: <name>` — required, must match the pack name in eyeexam config.
- `created: <RFC3339Nano UTC>` — required.
- `signer: <label>` — optional human-readable hint; the actual trust
  decision is by ed25519 key, not by this string.
- `files:` — every line under it is `  <relpath>  sha256:<hex>`,
  sorted ascending by path. Any entry that doesn't match this shape,
  or any pair of entries out of order, fails parsing.
- `MANIFEST` and `MANIFEST.sig` themselves are not in the file list.

## Verification: what eyeexam checks

`internal/pack/signature.VerifyPack` runs three steps in order:

1. `ed25519.Verify(pub, MANIFEST_bytes, MANIFEST.sig_bytes)` succeeds
   for **at least one** key in the trusted-keys set. If no trusted
   key signed the manifest, returns `ErrNoTrustedKey` and the pack is
   refused.
2. Every file declared in the manifest exists in the pack root and
   its sha256 matches.
3. No `*.yaml` file exists in the pack that isn't declared in the
   manifest. (This catches a smuggled extra test added after signing.)

Verification runs **at every load** — every `eyeexam plan`,
`eyeexam run`, `eyeexam runs resume`, `eyeexam scheduler run`. There
is no "verify once at `pack add`, trust forever" mode; an attacker
who tampers with a pack file between add and run is caught on the
next run.

## Configuring trusted keys

```yaml
# config.yaml
pack_keys:
  - ~/.config/eyeexam/keys/eyeexam-attackpacks-2026-key1.pub
  - ~/.config/eyeexam/keys/internal-bas-team.pub

packs:
  - name: eyeexam-attackpacks
    path: ~/.local/share/eyeexam/packs/eyeexam-attackpacks
    source: native
```

`pack_keys` is a list of paths to PEM-encoded ed25519 public keys
(any PEM block type — eyeexam reads `Block.Bytes` directly). All keys
listed are accepted; the manifest only needs to verify against one
of them.

If `pack_keys` is empty and any pack is configured without
`unsigned: true`, eyeexam refuses to start with a clear error.

## Opting out per pack

Some packs are not signable upstream — Atomic Red Team is the
canonical example, and any internally-managed pack during initial
development. Opt out per-pack:

```yaml
packs:
  - name: atomic
    path: ~/.local/share/eyeexam/packs/atomic-red-team
    source: atomic
    unsigned: true
```

Every load of an unsigned pack writes a `pack_loaded_unsigned` audit
record:

```json
{"event":"pack_loaded_unsigned","payload":{"pack":"atomic"}}
```

Operators can grep for these in the audit log:

```bash
eyeexam audit show --event pack_loaded_unsigned
```

The `unsigned: true` opt-in is per-pack, not per-deployment — there
is no global `--unsigned-ok` switch. If you flip a pack from signed
to unsigned, the change is visible in your config diff and in the
audit log on next load.

## Signing a pack

eyeexam does not ship a signing tool by design — pack authors use
their own ed25519 tools and their own key custody process. The wire
format is simple enough to sign with any of:

### Go

```go
import (
    "crypto/ed25519"
    "os"
    "path/filepath"

    "github.com/eavalenzuela/eyeexam/internal/pack/signature"
)

func sign(packDir, packName string, priv ed25519.PrivateKey) error {
    m, err := signature.BuildManifest(os.DirFS(packDir), packName)
    if err != nil {
        return err
    }
    manifest := m.Canonical()
    sig := ed25519.Sign(priv, manifest)
    if err := os.WriteFile(filepath.Join(packDir, "MANIFEST"), manifest, 0o644); err != nil {
        return err
    }
    return os.WriteFile(filepath.Join(packDir, "MANIFEST.sig"), sig, 0o644)
}
```

### `openssl`

Construct the manifest yourself (see Wire format above), then:

```bash
openssl pkeyutl -sign -inkey ed25519-priv.pem -in MANIFEST -out MANIFEST.sig -rawin
```

Note `-rawin` — eyeexam signs the manifest bytes directly, not a
hash of them; ed25519 hashes internally as part of the algorithm.

### `minisign` / `signify`

These tools wrap raw ed25519 in their own header formats which
eyeexam does not parse. Stick to raw ed25519 sigs; if you need
detached metadata, put it in the `signer:` field of the manifest.

## Distributing public keys

Host keys somewhere distinct from the pack itself — a separate git
repo, an HTTPS-served directory, a key-management system. eyeexam
verifies against keys it has on disk; rotating a key means updating
`pack_keys` in operator config and re-signing existing packs with
the new key.

If a key is compromised:

1. Rotate the key (generate new pair, distribute new pubkey).
2. Re-sign all packs with the new key.
3. Remove the old pubkey from `pack_keys`.
4. Run `eyeexam audit verify` and grep `pack_loaded_unsigned` to
   audit recent activity.

eyeexam does not maintain a revocation list — removing a key from
`pack_keys` is the revocation mechanism.

## What about the embedded builtin pack?

Skipped by construction. `Registry.AddEmbedded` reads from `embed.FS`
compiled into the binary, not from disk; there is no `MANIFEST` to
verify and no path that calls `signature.VerifyPack` on embedded
content. The eyeexam binary is the trust boundary for builtin tests.

If you need to verify the binary itself, that's the standard release
artifact path: signed releases, reproducible builds, checksum
verification at install time. Outside scope of pack signing.

## Adding new packs

`eyeexam pack add <name> <path>` records a pack in config without
loading it. Verification happens on the next `plan` / `run` /
`scheduler run`. To check before committing to a config change:

```bash
eyeexam pack add my-new-pack /tmp/staging-clone --unsigned-ok=false
eyeexam plan --pack my-new-pack --hosts dev-host  # fails fast on bad sig
```

(The `--unsigned-ok=false` flag is the default; pass `--unsigned`
to add an unsigned pack with the audited opt-in.)

## What can break

| symptom                                                                | likely cause                                              |
|------------------------------------------------------------------------|-----------------------------------------------------------|
| `pack "x": signature: MANIFEST.sig did not verify against any trusted key` | Wrong key in pack_keys, or pack signed with a key you don't trust |
| `pack "x": declared file "y" sha256 mismatch`                          | Pack was modified after signing                           |
| `pack "x": undeclared file "y" (smuggled or signer missed it)`         | YAML added to the pack after signing                      |
| `pack "x": declared file "y" missing`                                  | YAML deleted from the pack after signing                  |
| `pack "x" requires a signature but cfg.pack_keys is empty`             | Add trusted keys to config, or set `unsigned: true`       |
| `manifest: out of order`, `manifest: unsupported version`              | Hand-crafted MANIFEST didn't follow the format            |

## Limits (v1)

- No multi-sig or threshold signing. One trusted key per pack is
  enough; if you want defense in depth, sign with multiple keys
  in separate `MANIFEST.sig.<keyid>` files and rotate manually.
  (Not currently supported by eyeexam — file an issue if you need it.)
- No timestamp anchoring. The `created:` field is informational; an
  attacker with a stolen key can sign packs with any timestamp.
- No revocation lists. Key removal is the revocation mechanism.
- No support for signing tools other than raw ed25519 (no minisign,
  no PGP, no sigstore). Future-extensible — the format is text and
  the verifier is one file.
