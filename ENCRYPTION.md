# Encryption

This project uses age encryption to keep sensitive intermediate data off disk
in plaintext while converting between KeePass and Vaultwarden.

## What is encrypted

Sensitive temporary payloads written under `temp/` are stored as `.age`
artifacts. This includes:

- Vaultwarden JSON exports
- downloaded Vaultwarden attachments
- encrypted attachment filename manifests
- KeePass validation JSON
- KeePass XML used for Bitwarden CLI imports
- KeePass attachments staged for upload
- generated KeePass history archives

Temporary filenames are opaque where the original name may itself be sensitive.
Attachment names are retained inside encrypted metadata or passed to the target
through a sanitized handoff name.

## Per-run age identity

At the beginning of a run, the application executes `age-keygen -pq` to create
a new post-quantum age identity. It derives the corresponding recipient in
memory and uses that recipient for every temporary artifact in that run.

The private identity:

- is held only in process memory
- is provided to age through standard input when decryption is required
- is never written to `age-identity.txt` or another identity file
- is discarded when the process exits
- is intentionally not recoverable after the run

This design is appropriate because the encrypted artifacts are temporary. They
are not backups and are not intended to be decrypted after the run completes.

## External CLI handoffs

The Bitwarden CLI requires a path for KeePass XML imports and attachment
uploads. After an artifact's signatures are verified, the application decrypts
it in memory and streams it to the CLI through a named pipe.

Each pipe is created inside a random `0700` directory with `0600` permissions.
A named pipe has a filesystem name but stores no payload content on disk. The
pipe name is reduced to a safe basename so an attachment name cannot traverse
outside the staging directory. The pipe and its containing directory are
removed after the command finishes.

## Data not encrypted with age

`config.json` is persistent input and must remain readable on future runs, when
the prior per-run age identity no longer exists. It is therefore protected by
owner-only `0600` permissions, regular-file and symlink checks, git ignore
rules, and normal host access controls. Create it with:

```bash
install -m 600 sample.config.json config.json
```

Final `.kdbx` exports are encrypted by KeePass using the configured database
password and optional key file. Run logs contain operational metadata and
counts, not exported passwords or attachment contents.

## Transport security

Vaultwarden URLs must use HTTPS. Before configuring or contacting Vaultwarden,
the application performs a TLS connection using the operating system's trusted
certificate authorities. Plain HTTP, malformed URLs, expired certificates, and
untrusted certificates are rejected.

## Cleanup

Run-specific directories are removed when processing finishes. Cleanup reduces
residual encrypted artifacts, but confidentiality does not depend on cleanup:
temporary payload content is age-encrypted at rest and the per-run private
identity is not retained.

Encryption protects confidentiality and age also authenticates its ciphertext.
The additional signing layer is documented in [SIGNING.md](SIGNING.md).
