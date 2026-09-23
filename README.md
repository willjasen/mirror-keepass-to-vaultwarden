# mirror-keepass-to-vaultwarden

a small proof-of-concept project for testing a strongbox/keePass export -> vaultwarden mirror while preserving item history and attachments as much as the target api allows.

i was able to successfully import two keepass databases into vaultwarden, retaining attachments and history from keepass.

to retain history from keepass, the project cannot create historical entries directly in vaultwarden, so the history of each entry (if there is history) is attached as a "keepass-history.json" to their respective entries in vaultwarden.

---

# Copilot Generated

## What this repo contains

- a staged migration plan in `docs/strongbox-migration-plan.md`
- the completed workflow and verification details in `docs/migration-runbook.md`
- a script in `scripts/mirror_keepass_to_vaultwarden.py` that can:
  - inspect one or many `.kdbx` databases
  - export them to JSON for validation
  - summarize counts, attachments, history, and OTP entries
  - optionally attempt a dry-run mirror into a Vaultwarden org or personal vault

## Working assumptions

- multiple Keepass databases may be imported over time
- the `nerdhirn` database should be handled as its own dedicated organization in Vaultwarden
- live imports should be dry-run first until the mapping is validated

## Quick setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cp sample.env .env
```

Then fill in your `.env` values or pass CLI flags directly.

## Example dry-run for a single database

```bash
python scripts/mirror_keepass_to_vaultwarden.py \
  --db /path/to/nerdhirn.kdbx \
  --password "$KEEPASS_PASSWORD" \
  --org-name nerdhirn \
  --vault-url https://vault.risk-mermaid.ts.net \
  --api-key "$VAULTWARDEN_API_KEY" \
  --dry-run
```

## Example for multiple databases in a directory

```bash
python scripts/mirror_keepass_to_vaultwarden.py \
  --db-dir /path/to/keepass-databases \
  --dry-run
```

This does not write to Vaultwarden during `--dry-run`; it exports the JSON and prints the planned item mapping.

## Live encrypted import

Do not use the prototype's old direct API path for live writes. Use the official
Bitwarden CLI import format instead:

```bash
bw config server https://vault.risk-mermaid.ts.net
bw login --apikey
bw unlock --raw

.venv/bin/python scripts/mirror_keepass_to_vaultwarden.py \
  --env-file .env \
  --db ./nerdhirn.kdbx \
  --bw-cli
```

The script exports the KDBX through `keepassxc-cli` and immediately passes the
XML to `bw import keepass2xml --organizationid ...`. Vaultwarden receives the
Bitwarden-encrypted records; no plaintext cipher POST is used. The CLI session key is intentionally
not stored in the repository. For a noninteractive shell, export it explicitly:

```bash
export BITWARDENCLI_APPDATA_DIR=/tmp/nerdhirn-bw-cli
export BW_SESSION="$(bw unlock --raw)"
```

## Notes

- A real import will need a valid Vaultwarden API token and, if desired, a target org ID.
- For a production migration, we should keep a full source-history archive alongside the imported vault because KeePass revision history is richer than the Bitwarden/Vaultwarden import path typically preserves.
