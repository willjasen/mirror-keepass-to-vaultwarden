# Strongbox/KeePass to Vaultwarden migration runbook

This document records the migration of the `nerdhirn.kdbx` KeePass database into
the Vaultwarden organization named `nerdhirn`.

## Result

The completed migration contains:

- 73 imported vault items
- 8 original KeePass binary attachments
- 56 preserved KeePass history archives
- 64 total Vaultwarden attachments
- 15 OTP entries carried into the imported items

The target organization ID was:

```text
ec9e6800-30a1-416e-8611-b2c5389a52dc
```

## Repository tooling

- `scripts/mirror_keepass_to_vaultwarden.py` — exporter, dry-run validator, encrypted import wrapper, and attachment/history synchronizer
- `docs/strongbox-migration-plan.md` — original migration design
- `requirements.txt` — Python dependencies
- `sample.env` — configuration template
- `.gitignore` — excludes credentials, exports, virtual environments, and KDBX files

## Configuration

Create `.env` in the repository root. Do not commit it.

```env
KEEPASS_PATH=./nerdhirn.kdbx
KEEPASS_PASSWORD='the KeePass master password'
KEEPASS_KEY_FILE=
VAULTWARDEN_URL=https://vault.risk-mermaid.ts.net
VAULTWARDEN_ORGANIZATION_NAME=nerdhirn
VAULTWARDEN_ORGANIZATION_ID=ec9e6800-30a1-416e-8611-b2c5389a52dc
OUTPUT_DIR=exports
BW_CLI=/Users/willjasen/.nvm/versions/node/v20.19.1/bin/bw
```

The Vaultwarden OAuth token is useful for API checks, but the actual encrypted
import uses the Bitwarden CLI account session. Keep the Vaultwarden account
master password out of shell history and do not source `.env` when passwords
contain shell-special characters.

## Initial validation

Set up the Python environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Run a dry-run:

```bash
.venv/bin/python scripts/mirror_keepass_to_vaultwarden.py \
  --env-file .env \
  --db ./nerdhirn.kdbx \
  --dry-run
```

The dry-run reads the KDBX and reports item, history, OTP, attachment, and
group counts. It does not write to Vaultwarden.

## Encrypted item import

The direct Vaultwarden cipher API was intentionally not used. Vaultwarden
expects Bitwarden-encrypted cipher payloads, so posting plaintext KeePass
fields would be unsafe and incompatible.

Use the official Bitwarden CLI instead. A compatible CLI was installed at:

```text
/Users/willjasen/.nvm/versions/node/v20.19.1/bin/bw
```

Configure and authenticate it:

```bash
export PATH="/Users/willjasen/.nvm/versions/node/v20.19.1/bin:$PATH"
bw config server "https://vault.risk-mermaid.ts.net"
bw login --apikey
```

For a clean, isolated CLI state:

```bash
export BITWARDENCLI_APPDATA_DIR=/tmp/nerdhirn-bw-cli
export BW_SESSION="$(bw unlock --raw)"
bw sync
```

Confirm the organization is visible:

```bash
bw list organizations --raw
```

Run the encrypted import:

```bash
BW_CLI="/Users/willjasen/.nvm/versions/node/v20.19.1/bin/bw" \
.venv/bin/python scripts/mirror_keepass_to_vaultwarden.py \
  --env-file .env \
  --db ./nerdhirn.kdbx \
  --bw-cli
```

The script performs this transformation:

```text
KDBX -> KeePass XML -> bw import keepass2xml -> Vaultwarden organization
```

The temporary XML file is deleted after the import command finishes.

## Attachments and history preservation

The standard KeePass XML importer imported current item fields but did not
preserve KeePass revisions or binary attachments. The second pass handles both:

```bash
BW_CLI="/Users/willjasen/.nvm/versions/node/v20.19.1/bin/bw" \
BITWARDENCLI_APPDATA_DIR=/tmp/nerdhirn-bw-cli \
.venv/bin/python scripts/mirror_keepass_to_vaultwarden.py \
  --env-file .env \
  --db ./nerdhirn.kdbx \
  --bw-attachments
```

For each source entry, the script matches the imported item by title,
username, and URL, then:

- uploads every original KeePass attachment using `bw create attachment`
- serializes all KeePass history revisions into a JSON archive
- uploads that archive as an attachment named `keepass-history-<uuid>.json`
- skips attachments already present, making the pass idempotent

Vaultwarden does not render these KeePass revisions in its native History panel.
The history archives are the preservation layer. A separate Secure Note with
the original `.kdbx` file can also be kept as the authoritative source archive.

## Verification

Use the Bitwarden CLI to inspect the organization:

```bash
bw sync
bw list items \
  --organizationid "$VAULTWARDEN_ORGANIZATION_ID" \
  --raw
```

The final verification found:

- 73 organization items
- 64 attachments
- 56 `keepass-history-*.json` archives
- 8 original source binaries

## Security and operational notes

- Keep `.env`, `.kdbx`, XML exports, JSON exports, and CLI session keys private.
- Do not use `source .env` when a secret contains shell syntax unless every value
  is safely quoted.
- Keep the original KDBX backup until the Vaultwarden data has been reviewed.
- The history JSON files contain historical passwords and must be treated as
  highly sensitive.
- The script refuses the old plaintext direct-API import path.
- For additional KeePass databases, perform one organization import per
  database and use a distinct `VAULTWARDEN_ORGANIZATION_ID`.

  ## Personal-vault import

  To import a database into the account's personal vault, leave
  `VAULTWARDEN_ORGANIZATION_ID` unset. The same encrypted importer is used, but
  the CLI command omits `--organizationid`:

  ```bash
  .venv/bin/python scripts/mirror_keepass_to_vaultwarden.py \
    --env-file .env \
    --db ./willjasen.kdbx \
    --bw-cli
  ```

  The personal `willjasen.kdbx` import produced 1,598 items. Attachments and
  history archives can be synchronized afterward with `--bw-attachments`; that
  operation is idempotent and can be safely rerun if interrupted.
