# Strongbox/Keepass to Vaultwarden migration plan

## Goal

Move the contents of a Strongbox/Keepass database into Vaultwarden at `https://vault.risk-mermaid.ts.net` while preserving all meaningful data, especially:

- item history (previous values / revisions)
- attachments
- folder / group structure
- custom fields and notes
- TOTP data and login metadata

This is not a simple one-time export; it is a fidelity-preserving migration and likely requires an intermediate export format and a controlled import flow.

## Constraints and assumptions

- Source database is a KeePass/KDBX file, likely accessed through Strongbox on iOS/macOS or exported from a local KeePass client.
- Vaultwarden is Bitwarden-compatible, but it does not automatically preserve KeePass item history or external attachments in the same way as a raw `.kdbx` file.
- We should assume the target system is a live environment and should migrate in a staged way rather than a blind full import.
- The migration should be reversible with a restore point, because history and attachments are easy to lose if imported incorrectly.

## Recommended migration approach

### Phase 1: Capture a verified source snapshot

1. Create a complete backup of the source KeePass database and any attached files.
2. Export the database in a form that can be processed without losing metadata.
3. Record the source database hash and the export timestamp.
4. Confirm whether the source contains:
   - standard attachments
   - custom icons
   - history entries
   - TOTP/secrets
   - nested groups / folders

Useful source extraction options:

- KeepassXC CLI (preferred when available):
  - `keepassxc-cli export <db.kdbx> --format xml --output export.xml`
  - `keepassxc-cli export <db.kdbx> --format csv --output export.csv`
- Python + `pykeepass` for structured access to items, attachments, and history without manual XML parsing.
- Strongbox export if direct file export is available, but verify whether it preserves history and attachments.

Important: do not import from a simple CSV alone. CSV is usable for a first-pass import, but it loses full fidelity. To keep history and attachments, parse the KDBX data structurally and persist a richer intermediate representation.

### Phase 2: Build an intermediate migration dataset

Create a migration staging folder such as:

- `exports/strongbox-raw/`
- `exports/strongbox-json/`
- `exports/strongbox-attachments/`
- `exports/strongbox-history/`

Convert the KDBX data into a canonical JSON or SQLite dataset that includes:

- item UUID
- parent group / folder path
- title / username / notes / URL
- password / OTP secret
- custom fields
- attachments list with filename, path, MIME type, and binary blob reference
- history entries with timestamps and prior values
- item creation/update timestamps
- deleted or archived items, if present

This staging representation is the real source of truth for the migration. It allows you to validate and re-run imports without re-reading the database repeatedly.

### Phase 3: Map KeePass semantics to Vaultwarden semantics

KeePass and Bitwarden/Vaultwarden are close but not identical:

- `Group` => Vaultwarden folder or collection (depending on target configuration)
- `Entry` => vault item
- `Password` => field mapped to item password
- `UserName` => username field
- `URL` => URI field(s)
- `Notes` => notes field
- `OTP` => TOTP field
- attachments => binary attachment objects in Vaultwarden
- history => per-item revision import, if supported; otherwise preserve in a sidecar archive and rehydrate where possible

Known caveat: Vaultwarden’s native import path rarely preserves every historical revision exactly as KeePass stores it. For that reason, plan to keep a “source history archive” alongside the migrated Vaultwarden vault.

### Phase 4: Perform the migration in safe batches

Do not import the entire vault in one shot if it is large or historically complex.

Recommended sequence:

1. Test import with a small subset of records.
2. Validate folder mapping, usernames, passwords, and attachments.
3. Import the full set in batches by folder or date range.
4. Re-run the importer only for missing records or failed batches.
5. Preserve a manifest showing which source UUIDs mapped to which vault item IDs.

For a live Vaultwarden server, use a dedicated migration user or service account with a named API token or admin credentials. Keep the export script and importer in a dedicated local directory and log all actions.

### Phase 5: Preserve history and attachments explicitly

This is the most important part of the work.

#### History

For each KeePass entry, store:

- original item UUID
- creation time
- last modified time
- revision metadata
- previous values for password, username, URL, notes, and other tracked fields

If Vaultwarden cannot import revision history directly, keep the full history as a JSON/SQLite archive and optionally re-import via a custom script against the Vaultwarden API using the item UUID and revision metadata.

#### Attachments

For each attachment:

- save the original file in a `attachments/` folder
- record the exact item UUID it belonged to
- preserve file name, binary hash, and size
- import via Vaultwarden’s attachment API or equivalent supported import path

Important rule: attachments must be validated after import by checking filename, mime type, and file size against the original export.

### Phase 6: Validation and checking

After each batch or full migration:

1. Compare total item count vs. source item count.
2. Compare folder count and folder names.
3. Compare attachments count and file hashes.
4. Compare TOTP entries, login URLs, usernames, and notes.
5. Spot-check random records from each category.
6. Check histories for a subset of records.
7. Verify that Vaultwarden can open and render all imported items without corruption.

A good validation target is a zero-diff migration for the set of current records, plus an archive that preserves historical variants.

### Phase 7: Cutover and rollback

Before switching active usage to Vaultwarden:

- make the source database read-only
- archive the original export and migration logs
- validate the target vault one final time
- confirm users can log in to Vaultwarden and access data

Rollback plan:

- keep the original KeePass database and export files
- keep the migration logs and UUID map
- if the import is wrong, restore from the backup and re-run with corrected transformation rules

## Implementation details to keep in mind

- Source data likely needs a custom importer; do not assume an off-the-shelf tool preserves all semantics.
- A direct CSV-to-Vaultwarden import may be acceptable for first pass, but it is not sufficient for fidelity-preserving migration.
- If the target is a shared environment at `vault.risk-mermaid.ts.net`, verify whether the instance allows admin import APIs or only user-driven imports.
- Be careful with passwords and attachments in transit; use encrypted storage and delete temporary files when the migration is complete.

## Practical recommended workflow

1. Backup source DB and attachments.
2. Export KDBX to a structured XML/JSON representation.
3. Extract all entries, folders, history, and attachments into a JSON/SQLite staging folder.
4. Map objects to Vaultwarden item representations.
5. Run a small test migration.
6. Validate.
7. Import all records in batches.
8. Preserve a source-history archive as the long-term fidelity record.
9. Final sign-off and cleanup.

## Final recommendation

The safest path is a two-layer migration:

- layer 1: import current entries and attachments into Vaultwarden
- layer 2: preserve full historical and attachment metadata in a structured source archive that remains clearly associated with each item

This approach gives you the best chance of keeping both current data and historical fidelity without relying on a single import format that drops revision metadata.

## Suggested next step

Create a local importer project in the repo that:

- reads `.kdbx` via `pykeepass`
- exports each item to JSON
- stores attachments and history in a versioned staging directory
- generates a Vaultwarden-compatible batch import manifest

That will let us run the migration iteratively and verify data integrity before touching the live server.
