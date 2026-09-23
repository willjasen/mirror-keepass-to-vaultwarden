#!/usr/bin/env python3
"""Prototype mirror from KeePass/KDBX databases to Vaultwarden.

This script is intentionally conservative:
- it reads KeePass entries, folders, attachments, and history
- writes a JSON export for validation
- supports dry-run and optional Vaultwarden import when credentials are supplied
- can process multiple databases, each mapped to its own organization or folder

Usage examples:
  python scripts/mirror_keepass_to_vaultwarden.py --db /path/to/db.kdbx --password secret --dry-run
  python scripts/mirror_keepass_to_vaultwarden.py --db-dir /path/to/keepass --dry-run
  python scripts/mirror_keepass_to_vaultwarden.py --db /path/to/nerdhirn.kdbx --password secret --org-name nerdhirn --vault-url https://vault.risk-mermaid.ts.net --api-key xxx --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List

import requests
from dotenv import load_dotenv
from pykeepass import PyKeePass


DEFAULT_OUTPUT_DIR = "exports"


def load_env_file(path: str | None = None) -> None:
    if path:
        load_dotenv(path)
    else:
        load_dotenv()


def slugify(value: str) -> str:
    value = value.lower().strip()
    cleaned = []
    for ch in value:
        if ch.isalnum() or ch in "-_":
            cleaned.append(ch)
        else:
            cleaned.append("-")
    slug = "".join(cleaned).strip("-")
    return slug or "database"


def iter_kdbx_files(path: str | Path) -> List[Path]:
    source = Path(path)
    if source.is_file():
        return [source]
    if source.is_dir():
        return sorted(p for p in source.rglob("*.kdbx") if p.is_file())
    return []


def maybe_get_entry_value(entry: Any, *names: str) -> str | None:
    for name in names:
        value = getattr(entry, name, None)
        if value is not None:
            return str(value)
    return None


def item_to_dict(entry: Any, db_name: str) -> Dict[str, Any]:
    tags = [str(tag) for tag in getattr(entry, "tags", []) or []]
    attachment_entries = []
    attachments = getattr(entry, "attachments", []) or []
    if isinstance(attachments, dict):
        attachment_pairs = attachments.items()
    else:
        attachment_pairs = (
            (getattr(attachment, "filename", None), attachment)
            for attachment in attachments
        )
    for key, attachment in attachment_pairs:
        attachment_entries.append(
            {
                "name": str(key or getattr(attachment, "name", "attachment")),
                "size": getattr(attachment, "size", None),
                "content_type": getattr(attachment, "content_type", None),
                "is_binary": getattr(attachment, "is_binary", None),
                "path": getattr(attachment, "path", None),
                "sha256": getattr(attachment, "sha256", None),
            }
        )

    history_entries = []
    for old in getattr(entry, "history", []) or []:
        history_entries.append(
            {
                "title": maybe_get_entry_value(old, "title", "name"),
                "username": maybe_get_entry_value(old, "username", "user_name"),
                "url": maybe_get_entry_value(old, "url"),
                "notes": maybe_get_entry_value(old, "notes"),
                "password": maybe_get_entry_value(old, "password"),
                "last_modified": getattr(old, "last_modified", None),
            }
        )

    return {
        "database": db_name,
        "uuid": str(getattr(entry, "uuid", "")),
        "title": maybe_get_entry_value(entry, "title", "name") or "(untitled)",
        "username": maybe_get_entry_value(entry, "username", "user_name"),
        "password": maybe_get_entry_value(entry, "password"),
        "url": maybe_get_entry_value(entry, "url"),
        "notes": maybe_get_entry_value(entry, "notes"),
        "otp": maybe_get_entry_value(entry, "otp", "totp"),
        "group": str(getattr(getattr(entry, "group", None), "path", "") or ""),
        "tags": tags,
        "attachments": attachment_entries,
        "history": history_entries,
        "created": getattr(entry, "created", None),
        "last_modified": getattr(entry, "last_modified", None),
    }


def export_database(db_path: Path, password: str | None = None, key_file: str | None = None, output_dir: Path | None = None) -> Dict[str, Any]:
    db_name = db_path.stem
    kp = PyKeePass(str(db_path), password=password, keyfile=key_file)

    exported_entries = []
    for group in kp.groups:
        for entry in group.entries:
            exported_entries.append(item_to_dict(entry, db_name=db_name))

    for entry in kp.entries:
        if not any(item["uuid"] == str(entry.uuid) for item in exported_entries):
            exported_entries.append(item_to_dict(entry, db_name=db_name))

    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        out_path = output_dir / f"{slugify(db_name)}-export.json"
        with out_path.open("w", encoding="utf-8") as handle:
            json.dump({"database": db_name, "items": exported_entries}, handle, indent=2, default=str)
        print(f"Exported {len(exported_entries)} entries to {out_path}")

    return {"database": db_name, "items": exported_entries}


def summarize_items(data: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    items = list(data)
    summary = {
        "count": len(items),
        "with_attachments": sum(1 for item in items if item.get("attachments")),
        "with_history": sum(1 for item in items if item.get("history")),
        "with_otp": sum(1 for item in items if item.get("otp")),
        "groups": sorted({item.get("group") for item in items if item.get("group")}),
    }
    return summary


def resolve_vaultwarden_org_id(url: str, api_key: str, organization_name: str | None, organization_id: str | None) -> str | None:
    if organization_id:
        return organization_id
    if not organization_name:
        return None
    endpoint = f"{url.rstrip('/')}/api/organizations"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    response = requests.get(endpoint, headers=headers, timeout=30)
    response.raise_for_status()
    for org in response.json():
        if org.get("name") == organization_name or org.get("id") == organization_name:
            return str(org.get("id"))
    return None


def build_vaultwarden_cipher(item: Dict[str, Any], org_id: str | None) -> Dict[str, Any]:
    fields = []
    for key, value in {"title": item.get("title"), "username": item.get("username"), "url": item.get("url"), "notes": item.get("notes")}.items():
        if value:
            fields.append({"name": key, "value": str(value), "type": 1})

    login = {"username": item.get("username") or "", "password": item.get("password") or ""}
    if item.get("url"):
        login["uris"] = [{"match": None, "uri": item["url"]}]
    if item.get("otp"):
        login["totp"] = str(item["otp"])

    cipher = {
        "type": 1,
        "name": item.get("title") or "(untitled)",
        "notes": item.get("notes") or "",
        "favorite": False,
        "login": login,
        "fields": fields,
        "organizationId": org_id,
    }
    return cipher


def mirror_to_vaultwarden(db_name: str, items: List[Dict[str, Any]], url: str, api_key: str, org_id: str | None, dry_run: bool = True) -> Dict[str, Any]:
    if dry_run:
        return {
            "database": db_name,
            "dry_run": True,
            "organization_id": org_id,
            "items": [item.get("title") for item in items],
        }

    raise RuntimeError(
        "Live import is disabled: Vaultwarden expects Bitwarden-encrypted cipher "
        "payloads, while this prototype currently has plaintext KeePass fields."
    )


def import_with_bitwarden_cli(
    db_path: Path,
    keepass_password: str,
    vaultwarden_url: str,
    organization_id: str,
    cli: str = "bw",
) -> None:
    """Use Bitwarden's supported encrypted KeePass import path."""
    if not shutil.which(cli):
        raise SystemExit(
            "Bitwarden CLI not found. Install it, configure the Vaultwarden server, "
            "unlock it interactively, then rerun with --bw-cli."
        )

    xml_path = Path("/tmp") / f"{slugify(db_path.stem)}-keepass.xml"
    password_file = Path("/tmp") / f"{slugify(db_path.stem)}-keepass-password"
    try:
        export = subprocess.run(
            ["keepassxc-cli", "export", "-q", "-f", "xml", str(db_path)],
            input=f"{keepass_password}\n",
            text=True,
            capture_output=True,
            check=True,
        )
        xml_path.write_text(export.stdout, encoding="utf-8")
        if os.getenv("BW_SESSION"):
            subprocess.run([cli, "sync"], check=True, env=os.environ.copy())
        else:
            status = subprocess.run(
                [cli, "status"],
                check=True,
                capture_output=True,
                text=True,
            )
            if '"status":"unlocked"' not in status.stdout:
                raise SystemExit(
                    "Bitwarden CLI is locked. Run `export BW_SESSION=\"$(bw unlock --raw)\"` "
                    "in the same shell before importing."
                )
        import_command = [cli, "import"]
        if organization_id:
            import_command.extend(["--organizationid", organization_id])
        import_command.extend(["keepass2xml", str(xml_path)])
        subprocess.run(
            import_command,
            check=True,
            env=os.environ.copy(),
        )
        subprocess.run([cli, "sync"], check=True, env=os.environ.copy())
    except FileNotFoundError as exc:
        raise SystemExit("keepassxc-cli is required for the supported encrypted import path.") from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            "Bitwarden CLI import failed. Unlock the CLI interactively with `bw unlock`, "
            "then rerun this command."
        ) from exc
    finally:
        xml_path.unlink(missing_ok=True)
        password_file.unlink(missing_ok=True)


def attach_preserved_data(
    db_path: Path,
    keepass_password: str,
    organization_id: str,
    cli: str = "bw",
) -> Dict[str, int]:
    """Attach KeePass binaries and revision archives to already-imported items."""
    if not shutil.which(cli):
        raise SystemExit("Bitwarden CLI not found.")
    if not os.getenv("BW_SESSION"):
        raise SystemExit("Export BW_SESSION=\"$(bw unlock --raw)\" before attaching data.")

    source = PyKeePass(str(db_path), password=keepass_password)
    list_command = [cli, "list", "items"]
    if organization_id:
        list_command.extend(["--organizationid", organization_id])
    list_command.append("--raw")
    listed = subprocess.run(
        list_command,
        check=True,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    imported = json.loads(listed.stdout)
    if not organization_id:
        imported = [item for item in imported if not item.get("organizationId")]
    candidates: Dict[str, List[Dict[str, Any]]] = {}
    for item in imported:
        login = item.get("login") or {}
        key = json.dumps(
            [
                item.get("name", ""),
                login.get("username") or "",
                (login.get("uris") or [{}])[0].get("uri", "") or "",
            ],
            ensure_ascii=False,
        )
        candidates.setdefault(key, []).append(item)

    uploaded = 0
    skipped = 0
    with tempfile.TemporaryDirectory(prefix="keepass-vaultwarden-") as temp_dir:
        for entry in source.entries:
            key = json.dumps(
                [entry.title or "(untitled)", entry.username or "", entry.url or ""],
                ensure_ascii=False,
            )
            matches = candidates.get(key, [])
            if not matches:
                continue
            item = matches.pop(0)
            existing_names = {a.get("fileName") for a in item.get("attachments") or []}
            attachments = list(entry.attachments or [])
            if entry.history:
                history_name = f"keepass-history-{entry.uuid}.json"
                history_path = Path(temp_dir) / history_name
                history_path.write_text(
                    json.dumps(
                        {
                            "source_uuid": str(entry.uuid),
                            "title": entry.title,
                            "history": [
                                {
                                    "title": old.title,
                                    "username": old.username,
                                    "url": old.url,
                                    "notes": old.notes,
                                    "password": old.password,
                                    "last_modified": str(old.mtime),
                                }
                                for old in entry.history
                            ],
                        },
                        indent=2,
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
                attachments.append(history_path)
            for attachment in attachments:
                if isinstance(attachment, Path):
                    name = attachment.name
                    path = attachment
                else:
                    name = attachment.filename
                    path = Path(temp_dir) / name
                    path.write_bytes(attachment.binary)
                if name in existing_names:
                    skipped += 1
                    continue
                subprocess.run(
                    [
                        cli,
                        "--quiet",
                        "create",
                        "attachment",
                        "--file",
                        str(path),
                        "--itemid",
                        item["id"],
                    ],
                    check=True,
                    env=os.environ.copy(),
                )
                uploaded += 1
    return {"uploaded": uploaded, "skipped": skipped}


def main() -> None:
    parser = argparse.ArgumentParser(description="Prototype KeePass to Vaultwarden mirror")
    parser.add_argument("--db", dest="db_path", help="Path to a single KeePass KDBX file")
    parser.add_argument("--db-dir", dest="db_dir", help="Directory containing one or more KeePass KDBX files")
    parser.add_argument("--password", default=None, help="KeePass database password")
    parser.add_argument("--key-file", default=None, help="KeePass key file path")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory to place JSON export files")
    parser.add_argument("--dry-run", action="store_true", help="Do not push into Vaultwarden")
    parser.add_argument("--vault-url", default=None, help="Vaultwarden base URL, e.g. https://vault.risk-mermaid.ts.net")
    parser.add_argument("--api-key", default=None, help="Vaultwarden API key / bearer token")
    parser.add_argument("--org-name", default=None, help="Organization name used for a dedicated DB import")
    parser.add_argument("--org-id", default=None, help="Vaultwarden organization ID for target imports")
    parser.add_argument("--env-file", default=None, help="Optional .env file path")
    parser.add_argument(
        "--bw-cli",
        action="store_true",
        help="Use Bitwarden's encrypted keepass2xml import into the organization",
    )
    parser.add_argument(
        "--bw-attachments",
        action="store_true",
        help="Attach source binaries and encrypted KeePass history archives to imported items",
    )
    args = parser.parse_args()

    load_env_file(args.env_file)

    if args.password is None:
        args.password = os.getenv("KEEPASS_PASSWORD")
    if args.key_file is None:
        args.key_file = os.getenv("KEEPASS_KEY_FILE")
    if args.vault_url is None:
        args.vault_url = os.getenv("VAULTWARDEN_URL")
    if args.api_key is None:
        args.api_key = os.getenv("VAULTWARDEN_API_KEY")
    if args.org_name is None:
        args.org_name = os.getenv("VAULTWARDEN_ORGANIZATION_NAME")
    if args.org_id is None:
        args.org_id = os.getenv("VAULTWARDEN_ORGANIZATION_ID")
    bw_cli = os.getenv("BW_CLI", "bw")

    source_paths = []
    if args.db_path:
        source_paths.append(args.db_path)
    if args.db_dir:
        source_paths.append(args.db_dir)
    if not source_paths and os.getenv("KEEPASS_PATH"):
        source_paths.append(os.environ["KEEPASS_PATH"])
    if not source_paths:
        raise SystemExit(
            "Provide --db, --db-dir, or KEEPASS_PATH in .env. "
            "The source must be a .kdbx file or a directory containing .kdbx files."
        )

    output_dir = Path(args.output_dir)
    report = []

    database_paths = [db_path for path in source_paths for db_path in iter_kdbx_files(path)]
    if not database_paths:
        formatted_paths = ", ".join(str(path) for path in source_paths)
        raise SystemExit(f"No .kdbx files found at: {formatted_paths}")

    if args.bw_cli:
        if args.dry_run:
            raise SystemExit("--bw-cli cannot be combined with --dry-run.")
        if len(database_paths) != 1:
            raise SystemExit("--bw-cli requires exactly one database at a time.")
        import_with_bitwarden_cli(
            database_paths[0],
            args.password or "",
            args.vault_url or "",
            args.org_id or "",
            cli=bw_cli,
        )
        print(f"Encrypted import completed for {database_paths[0].stem}.")
        return
    if args.bw_attachments:
        if len(database_paths) != 1:
            raise SystemExit("--bw-attachments requires exactly one database at a time.")
        result = attach_preserved_data(
            database_paths[0],
            args.password or "",
            args.org_id,
            cli=bw_cli,
        )
        print(json.dumps(result, indent=2))
        return

    for db_path in database_paths:
            exported = export_database(db_path, password=args.password, key_file=args.key_file, output_dir=output_dir)
            summary = summarize_items(exported["items"])
            report.append({"database": exported["database"], "summary": summary})

            if args.vault_url and args.api_key:
                org_id = args.org_id
                if not args.dry_run and not org_id:
                    org_id = resolve_vaultwarden_org_id(
                        args.vault_url, args.api_key, args.org_name, args.org_id
                    )
                print(
                    f"Targeting organization: {args.org_name or 'none'}"
                    f" (ID: {org_id or 'not resolved in dry-run'})"
                )
                result = mirror_to_vaultwarden(exported["database"], exported["items"], args.vault_url, args.api_key, org_id, dry_run=args.dry_run)
                print(json.dumps(result, indent=2, default=str))

    print(json.dumps({"databases": report}, indent=2))


if __name__ == "__main__":
    main()
