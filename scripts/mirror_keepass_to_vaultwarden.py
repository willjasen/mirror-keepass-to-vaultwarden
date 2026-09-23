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
from datetime import datetime
import json
import os
import shutil
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse

import requests
from pykeepass import PyKeePass, create_database


DEFAULT_OUTPUT_DIR = "exports"
DEFAULT_BACKUP_PATH = "exports/vaultwarden-backup.kdbx"
DEFAULT_CONFIG_PATH = "config.json"
DEFAULT_LOG_DIR = "logs"
DEFAULT_TEMP_DIR = "temp"
DEFAULT_KEY_DIR = "keys"
SIGNING_PRIVATE_KEY = "p256-signing-private.pem"
SIGNING_PUBLIC_KEY = "p256-signing-public.pem"


def export_timestamp() -> str:
    return datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")


def timestamp_path(path: Path, timestamp: str) -> Path:
    return path.with_name(f"{path.stem}-{timestamp}{path.suffix}")


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


class RunLogger:
    def __init__(self, log_dir: Path, timestamp: str) -> None:
        log_dir.mkdir(parents=True, exist_ok=True)
        self.path = log_dir / f"run-{timestamp}.jsonl"

    def write(self, event: str, **data: Any) -> None:
        record = {"time": now_iso(), "event": event, **data}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")


def load_config_file(path: str | None = None) -> Dict[str, Any]:
    config_path = Path(path or DEFAULT_CONFIG_PATH)
    if not config_path.exists():
        return {}
    if config_path.is_symlink() or not config_path.is_file():
        raise SystemExit("The configuration path must be a regular file, not a symlink.")
    config_path.chmod(0o600)
    with config_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def config_value(config: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in config and config[key] not in (None, ""):
            return config[key]
    return default


def config_list_value(config: Dict[str, Any], *keys: str) -> List[str]:
    value = config_value(config, *keys)
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)]


def optional_path_value(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def validate_vaultwarden_url(url: str | None) -> None:
    if not url:
        return
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise SystemExit("vaultwarden_url must be a valid HTTPS URL.")
    try:
        response = requests.get(url, timeout=30, allow_redirects=False)
        response.close()
    except requests.exceptions.SSLError as exc:
        raise SystemExit("vaultwarden_url must present a certificate trusted by this system.") from exc
    except requests.RequestException as exc:
        raise SystemExit(f"Could not securely connect to vaultwarden_url: {exc}") from exc


def global_config(config: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(config.get("global"), dict):
        return config["global"]
    return config


def configured_databases(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    databases = config.get("keepass_databases")
    if isinstance(databases, list) and databases:
        return [database for database in databases if isinstance(database, dict)]

    legacy_database: Dict[str, Any] = {}
    for key in (
        "keepass_path",
        "keepass_paths",
        "keepass_password",
        "keepass_key_file",
        "keepass_backup_path",
        "vaultwarden_organization_name",
        "vaultwarden_organization_id",
    ):
        value = config.get(key)
        if value not in (None, ""):
            legacy_database[key] = value
    return [legacy_database] if legacy_database else []


def database_value(database: Dict[str, Any], global_values: Dict[str, Any], key: str, default: Any = None) -> Any:
    value = database.get(key)
    if value not in (None, ""):
        return value
    return config_value(global_values, key, default=default)


def database_source_paths(database: Dict[str, Any]) -> List[str]:
    return config_list_value(database, "keepass_paths", "keepass_path")


def database_label(database: Dict[str, Any], fallback: str) -> str:
    return str(
        database.get("vaultwarden_organization_name")
        or database.get("vaultwarden_username")
        or database.get("keepass_path")
        or fallback
    )


def database_organization_name(database: Dict[str, Any], global_values: Dict[str, Any]) -> str | None:
    explicit_name = database_value(database, global_values, "vaultwarden_organization_name")
    if explicit_name:
        return str(explicit_name)
    return None


def vaultwarden_export_name(database: Dict[str, Any], global_values: Dict[str, Any], fallback: str) -> str:
    organization_name = database_organization_name(database, global_values)
    if organization_name:
        return str(organization_name)
    organization_id = database_value(database, global_values, "vaultwarden_organization_id")
    if organization_id:
        return str(organization_id)
    username = (
        database_value(database, global_values, "vaultwarden_username")
        or database_value(database, global_values, "vaultwarden_email")
    )
    return str(username or fallback)


def default_backup_path_for_export(output_dir: Path, export_name: str) -> Path:
    return output_dir / f"{slugify(export_name)}.kdbx"


def resolve_mode(config_mode: str | None, args: argparse.Namespace) -> str:
    if args.vaultwarden_to_keepass:
        mode = "vaultwarden_to_keepass"
    else:
        mode = config_mode or "keepass_to_vaultwarden"

    normalized = str(mode).strip().lower().replace("-", "_")
    aliases = {
        "bw_to_keepass": "vaultwarden_to_keepass",
        "bitwarden_to_keepass": "vaultwarden_to_keepass",
        "vaultwarden_to_keepass": "vaultwarden_to_keepass",
        "keepass_to_bw": "keepass_to_vaultwarden",
        "keepass_to_bitwarden": "keepass_to_vaultwarden",
        "keepass_to_vaultwarden": "keepass_to_vaultwarden",
    }
    if normalized not in aliases:
        raise SystemExit(
            "Unsupported global.mode. Use 'vaultwarden_to_keepass' or 'keepass_to_vaultwarden'."
        )
    resolved = aliases[normalized]
    if resolved == "vaultwarden_to_keepass" and (args.bw_cli or args.bw_attachments):
        raise SystemExit("--bw-cli and --bw-attachments require global.mode 'keepass_to_vaultwarden'.")
    return resolved


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


def export_database(
    db_path: Path,
    password: str | None = None,
    key_file: str | None = None,
    output_dir: Path | None = None,
    age_recipient: str | None = None,
    age_identity: str | None = None,
    signing_keys: Dict[str, Path] | None = None,
) -> Dict[str, Any]:
    db_name = db_path.stem
    key_file = optional_path_value(key_file)
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
        data = json.dumps({"database": db_name, "items": exported_entries}, indent=2, default=str).encode("utf-8")
        if not age_recipient or not age_identity or not signing_keys:
            raise RuntimeError("age identity and signing keys are required for KeePass JSON staging.")
        out_path = output_dir / f"{slugify(db_name)}-export.json.age"
        write_secure_temp_artifact(
            plaintext=data,
            encrypted_path=out_path,
            age_recipient=age_recipient,
            signing_keys=signing_keys,
        )
        print(f"Exported {len(exported_entries)} entries to encrypted temp file {out_path}")

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
    validate_vaultwarden_url(url)
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
    temp_dir: Path,
    key_dir: Path,
    cli: str = "bw",
) -> None:
    """Use Bitwarden's supported encrypted KeePass import path."""
    if not shutil.which(cli):
        raise SystemExit(
            "Bitwarden CLI not found. Install it, configure the Vaultwarden server, "
            "unlock it interactively, then rerun with --bw-cli."
        )
    validate_vaultwarden_url(vaultwarden_url)

    timestamp = export_timestamp()
    run_temp_dir = temp_dir / f"keepass-import-{slugify(db_path.stem)}-{timestamp}"
    run_temp_dir.mkdir(parents=True, exist_ok=True)
    age_material = generate_age_identity()
    signing_keys = ensure_signing_keypair(key_dir)
    encrypted_xml_path = run_temp_dir / f"{slugify(db_path.stem)}-keepass.xml.age"
    try:
        export = subprocess.run(
            ["keepassxc-cli", "export", "-q", "-f", "xml", str(db_path)],
            input=f"{keepass_password}\n",
            text=True,
            capture_output=True,
            check=True,
        )
        xml_bytes = export.stdout.encode("utf-8")
        write_secure_temp_artifact(
            plaintext=xml_bytes,
            encrypted_path=encrypted_xml_path,
            age_recipient=str(age_material["recipient"]),
            signing_keys=signing_keys,
        )
        verified_xml = read_secure_temp_artifact(
            encrypted_path=encrypted_xml_path,
            age_identity=age_material["identity"],
            signing_keys=signing_keys,
        )
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
        import_command.extend(["keepass2xml", "{fifo}"])
        run_command_with_fifo_input(
            import_command,
            verified_xml,
            run_temp_dir,
            f"{slugify(db_path.stem)}-keepass.xml",
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
        shutil.rmtree(run_temp_dir, ignore_errors=True)
        try:
            temp_dir.rmdir()
        except OSError:
            pass


def require_unlocked_bitwarden_cli(cli: str = "bw", master_password: str | None = None) -> None:
    if not shutil.which(cli):
        raise SystemExit("Bitwarden CLI not found.")
    if os.getenv("BW_SESSION"):
        subprocess.run(
            [cli, "sync"],
            check=True,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        return
    status = subprocess.run(
        [cli, "status"],
        check=True,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    if '"status":"unlocked"' not in status.stdout:
        if master_password:
            unlock_env = os.environ.copy()
            unlock_env["CODEX_VAULTWARDEN_MASTER_PASSWORD"] = str(master_password)
            unlocked = subprocess.run(
                [cli, "unlock", "--passwordenv", "CODEX_VAULTWARDEN_MASTER_PASSWORD", "--raw"],
                check=True,
                capture_output=True,
                text=True,
                env=unlock_env,
            )
            os.environ["BW_SESSION"] = unlocked.stdout.strip()
            subprocess.run(
                [cli, "sync"],
                check=True,
                capture_output=True,
                text=True,
                env=os.environ.copy(),
            )
            return
        raise SystemExit(
            "Bitwarden CLI is locked. Run `export BW_SESSION=\"$(bw unlock --raw)\"` "
            "in the same shell before exporting."
        )


def safe_handoff_name(name: str) -> str:
    basename = Path(str(name).replace("\\", "/")).name
    if basename in ("", ".", ".."):
        return "attachment"
    return basename.replace("\x00", "") or "attachment"


def run_command_with_fifo_input(
    command: List[str],
    data: bytes,
    staging_dir: Path,
    display_name: str,
) -> None:
    handoff_dir = staging_dir / uuid.uuid4().hex
    handoff_dir.mkdir(mode=0o700, parents=True)
    fifo_path = handoff_dir / safe_handoff_name(display_name)
    os.mkfifo(fifo_path, mode=0o600)
    resolved_command = [str(fifo_path) if part == "{fifo}" else part for part in command]
    writer_error: List[BaseException] = []

    def write_fifo() -> None:
        try:
            with fifo_path.open("wb", buffering=0) as handle:
                handle.write(data)
        except BaseException as exc:
            writer_error.append(exc)

    writer = threading.Thread(target=write_fifo, daemon=True)
    writer.start()
    try:
        subprocess.run(resolved_command, check=True, env=os.environ.copy())
        writer.join(timeout=30)
        if writer.is_alive():
            raise RuntimeError("CLI did not finish reading the secure handoff stream.")
        if writer_error:
            raise RuntimeError("Could not stream data to the CLI.") from writer_error[0]
    finally:
        fifo_path.unlink(missing_ok=True)
        try:
            handoff_dir.rmdir()
        except OSError:
            pass


def generate_age_identity() -> Dict[str, str]:
    if not shutil.which("age") or not shutil.which("age-keygen"):
        raise SystemExit("age and age-keygen are required for encrypted temp staging.")
    try:
        identity = subprocess.run(
            ["age-keygen", "-pq"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            "age-keygen must support post-quantum identities via `age-keygen -pq`. "
            "Install or upgrade age before running this script."
        ) from exc
    recipient = subprocess.run(
        ["age-keygen", "-y", "-"],
        check=True,
        capture_output=True,
        text=True,
        input=identity,
    ).stdout.strip()
    return {"identity": identity, "recipient": recipient}


def encrypt_command_output(command: List[str], output_path: Path, recipient: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    producer = subprocess.Popen(command, stdout=subprocess.PIPE, env=os.environ.copy())
    assert producer.stdout is not None
    consumer = subprocess.Popen(
        ["age", "--encrypt", "-r", recipient, "-o", str(output_path)],
        stdin=producer.stdout,
    )
    producer.stdout.close()
    consumer_rc = consumer.wait()
    producer_rc = producer.wait()
    if producer_rc != 0:
        raise subprocess.CalledProcessError(producer_rc, command)
    if consumer_rc != 0:
        raise subprocess.CalledProcessError(consumer_rc, ["age", "--encrypt", "-o", str(output_path)])


def encrypt_bytes(data: bytes, output_path: Path, recipient: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["age", "--encrypt", "-r", recipient, "-o", str(output_path)],
        check=True,
        input=data,
    )


def ensure_signing_keypair(key_dir: Path) -> Dict[str, Path]:
    if not shutil.which("openssl"):
        raise SystemExit("openssl is required for temp data signatures.")
    key_dir.mkdir(parents=True, exist_ok=True)
    private_key = key_dir / SIGNING_PRIVATE_KEY
    public_key = key_dir / SIGNING_PUBLIC_KEY
    if not private_key.exists():
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(private_key)],
            check=True,
        )
        private_key.chmod(0o600)
    if not public_key.exists():
        subprocess.run(
            ["openssl", "ec", "-in", str(private_key), "-pubout", "-out", str(public_key)],
            check=True,
            capture_output=True,
            text=True,
        )
    return {"private_key": private_key, "public_key": public_key}


def sign_bytes(data: bytes, signature_path: Path, private_key: Path) -> None:
    signature_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(private_key), "-out", str(signature_path)],
        input=data,
        check=True,
    )


def verify_bytes_signature(data: bytes, signature_path: Path, public_key: Path) -> None:
    subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature_path)],
        input=data,
        check=True,
        capture_output=True,
    )


def sign_file(path: Path, signature_path: Path, private_key: Path) -> None:
    signature_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(private_key), "-out", str(signature_path), str(path)],
        check=True,
    )


def verify_file_signature(path: Path, signature_path: Path, public_key: Path) -> None:
    subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature_path), str(path)],
        check=True,
        capture_output=True,
    )


def sign_and_verify_temp_artifact(
    *,
    encrypted_path: Path,
    plaintext: bytes,
    private_key: Path,
    public_key: Path,
) -> None:
    plaintext_signature = encrypted_path.with_suffix(encrypted_path.suffix + ".plaintext.sig")
    encrypted_signature = encrypted_path.with_suffix(encrypted_path.suffix + ".sig")
    sign_bytes(plaintext, plaintext_signature, private_key)
    sign_file(encrypted_path, encrypted_signature, private_key)
    verify_bytes_signature(plaintext, plaintext_signature, public_key)
    verify_file_signature(encrypted_path, encrypted_signature, public_key)


def decrypt_age_file(encrypted_path: Path, identity: str) -> bytes:
    decrypted = subprocess.run(
        ["age", "--decrypt", "-i", "-", str(encrypted_path)],
        check=True,
        capture_output=True,
        input=identity.encode("utf-8"),
    )
    return decrypted.stdout


def write_secure_temp_artifact(
    *,
    plaintext: bytes,
    encrypted_path: Path,
    age_recipient: str,
    signing_keys: Dict[str, Path],
) -> None:
    encrypt_bytes(plaintext, encrypted_path, age_recipient)
    sign_and_verify_temp_artifact(
        encrypted_path=encrypted_path,
        plaintext=plaintext,
        private_key=signing_keys["private_key"],
        public_key=signing_keys["public_key"],
    )


def write_secure_command_output(
    *,
    command: List[str],
    encrypted_path: Path,
    age_recipient: str,
    age_identity: str,
    signing_keys: Dict[str, Path],
) -> bytes:
    encrypt_command_output(command, encrypted_path, age_recipient)
    plaintext = decrypt_age_file(encrypted_path, age_identity)
    sign_and_verify_temp_artifact(
        encrypted_path=encrypted_path,
        plaintext=plaintext,
        private_key=signing_keys["private_key"],
        public_key=signing_keys["public_key"],
    )
    return plaintext


def read_secure_temp_artifact(
    *,
    encrypted_path: Path,
    age_identity: str,
    signing_keys: Dict[str, Path],
) -> bytes:
    encrypted_signature = encrypted_path.with_suffix(encrypted_path.suffix + ".sig")
    plaintext_signature = encrypted_path.with_suffix(encrypted_path.suffix + ".plaintext.sig")
    verify_file_signature(encrypted_path, encrypted_signature, signing_keys["public_key"])
    plaintext = decrypt_age_file(encrypted_path, age_identity)
    verify_bytes_signature(plaintext, plaintext_signature, signing_keys["public_key"])
    return plaintext


def export_vaultwarden_json(
    output_path: Path,
    organization_id: str | None = None,
    cli: str = "bw",
    master_password: str | None = None,
    age_recipient: str | None = None,
    age_identity: str | None = None,
    signing_keys: Dict[str, Path] | None = None,
) -> Dict[str, Any]:
    """Export Vaultwarden JSON through age-encrypted temp staging."""
    require_unlocked_bitwarden_cli(cli, master_password=master_password)
    if not age_recipient or not age_identity:
        raise RuntimeError("age recipient and identity are required for Vaultwarden JSON export.")
    export_command = [
        cli,
        "--raw",
        "export",
        "--format",
        "json",
    ]
    if organization_id:
        export_command.extend(["--organizationid", organization_id])
    if not signing_keys:
        raise RuntimeError("signing keys are required for Vaultwarden JSON export.")
    plaintext = write_secure_command_output(
        command=export_command,
        encrypted_path=output_path,
        age_recipient=age_recipient,
        age_identity=age_identity,
        signing_keys=signing_keys,
    )
    return json.loads(plaintext.decode("utf-8"))


def list_vaultwarden_items(
    organization_id: str | None = None,
    cli: str = "bw",
    master_password: str | None = None,
) -> List[Dict[str, Any]]:
    require_unlocked_bitwarden_cli(cli, master_password=master_password)
    command = [cli, "list", "items", "--raw"]
    if organization_id:
        command.extend(["--organizationid", organization_id])
    listed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    items = json.loads(listed.stdout)
    if organization_id:
        return items
    return [item for item in items if not item.get("organizationId")]


def merge_attachment_metadata(
    vault_export: Dict[str, Any],
    live_items: List[Dict[str, Any]],
) -> None:
    live_by_id = {item.get("id"): item for item in live_items if item.get("id")}
    for item in vault_export.get("items", []):
        live_item = live_by_id.get(item.get("id"))
        if live_item and live_item.get("attachments"):
            item["attachments"] = live_item["attachments"]


def resolve_bitwarden_cli_org_id(
    organization_name: str | None,
    organization_id: str | None,
    cli: str = "bw",
    master_password: str | None = None,
) -> str | None:
    if organization_id:
        return organization_id
    if not organization_name:
        return None
    require_unlocked_bitwarden_cli(cli, master_password=master_password)
    listed = subprocess.run(
        [cli, "list", "organizations", "--raw"],
        check=True,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    for org in json.loads(listed.stdout):
        if org.get("name") == organization_name or org.get("id") == organization_name:
            return str(org.get("id"))
    raise SystemExit(f"Could not find Vaultwarden organization named {organization_name!r}.")


def configure_bitwarden_server(url: str | None, cli: str = "bw") -> None:
    if not url:
        return
    validate_vaultwarden_url(url)
    result = subprocess.run(
        [cli, "config", "server", url],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    if result.returncode == 0:
        return
    output = f"{result.stdout}\n{result.stderr}"
    if "Logout required before server config update" in output:
        return
    raise subprocess.CalledProcessError(
        result.returncode,
        result.args,
        output=result.stdout,
        stderr=result.stderr,
    )


def ensure_group(kp: PyKeePass, groups_by_path: Dict[str, Any], group_path: str) -> Any:
    normalized = group_path.strip("/")
    if not normalized:
        return kp.root_group
    if normalized in groups_by_path:
        return groups_by_path[normalized]

    parent_path, _, name = normalized.rpartition("/")
    parent = ensure_group(kp, groups_by_path, parent_path)
    group = kp.add_group(parent, name)
    groups_by_path[normalized] = group
    return group


def bitwarden_item_group_path(
    item: Dict[str, Any],
    folders_by_id: Dict[str, str],
    collections_by_id: Dict[str, str],
) -> str:
    folder_id = item.get("folderId")
    if folder_id and folder_id in folders_by_id:
        return folders_by_id[folder_id]
    collection_ids = [collection_id for collection_id in item.get("collectionIds", []) if collection_id in collections_by_id]
    if collection_ids:
        return collections_by_id[collection_ids[0]]
    if item.get("organizationId"):
        return "Organizations"
    return ""


def bitwarden_item_notes(item: Dict[str, Any]) -> str:
    notes = item.get("notes") or ""
    extras: List[str] = []
    if item.get("id"):
        extras.append(f"Bitwarden item ID: {item['id']}")
    if item.get("organizationId"):
        extras.append(f"Bitwarden organization ID: {item['organizationId']}")
    if item.get("collectionIds"):
        extras.append("Bitwarden collection IDs: " + ", ".join(item["collectionIds"]))
    fields = item.get("fields") or []
    if fields:
        extras.append(
            "Custom fields:\n"
            + "\n".join(
                f"- {field.get('name')}: {field.get('value', '')}"
                for field in fields
                if field.get("name")
            )
        )
    if extras:
        return "\n\n".join(part for part in [notes, "Vaultwarden metadata:\n" + "\n".join(extras)] if part)
    return notes


def download_vaultwarden_attachment(
    attachment: Dict[str, Any],
    item: Dict[str, Any],
    cli: str,
    output_dir: Path,
    age_recipient: str,
    age_identity: str,
    signing_keys: Dict[str, Path],
    manifest: List[Dict[str, str]] | None = None,
    organization_id: str | None = None,
) -> Path:
    attachment_id = attachment.get("id") or attachment.get("fileName")
    if not attachment_id:
        raise RuntimeError(f"Attachment for item {item.get('id')} has no id or filename.")
    item_dir = output_dir / uuid.uuid4().hex
    item_dir.mkdir(parents=True, exist_ok=True)
    output_path = item_dir / f"{uuid.uuid4().hex}.age"
    command = [
        cli,
        "get",
        "attachment",
        str(attachment_id),
        "--itemid",
        str(item["id"]),
        "--raw",
    ]
    if organization_id:
        command.extend(["--organizationid", organization_id])
    write_secure_command_output(
        command=command,
        encrypted_path=output_path,
        age_recipient=age_recipient,
        age_identity=age_identity,
        signing_keys=signing_keys,
    )
    if manifest is not None:
        manifest.append(
            {
                "item_id": str(item.get("id") or ""),
                "attachment_id": str(attachment_id),
                "file_name": str(attachment.get("fileName") or attachment.get("name") or attachment_id),
                "encrypted_path": str(output_path),
            }
        )
    return output_path


def attach_bitwarden_attachments(
    kp: PyKeePass,
    entry: Any,
    item: Dict[str, Any],
    *,
    cli: str | None = None,
    organization_id: str | None = None,
    attachment_downloader: Any = None,
    attachment_output_dir: Path | None = None,
    age_recipient: str | None = None,
    age_identity: str | None = None,
    signing_keys: Dict[str, Path] | None = None,
    attachment_manifest: List[Dict[str, str]] | None = None,
) -> int:
    attachments = item.get("attachments") or []
    if not attachments:
        return 0
    if attachment_downloader is None:
        if not cli:
            return 0
        if not age_recipient or not age_identity or not signing_keys:
            raise RuntimeError("age recipient, identity, and signing keys are required for attachment staging.")
        attachment_downloader = lambda attachment, source_item: download_vaultwarden_attachment(
            attachment,
            source_item,
            cli,
            attachment_output_dir or Path(tempfile.mkdtemp(prefix="vaultwarden-attachments-")),
            age_recipient,
            age_identity,
            signing_keys,
            manifest=attachment_manifest,
            organization_id=organization_id,
        )

    attached = 0
    for attachment in attachments:
        filename = attachment.get("fileName") or attachment.get("name") or attachment.get("id") or "attachment"
        attachment_path = Path(attachment_downloader(attachment, item))
        if attachment_path.suffix == ".age":
            if not age_identity or not signing_keys:
                raise RuntimeError("age identity and signing keys are required to decrypt staged attachments.")
            data = read_secure_temp_artifact(
                encrypted_path=attachment_path,
                age_identity=age_identity,
                signing_keys=signing_keys,
            )
        else:
            data = attachment_path.read_bytes()
        binary_id = kp.add_binary(data)
        entry.add_attachment(binary_id, str(filename))
        attached += 1
    return attached


def backup_vaultwarden_to_keepass(
    vault_export: Dict[str, Any],
    db_path: Path,
    password: str,
    key_file: str | None = None,
    overwrite: bool = False,
    bw_cli: str | None = None,
    organization_id: str | None = None,
    attachment_downloader: Any = None,
    attachment_output_dir: Path | None = None,
    age_recipient: str | None = None,
    age_identity: str | None = None,
    signing_keys: Dict[str, Path] | None = None,
    attachment_manifest: List[Dict[str, str]] | None = None,
) -> Dict[str, Any]:
    if db_path.exists() and not overwrite:
        raise SystemExit(f"{db_path} already exists. Pass --overwrite-backup to replace it.")

    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.unlink(missing_ok=True)
    key_file = optional_path_value(key_file)
    kp = create_database(str(db_path), password=password, keyfile=key_file)
    folders_by_id = {
        folder["id"]: folder.get("name") or "Folders"
        for folder in vault_export.get("folders", [])
        if folder.get("id")
    }
    collections_by_id = {
        collection["id"]: collection.get("name") or "Collections"
        for collection in vault_export.get("collections", [])
        if collection.get("id")
    }
    groups_by_path: Dict[str, Any] = {"": kp.root_group}

    counts = {"logins": 0, "secure_notes": 0, "cards": 0, "identities": 0, "attachments": 0, "skipped": 0}
    for item in vault_export.get("items", []):
        item_type = item.get("type")
        group = ensure_group(kp, groups_by_path, bitwarden_item_group_path(item, folders_by_id, collections_by_id))
        name = item.get("name") or "(untitled)"
        entry = None

        if item_type == 1:
            login = item.get("login") or {}
            uris = login.get("uris") or []
            url = next((uri.get("uri") for uri in uris if uri.get("uri")), "")
            entry = kp.add_entry(
                group,
                name,
                login.get("username") or "",
                login.get("password") or "",
                url or "",
                bitwarden_item_notes(item),
                force_creation=True,
            )
            if login.get("totp"):
                entry.set_custom_property("Bitwarden TOTP", str(login["totp"]))
            counts["logins"] += 1
        elif item_type == 2:
            entry = kp.add_entry(group, name, "", "", "", bitwarden_item_notes(item), force_creation=True)
            counts["secure_notes"] += 1
        elif item_type == 3:
            card = item.get("card") or {}
            notes = bitwarden_item_notes(item)
            card_lines = [
                f"Cardholder: {card.get('cardholderName', '')}",
                f"Brand: {card.get('brand', '')}",
                f"Number: {card.get('number', '')}",
                f"Expiration: {card.get('expMonth', '')}/{card.get('expYear', '')}",
                f"Code: {card.get('code', '')}",
            ]
            entry = kp.add_entry(group, name, card.get("cardholderName") or "", card.get("number") or "", "", "\n".join([notes, *card_lines]).strip(), force_creation=True)
            counts["cards"] += 1
        elif item_type == 4:
            identity = item.get("identity") or {}
            identity_notes = bitwarden_item_notes(item)
            identity_lines = [f"{key}: {value}" for key, value in identity.items() if value]
            entry = kp.add_entry(group, name, identity.get("username") or identity.get("email") or "", "", "", "\n".join([identity_notes, *identity_lines]).strip(), force_creation=True)
            counts["identities"] += 1
        else:
            counts["skipped"] += 1
        if entry is not None:
            counts["attachments"] += attach_bitwarden_attachments(
                kp,
                entry,
                item,
                cli=bw_cli,
                organization_id=organization_id,
                attachment_downloader=attachment_downloader,
                attachment_output_dir=attachment_output_dir,
                age_recipient=age_recipient,
                age_identity=age_identity,
                signing_keys=signing_keys,
                attachment_manifest=attachment_manifest,
            )

    kp.save()
    return {
        "database": str(db_path),
        "folders": len(folders_by_id),
        "collections": len(collections_by_id),
        "items": len(vault_export.get("items", [])),
        "counts": counts,
    }


def summarize_vaultwarden_export(vault_export: Dict[str, Any]) -> Dict[str, Any]:
    type_names = {1: "logins", 2: "secure_notes", 3: "cards", 4: "identities"}
    counts: Dict[str, int] = {}
    for item in vault_export.get("items", []):
        name = type_names.get(item.get("type"), "other")
        counts[name] = counts.get(name, 0) + 1
    return {
        "folders": len(vault_export.get("folders", [])),
        "collections": len(vault_export.get("collections", [])),
        "items": len(vault_export.get("items", [])),
        "items_with_attachments": sum(1 for item in vault_export.get("items", []) if item.get("attachments")),
        "attachments": sum(len(item.get("attachments") or []) for item in vault_export.get("items", [])),
        "counts": counts,
    }


def run_vaultwarden_to_keepass_backup(
    *,
    label: str,
    output_dir: Path,
    temp_dir: Path,
    key_dir: Path,
    backup_db: Path,
    keepass_password: str,
    keepass_key_file: str | None,
    vaultwarden_url: str | None,
    organization_name: str | None,
    organization_id: str | None,
    bw_cli: str,
    vaultwarden_master_password: str | None,
    dry_run: bool,
    overwrite: bool,
) -> Dict[str, Any]:
    timestamp = export_timestamp()
    run_temp_dir = temp_dir / f"vaultwarden-{slugify(label)}-{timestamp}"
    run_temp_dir.mkdir(parents=True, exist_ok=True)
    signing_keys = ensure_signing_keypair(key_dir)
    age_material = generate_age_identity()
    age_identity = age_material["identity"]
    age_recipient = str(age_material["recipient"])
    export_path = run_temp_dir / f"vaultwarden-export-{slugify(label)}-{timestamp}.json.age"
    attachment_output_dir = run_temp_dir / "attachments"
    attachment_manifest_path = run_temp_dir / "attachment-manifest.json.age"
    attachment_manifest: List[Dict[str, str]] = []
    final_backup_path = timestamp_path(backup_db, timestamp)
    temp_backup_path = run_temp_dir / final_backup_path.name
    configure_bitwarden_server(vaultwarden_url, cli=bw_cli)
    org_id = resolve_bitwarden_cli_org_id(
        organization_name,
        organization_id,
        cli=bw_cli,
        master_password=vaultwarden_master_password,
    )
    try:
        vault_export = export_vaultwarden_json(
            export_path,
            organization_id=org_id,
            cli=bw_cli,
            master_password=vaultwarden_master_password,
            age_recipient=age_recipient,
            age_identity=age_identity,
            signing_keys=signing_keys,
        )
        merge_attachment_metadata(
            vault_export,
            list_vaultwarden_items(
                organization_id=org_id,
                cli=bw_cli,
                master_password=vaultwarden_master_password,
            ),
        )
        summary = summarize_vaultwarden_export(vault_export)
        if dry_run:
            return {
                "dry_run": True,
                "export_deleted": True,
                "planned_backup": str(final_backup_path),
                "summary": summary,
            }
        result = backup_vaultwarden_to_keepass(
            vault_export,
            temp_backup_path,
            keepass_password,
            key_file=keepass_key_file,
            overwrite=overwrite,
            bw_cli=bw_cli,
            organization_id=org_id,
            attachment_output_dir=attachment_output_dir,
            age_recipient=age_recipient,
            age_identity=age_identity,
            signing_keys=signing_keys,
            attachment_manifest=attachment_manifest,
        )
        if attachment_manifest:
            write_secure_temp_artifact(
                plaintext=json.dumps(attachment_manifest, indent=2).encode("utf-8"),
                encrypted_path=attachment_manifest_path,
                age_recipient=age_recipient,
                signing_keys=signing_keys,
            )
        final_backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(temp_backup_path), str(final_backup_path))
        result["database"] = str(final_backup_path)
        return {"export_deleted": True, "backup": result}
    finally:
        shutil.rmtree(run_temp_dir, ignore_errors=True)
        try:
            temp_dir.rmdir()
        except OSError:
            pass


def attach_preserved_data(
    db_path: Path,
    keepass_password: str,
    organization_id: str,
    temp_dir: Path,
    key_dir: Path,
    cli: str = "bw",
) -> Dict[str, int]:
    """Attach KeePass binaries and revision archives to already-imported items."""
    if not shutil.which(cli):
        raise SystemExit("Bitwarden CLI not found.")
    if not os.getenv("BW_SESSION"):
        raise SystemExit("Export BW_SESSION=\"$(bw unlock --raw)\" before attaching data.")

    source = PyKeePass(str(db_path), password=keepass_password)
    age_material = generate_age_identity()
    signing_keys = ensure_signing_keypair(key_dir)
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
    temp_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="keepass-vaultwarden-", dir=temp_dir) as staging_root:
        staging_dir = Path(staging_root)
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
                history_plaintext = json.dumps(
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
                ).encode("utf-8")
                encrypted_history_path = staging_dir / f"{uuid.uuid4().hex}.json.age"
                write_secure_temp_artifact(
                    plaintext=history_plaintext,
                    encrypted_path=encrypted_history_path,
                    age_recipient=str(age_material["recipient"]),
                    signing_keys=signing_keys,
                )
                attachments.append({"name": history_name, "encrypted_path": encrypted_history_path})
            for attachment in attachments:
                if isinstance(attachment, dict):
                    name = str(attachment["name"])
                    encrypted_path = Path(attachment["encrypted_path"])
                    plaintext = read_secure_temp_artifact(
                        encrypted_path=encrypted_path,
                        age_identity=age_material["identity"],
                        signing_keys=signing_keys,
                    )
                elif isinstance(attachment, Path):
                    name = attachment.name
                    encrypted_path = staging_dir / f"{uuid.uuid4().hex}.age"
                    write_secure_temp_artifact(
                        plaintext=attachment.read_bytes(),
                        encrypted_path=encrypted_path,
                        age_recipient=str(age_material["recipient"]),
                        signing_keys=signing_keys,
                    )
                    plaintext = read_secure_temp_artifact(
                        encrypted_path=encrypted_path,
                        age_identity=age_material["identity"],
                        signing_keys=signing_keys,
                    )
                else:
                    name = attachment.filename
                    encrypted_path = staging_dir / f"{uuid.uuid4().hex}.age"
                    write_secure_temp_artifact(
                        plaintext=attachment.binary,
                        encrypted_path=encrypted_path,
                        age_recipient=str(age_material["recipient"]),
                        signing_keys=signing_keys,
                    )
                    plaintext = read_secure_temp_artifact(
                        encrypted_path=encrypted_path,
                        age_identity=age_material["identity"],
                        signing_keys=signing_keys,
                    )
                if name in existing_names:
                    skipped += 1
                    continue
                run_command_with_fifo_input(
                    [
                        cli,
                        "--quiet",
                        "create",
                        "attachment",
                        "--file",
                        "{fifo}",
                        "--itemid",
                        item["id"],
                    ],
                    plaintext,
                    staging_dir,
                    str(name),
                )
                uploaded += 1
    try:
        temp_dir.rmdir()
    except OSError:
        pass
    return {"uploaded": uploaded, "skipped": skipped}


def main() -> None:
    parser = argparse.ArgumentParser(description="Prototype KeePass to Vaultwarden mirror")
    parser.add_argument("--db", dest="db_path", help="Path to a single KeePass KDBX file")
    parser.add_argument("--db-dir", dest="db_dir", help="Directory containing one or more KeePass KDBX files")
    parser.add_argument("--password", default=None, help="KeePass database password")
    parser.add_argument("--key-file", default=None, help="KeePass key file path")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory to place Vaultwarden-to-KeePass KDBX backups")
    parser.add_argument("--dry-run", action="store_true", help="Do not push into Vaultwarden")
    parser.add_argument("--vault-url", default=None, help="Vaultwarden base URL, e.g. https://vault.risk-mermaid.ts.net")
    parser.add_argument("--api-key", default=None, help="Vaultwarden API key / bearer token")
    parser.add_argument("--org-name", default=None, help="Organization name used for a dedicated DB import")
    parser.add_argument("--org-id", default=None, help="Vaultwarden organization ID for target imports")
    parser.add_argument("--config-file", default=DEFAULT_CONFIG_PATH, help="Optional JSON config file path")
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
    parser.add_argument(
        "--vaultwarden-to-keepass",
        action="store_true",
        help="Back up the unlocked Vaultwarden vault into a new KeePass KDBX database",
    )
    parser.add_argument(
        "--backup-db",
        default=None,
        help="Output KeePass KDBX path for --vaultwarden-to-keepass",
    )
    parser.add_argument(
        "--overwrite-backup",
        action="store_true",
        help="Replace the output KDBX if it already exists",
    )
    args = parser.parse_args()

    config = load_config_file(args.config_file)
    globals_ = global_config(config)
    databases = configured_databases(config)

    if args.output_dir == DEFAULT_OUTPUT_DIR:
        args.output_dir = config_value(globals_, "output_dir", default=DEFAULT_OUTPUT_DIR)
    log_dir = Path(config_value(globals_, "log_dir", default=DEFAULT_LOG_DIR))
    temp_dir = Path(config_value(globals_, "temp_dir", default=DEFAULT_TEMP_DIR))
    key_dir = Path(config_value(globals_, "key_dir", default=DEFAULT_KEY_DIR))
    logger = RunLogger(log_dir, export_timestamp())
    if args.vault_url is None:
        args.vault_url = config_value(globals_, "vaultwarden_url")
    if args.api_key is None:
        args.api_key = config_value(globals_, "vaultwarden_api_key")
    bw_cli = config_value(globals_, "bw_cli", default="bw")
    vaultwarden_master_password = config_value(
        globals_,
        "vaultwarden_master_password",
    )
    mode = resolve_mode(config_value(globals_, "mode"), args)
    if not databases and (args.db_path or args.db_dir):
        databases = [{}]
    if not databases:
        raise SystemExit(
            "Define keepass_databases in config.json, or pass --db/--db-dir for a single database."
        )
    direction = mode
    if args.bw_cli:
        direction = "keepass_to_vaultwarden_import"
    if args.bw_attachments:
        direction = "keepass_to_vaultwarden_attachments"
    logger.write(
        "run_started",
        direction=direction,
        dry_run=args.dry_run,
        config_file=args.config_file,
        database_count=len(databases),
    )

    if mode == "vaultwarden_to_keepass":
        results = []
        for index, database in enumerate(databases, start=1):
            label = database_label(database, str(index))
            export_name = vaultwarden_export_name(database, globals_, label)
            keepass_password = args.password or database_value(database, globals_, "keepass_password")
            if not keepass_password:
                raise SystemExit(
                    f"Set keepass_password for database {label} "
                    "or pass --password for the backup KDBX."
                )
            configured_backup_db = args.backup_db or database_value(database, globals_, "keepass_backup_path")
            backup_db = configured_backup_db or str(
                default_backup_path_for_export(Path(args.output_dir), export_name)
            )
            result = run_vaultwarden_to_keepass_backup(
                label=export_name,
                output_dir=Path(args.output_dir),
                temp_dir=temp_dir,
                key_dir=key_dir,
                backup_db=Path(backup_db),
                keepass_password=keepass_password,
                keepass_key_file=optional_path_value(args.key_file or database_value(database, globals_, "keepass_key_file")),
                vaultwarden_url=args.vault_url,
                organization_name=args.org_name or database_organization_name(database, globals_),
                organization_id=args.org_id or database_value(database, globals_, "vaultwarden_organization_id"),
                bw_cli=bw_cli,
                vaultwarden_master_password=vaultwarden_master_password,
                dry_run=args.dry_run,
                overwrite=args.overwrite_backup,
            )
            result["database_config"] = label
            result["vaultwarden_export_name"] = export_name
            results.append(result)
            logger.write("database_completed", direction=direction, result=result)
        logger.write("run_completed", direction=direction, database_count=len(results))
        print(json.dumps({"databases": results}, indent=2))
        return

    report = []

    if args.bw_cli:
        if args.dry_run:
            raise SystemExit("--bw-cli cannot be combined with --dry-run.")
        results = []
        for index, database in enumerate(databases, start=1):
            source_paths = []
            if args.db_path:
                source_paths.append(args.db_path)
            if args.db_dir:
                source_paths.append(args.db_dir)
            if not source_paths:
                source_paths.extend(database_source_paths(database))
            database_paths = [db_path for path in source_paths for db_path in iter_kdbx_files(path)]
            if len(database_paths) != 1:
                raise SystemExit(
                    f"--bw-cli requires exactly one KDBX for {database_label(database, str(index))}."
                )
            org_id = args.org_id or database_value(database, globals_, "vaultwarden_organization_id")
            import_with_bitwarden_cli(
                database_paths[0],
                args.password or database_value(database, globals_, "keepass_password") or "",
                args.vault_url or "",
                org_id or "",
                temp_dir=temp_dir,
                key_dir=key_dir,
                cli=bw_cli,
            )
            results.append({"database": database_paths[0].stem, "imported": True, "organization_id": org_id})
            logger.write("database_completed", direction=direction, result=results[-1])
        logger.write("run_completed", direction=direction, database_count=len(results))
        print(json.dumps({"databases": results}, indent=2))
        return
    if args.bw_attachments:
        results = []
        for index, database in enumerate(databases, start=1):
            source_paths = []
            if args.db_path:
                source_paths.append(args.db_path)
            if args.db_dir:
                source_paths.append(args.db_dir)
            if not source_paths:
                source_paths.extend(database_source_paths(database))
            database_paths = [db_path for path in source_paths for db_path in iter_kdbx_files(path)]
            if len(database_paths) != 1:
                raise SystemExit(
                    f"--bw-attachments requires exactly one KDBX for {database_label(database, str(index))}."
                )
            result = attach_preserved_data(
                database_paths[0],
                args.password or database_value(database, globals_, "keepass_password") or "",
                args.org_id or database_value(database, globals_, "vaultwarden_organization_id"),
                temp_dir=temp_dir,
                key_dir=key_dir,
                cli=bw_cli,
            )
            result["database"] = database_paths[0].stem
            results.append(result)
            logger.write("database_completed", direction=direction, result=result)
        logger.write("run_completed", direction=direction, database_count=len(results))
        print(json.dumps({"databases": results}, indent=2))
        return

    timestamp = export_timestamp()
    run_temp_dir = temp_dir / f"keepass-export-{timestamp}"
    run_temp_dir.mkdir(parents=True, exist_ok=True)
    signing_keys = ensure_signing_keypair(key_dir)
    age_material = generate_age_identity()
    try:
        for index, database in enumerate(databases, start=1):
            source_paths = []
            if args.db_path:
                source_paths.append(args.db_path)
            if args.db_dir:
                source_paths.append(args.db_dir)
            if not source_paths:
                source_paths.extend(database_source_paths(database))
            if not source_paths:
                raise SystemExit(
                    f"Provide keepass_path for database {database_label(database, str(index))}, "
                    "or pass --db/--db-dir."
                )
            database_paths = [db_path for path in source_paths for db_path in iter_kdbx_files(path)]
            if not database_paths:
                formatted_paths = ", ".join(str(path) for path in source_paths)
                raise SystemExit(f"No .kdbx files found at: {formatted_paths}")

            for db_path in database_paths:
                keepass_password = args.password or database_value(database, globals_, "keepass_password")
                key_file = optional_path_value(args.key_file or database_value(database, globals_, "keepass_key_file"))
                exported = export_database(
                    db_path,
                    password=keepass_password,
                    key_file=key_file,
                    output_dir=run_temp_dir,
                    age_recipient=str(age_material["recipient"]),
                    age_identity=age_material["identity"],
                    signing_keys=signing_keys,
                )
                summary = summarize_items(exported["items"])
                report.append({"database": exported["database"], "summary": summary})
                logger.write("database_exported", direction=direction, database=exported["database"], summary=summary)

                if args.vault_url and args.api_key:
                    org_name = args.org_name or database_organization_name(database, globals_)
                    org_id = args.org_id or database_value(database, globals_, "vaultwarden_organization_id")
                    if not args.dry_run and not org_id:
                        org_id = resolve_vaultwarden_org_id(
                            args.vault_url, args.api_key, org_name, org_id
                        )
                    print(
                        f"Targeting organization: {org_name or 'none'}"
                        f" (ID: {org_id or 'not resolved in dry-run'})"
                    )
                    result = mirror_to_vaultwarden(exported["database"], exported["items"], args.vault_url, args.api_key, org_id, dry_run=args.dry_run)
                    print(json.dumps(result, indent=2, default=str))
                    logger.write("database_mirror_planned", direction=direction, result=result)
    finally:
        shutil.rmtree(run_temp_dir, ignore_errors=True)
        try:
            temp_dir.rmdir()
        except OSError:
            pass

    logger.write("run_completed", direction=direction, database_count=len(report))
    print(json.dumps({"databases": report}, indent=2))


if __name__ == "__main__":
    main()
