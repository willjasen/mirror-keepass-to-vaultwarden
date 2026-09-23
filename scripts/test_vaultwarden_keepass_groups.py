#!/usr/bin/env python3
"""Verify Vaultwarden folders and collections become KeePass groups."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from pykeepass import PyKeePass

import mirror_keepass_to_vaultwarden as mirror


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="vaultwarden-keepass-groups-") as temp_dir:
        db_path = Path(temp_dir) / "backup.kdbx"
        vault_export = {
            "folders": [{"id": "folder-1", "name": "Personal/Email"}],
            "collections": [
                {"id": "collection-1", "name": "Engineering/Servers"},
                {"id": "collection-2", "name": "Finance"},
            ],
            "items": [
                {
                    "type": 1,
                    "name": "Personal Login",
                    "folderId": "folder-1",
                    "login": {"username": "me", "password": "secret"},
                },
                {
                    "type": 1,
                    "name": "Server Login",
                    "id": "server-item",
                    "organizationId": "org-1",
                    "collectionIds": ["collection-1"],
                    "attachments": [{"id": "attachment-1", "fileName": "server.txt"}],
                    "login": {"username": "root", "password": "secret"},
                },
                {
                    "type": 1,
                    "name": "Finance Login",
                    "organizationId": "org-1",
                    "collectionIds": ["collection-2"],
                    "login": {"username": "acct", "password": "secret"},
                },
            ],
        }
        stripped_export = {
            "items": [{"id": "server-item", "type": 1, "name": "Server Login"}],
        }
        mirror.merge_attachment_metadata(
            stripped_export,
            [{"id": "server-item", "attachments": [{"id": "attachment-1", "fileName": "server.txt"}]}],
        )
        if stripped_export["items"][0].get("attachments") != [{"id": "attachment-1", "fileName": "server.txt"}]:
            raise AssertionError("attachment metadata was not merged")

        encrypted_command_calls: list[Path] = []

        def fake_encrypt_command_output(command: list[str], output_path: Path, recipient: str) -> None:
            encrypted_command_calls.append(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(b"encrypted")

        manifest: list[dict[str, str]] = []
        with patch.object(mirror, "encrypt_command_output", fake_encrypt_command_output):
            with patch.object(mirror, "decrypt_age_file", lambda path, identity: b"server attachment"):
                with patch.object(mirror, "sign_and_verify_temp_artifact", lambda **kwargs: None):
                    staged_path = mirror.download_vaultwarden_attachment(
                        {"id": "attachment-1", "fileName": "Sensitive Screenshot Name.png"},
                        {"id": "server-item"},
                        "bw",
                        Path(temp_dir) / "entries",
                        "age1example",
                        "identity",
                        {"private_key": Path("private.pem"), "public_key": Path("public.pem")},
                        manifest=manifest,
                    )
        if "Sensitive" in str(staged_path) or "Screenshot" in str(staged_path):
            raise AssertionError(f"staged path leaked attachment name: {staged_path}")
        if staged_path.suffix != ".age":
            raise AssertionError(f"staged path was not age encrypted: {staged_path}")
        if manifest[0]["file_name"] != "Sensitive Screenshot Name.png":
            raise AssertionError(f"manifest did not retain filename: {manifest}")

        def fake_attachment_downloader(attachment: dict, item: dict) -> bytes:
            if attachment["id"] != "attachment-1" or item["id"] != "server-item":
                raise AssertionError("unexpected attachment download request")
            attachment_path = Path(temp_dir) / "server.txt"
            attachment_path.write_bytes(b"server attachment")
            return attachment_path

        mirror.backup_vaultwarden_to_keepass(
            vault_export,
            db_path,
            "password",
            key_file="",
            attachment_downloader=fake_attachment_downloader,
        )
        kp = PyKeePass(str(db_path), password="password")
        groups_by_entry = {entry.title: "/".join(entry.group.path) for entry in kp.entries}

        expected = {
            "Personal Login": "Personal/Email",
            "Server Login": "Engineering/Servers",
            "Finance Login": "Finance",
        }
        if groups_by_entry != expected:
            raise AssertionError(f"unexpected groups: {groups_by_entry}")
        server_entry = next(entry for entry in kp.entries if entry.title == "Server Login")
        attachment_names = [attachment.filename for attachment in server_entry.attachments]
        if attachment_names != ["server.txt"]:
            raise AssertionError(f"unexpected attachments: {attachment_names}")

    print("vaultwarden keepass group mapping test passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"vaultwarden keepass group mapping test failed: {exc}", file=sys.stderr)
        raise
