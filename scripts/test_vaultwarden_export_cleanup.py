#!/usr/bin/env python3
"""Verify raw Vaultwarden JSON exports are removed after backup runs."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import mirror_keepass_to_vaultwarden as mirror


def run_case(dry_run: bool) -> None:
    with tempfile.TemporaryDirectory(prefix="vaultwarden-export-cleanup-") as temp_dir:
        output_dir = Path(temp_dir)
        created_exports: list[Path] = []

        def fake_configure_bitwarden_server(url: str | None, cli: str = "bw") -> None:
            return None

        def fake_resolve_org_id(
            organization_name: str | None,
            organization_id: str | None,
            cli: str = "bw",
            master_password: str | None = None,
        ) -> str:
            return "org-id"

        def fake_export_vaultwarden_json(
            output_path: Path,
            organization_id: str | None = None,
            cli: str = "bw",
            master_password: str | None = None,
            age_recipient: str | None = None,
            age_identity: str | None = None,
            signing_keys=None,
        ) -> dict:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps({"items": [{"type": 1, "name": "Example"}], "folders": []}),
                encoding="utf-8",
            )
            created_exports.append(output_path)
            return {"items": [{"type": 1, "name": "Example"}], "folders": []}

        def fake_backup_vaultwarden_to_keepass(
            vault_export: dict,
            db_path: Path,
            password: str,
            key_file: str | None = None,
            overwrite: bool = False,
            bw_cli: str | None = None,
            organization_id: str | None = None,
            attachment_downloader=None,
            attachment_output_dir: Path | None = None,
            age_recipient: str | None = None,
            age_identity: str | None = None,
            signing_keys=None,
            attachment_manifest=None,
        ) -> dict:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            db_path.write_text("encrypted backup placeholder", encoding="utf-8")
            return {"database": str(db_path), "items": len(vault_export["items"])}

        def fake_list_vaultwarden_items(
            organization_id: str | None = None,
            cli: str = "bw",
            master_password: str | None = None,
        ) -> list[dict]:
            return []

        original_configure = mirror.configure_bitwarden_server
        original_resolve = mirror.resolve_bitwarden_cli_org_id
        original_export = mirror.export_vaultwarden_json
        original_backup = mirror.backup_vaultwarden_to_keepass
        original_list_items = mirror.list_vaultwarden_items
        try:
            mirror.configure_bitwarden_server = fake_configure_bitwarden_server
            mirror.resolve_bitwarden_cli_org_id = fake_resolve_org_id
            mirror.export_vaultwarden_json = fake_export_vaultwarden_json
            mirror.backup_vaultwarden_to_keepass = fake_backup_vaultwarden_to_keepass
            mirror.list_vaultwarden_items = fake_list_vaultwarden_items

            result = mirror.run_vaultwarden_to_keepass_backup(
                label="nerdhirn",
                output_dir=output_dir,
                temp_dir=output_dir / "temp",
                key_dir=output_dir / "keys",
                backup_db=output_dir / "vaultwarden-backup.kdbx",
                keepass_password="password",
                keepass_key_file=None,
                vaultwarden_url="https://vault.example.test",
                organization_name="nerdhirn",
                organization_id=None,
                bw_cli="bw",
                vaultwarden_master_password="password",
                dry_run=dry_run,
                overwrite=False,
            )
        finally:
            mirror.configure_bitwarden_server = original_configure
            mirror.resolve_bitwarden_cli_org_id = original_resolve
            mirror.export_vaultwarden_json = original_export
            mirror.backup_vaultwarden_to_keepass = original_backup
            mirror.list_vaultwarden_items = original_list_items

        if not created_exports:
            raise AssertionError("test did not create a fake raw export")
        leftover_exports = [path for path in created_exports if path.exists()]
        if leftover_exports:
            raise AssertionError(f"raw export was not deleted: {leftover_exports}")
        if result.get("export_deleted") is not True:
            raise AssertionError(f"result did not report export cleanup: {result}")


def main() -> None:
    run_case(dry_run=True)
    run_case(dry_run=False)
    print("vaultwarden export cleanup test passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"vaultwarden export cleanup test failed: {exc}", file=sys.stderr)
        raise
