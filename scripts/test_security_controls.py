#!/usr/bin/env python3
"""Verify secure CLI handoffs and Vaultwarden transport requirements."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import mirror_keepass_to_vaultwarden as mirror


def test_fifo_handoff_blocks_path_traversal() -> None:
    payload = b"sensitive attachment data"
    with tempfile.TemporaryDirectory(prefix="secure-handoff-") as temp_dir:
        staging_dir = Path(temp_dir) / "staging"
        staging_dir.mkdir()
        escaped_path = Path(temp_dir) / "escaped.txt"
        command = [
            sys.executable,
            "-c",
            (
                "import json, pathlib, sys; "
                "p = pathlib.Path(sys.argv[1]); "
                "data = p.read_bytes(); "
                "print(json.dumps({'name': p.name, 'data': data.decode()}))"
            ),
            "{fifo}",
        ]
        with patch("subprocess.run", wraps=mirror.subprocess.run) as run:
            mirror.run_command_with_fifo_input(
                command,
                payload,
                staging_dir,
                "../../escaped.txt",
            )
        actual_command = run.call_args.args[0]
        handoff_path = Path(actual_command[-1])
        if handoff_path.name != "escaped.txt":
            raise AssertionError(f"unexpected sanitized name: {handoff_path}")
        if staging_dir not in handoff_path.parents:
            raise AssertionError(f"handoff escaped staging directory: {handoff_path}")
        if escaped_path.exists():
            raise AssertionError("path traversal created a file outside staging")
        if any(staging_dir.rglob("*")):
            raise AssertionError("named pipe handoff was not cleaned up")


def test_https_validation() -> None:
    for url in ("http://vault.example.test", "vault.example.test", "file:///tmp/vault"):
        try:
            mirror.validate_vaultwarden_url(url)
        except SystemExit:
            pass
        else:
            raise AssertionError(f"insecure URL was accepted: {url}")

    response = Mock()
    with patch.object(mirror.requests, "get", return_value=response) as request:
        mirror.validate_vaultwarden_url("https://vault.example.test")
    request.assert_called_once_with(
        "https://vault.example.test",
        timeout=30,
        allow_redirects=False,
    )
    response.close.assert_called_once_with()

    with patch.object(
        mirror.requests,
        "get",
        side_effect=mirror.requests.exceptions.SSLError("untrusted"),
    ):
        try:
            mirror.validate_vaultwarden_url("https://vault.example.test")
        except SystemExit as exc:
            if "trusted" not in str(exc):
                raise AssertionError(f"unexpected certificate error: {exc}") from exc
        else:
            raise AssertionError("untrusted certificate was accepted")


def test_config_permissions() -> None:
    with tempfile.TemporaryDirectory(prefix="secure-config-") as temp_dir:
        config_path = Path(temp_dir) / "config.json"
        config_path.write_text('{"global": {}}', encoding="utf-8")
        config_path.chmod(0o644)
        mirror.load_config_file(str(config_path))
        if config_path.stat().st_mode & 0o777 != 0o600:
            raise AssertionError("config file was not restricted to owner-only access")

        symlink_path = Path(temp_dir) / "linked-config.json"
        os.symlink(config_path, symlink_path)
        try:
            mirror.load_config_file(str(symlink_path))
        except SystemExit:
            pass
        else:
            raise AssertionError("configuration symlink was accepted")


def main() -> None:
    test_fifo_handoff_blocks_path_traversal()
    test_https_validation()
    test_config_permissions()
    print(json.dumps({"security_controls": "passed"}))


if __name__ == "__main__":
    main()
