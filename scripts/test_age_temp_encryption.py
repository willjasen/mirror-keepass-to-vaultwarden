#!/usr/bin/env python3
"""Verify temp files are age-encrypted and decryptable during a run."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import mirror_keepass_to_vaultwarden as mirror


def main() -> None:
    secret = b'{"password":"plaintext should not be visible"}\n'
    with tempfile.TemporaryDirectory(prefix="age-temp-encryption-") as temp_dir:
        run_temp_dir = Path(temp_dir)
        age_material = mirror.generate_age_identity()
        signing_keys = mirror.ensure_signing_keypair(run_temp_dir / "keys")
        encrypted_path = run_temp_dir / "secret.json.age"
        mirror.write_secure_command_output(
            command=["python3", "-c", "import sys; sys.stdout.buffer.write(%r)" % secret],
            encrypted_path=encrypted_path,
            age_recipient=str(age_material["recipient"]),
            age_identity=age_material["identity"],
            signing_keys=signing_keys,
        )
        if list(run_temp_dir.glob("*identity*")):
            raise AssertionError("age identity was written to disk")
        encrypted_bytes = encrypted_path.read_bytes()
        if secret in encrypted_bytes or b"plaintext should not be visible" in encrypted_bytes:
            raise AssertionError("encrypted temp file contains plaintext secret")
        decrypted = mirror.read_secure_temp_artifact(
            encrypted_path=encrypted_path,
            age_identity=age_material["identity"],
            signing_keys=signing_keys,
        )
        if decrypted != secret:
            raise AssertionError("decrypted content did not match original secret")
        manifest_path = run_temp_dir / "attachment-manifest.json.age"
        mirror.write_secure_temp_artifact(
            plaintext=b'[{"file_name":"Sensitive Screenshot Name.png"}]',
            encrypted_path=manifest_path,
            age_recipient=str(age_material["recipient"]),
            signing_keys=signing_keys,
        )
        if b"Sensitive Screenshot" in manifest_path.read_bytes():
            raise AssertionError("encrypted manifest contains plaintext attachment name")
        if not encrypted_path.with_suffix(encrypted_path.suffix + ".sig").exists():
            raise AssertionError("encrypted artifact signature was not written")
        if encrypted_path.with_suffix(encrypted_path.suffix + ".plaintext.sig").exists():
            raise AssertionError("plaintext signature leaks a password-guessing oracle")
    print("age temp encryption test passed")


if __name__ == "__main__":
    try:
        main()
    except (Exception, subprocess.CalledProcessError) as exc:
        print(f"age temp encryption test failed: {exc}", file=sys.stderr)
        raise
