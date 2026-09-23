# Repository instructions

- Never write sensitive plaintext to disk. Sensitive data includes credentials,
  Vaultwarden exports, KeePass XML or JSON, passwords and history, attachment
  contents, and sensitive attachment names or metadata.
- Keep sensitive intermediate values in memory. When an external command or
  workflow requires a filesystem artifact, write it only as an age-encrypted,
  ciphertext-signed artifact through `write_secure_temp_artifact()` or
  `write_secure_command_output()`. Read it through
  `read_secure_temp_artifact()` so its ciphertext signature is verified before
  age decrypts and authenticates it.
- When an external CLI requires a path to plaintext, pass the in-memory value
  through `run_command_with_fifo_input()`. Do not create a regular plaintext
  temporary file as a handoff.
- Use opaque temporary filenames when names or metadata may be sensitive. Keep
  any manifest that maps opaque names to sensitive names inside an encrypted,
  signed artifact.
- Remove each run-specific encrypted staging directory in a `finally` path so
  cleanup also occurs during dry runs and failures. Raw
  `vaultwarden-export*.json` files are forbidden, even temporarily.
- Keep only the intended encrypted KeePass backup as persistent workflow output.
