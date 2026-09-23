# Repository instructions

- Raw Vaultwarden JSON exports contain decrypted secrets. Any workflow that creates a `vaultwarden-export*.json` file must delete it before the process exits, including dry runs and failure paths. Keep only the encrypted KeePass backup artifact.
