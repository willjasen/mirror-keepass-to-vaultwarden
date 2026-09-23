# Signing

This project adds a P-256 signing layer around temporary age artifacts. Its
purpose is defense in depth: detect unexpected modification between export,
staging, decryption, and import.

It is not intended to prove that data originated from Vaultwarden, establish a
remote chain of custody, or replace age encryption.

## Device signing key

On the first run, OpenSSL creates an ECDSA keypair using the P-256 curve
(`prime256v1`):

```text
keys/p256-signing-private.pem
keys/p256-signing-public.pem
```

The private key is set to `0600`. The keypair remains under the repository so it
can be reused by later runs on the same device. The entire `keys/` directory,
along with `*.pem` and `*.sig`, is ignored by git.

Do not commit, synchronize, or disclose the private key. Deleting the keypair
is safe only when no active run needs to verify artifacts signed by it; the next
run will generate a new device keypair.

## Signatures created

For every temporary encrypted artifact, the application creates one SHA-256
ECDSA signature:

```text
artifact.age
artifact.age.sig
```

`artifact.age.sig` signs the exact encrypted file bytes. Plaintext signatures
are deliberately not created because a public signature over secret material
would let someone test guesses without possessing the age identity.

Older versions also created `artifact.age.plaintext.sig`. Current runs neither
create nor require that file. Run-specific temporary directories are removed at
the end of processing, so legacy temporary signatures should not be retained.

## Verification order

Before temporary data is used, the application:

1. verifies `artifact.age.sig` against the encrypted artifact
2. decrypts and authenticates the age artifact in memory with the current run's
   identity
3. parses the data, writes it into the encrypted KeePass database, or streams it
   to an external CLI through a named pipe

A failed OpenSSL verification stops the operation. Age's authenticated
encryption detects modification when the artifact is decrypted.

## Security boundary

The signing key is local to the repository and device. This layer is useful for
detecting corruption or modification by something that cannot use the private
key. It does not provide source attestation: a process or user with access to
the private signing key can create valid signatures for different data.

That boundary is intentional. Vaultwarden authentication and HTTPS establish
the remote connection, age protects temporary confidentiality and ciphertext
integrity, and P-256 signatures provide an additional local consistency check.

See [ENCRYPTION.md](ENCRYPTION.md) for the age identity lifecycle and encrypted
temporary-data flow.
