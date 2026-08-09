# go-openssl

`go-openssl` is the GoForge CLI for generating PEM certificates and keys for
RSA, ECC/ECDSA, or Ed25519. It can create self-signed certificates, CA
certificates, certificates signed by an existing CA, and encrypted PEM
envelopes that can later be read back by the CLI or the Go API.

## Install

```bash
go install github.com/PointerByte/forge-go/cmd/go-openssl@latest
```

Update the dependencies used by the current module:

```bash
go get -u ./...
```

## Commands

Generate PEM files:

```bash
go-openssl generate [flags]
```

Read a plain or encrypted PEM file:

```bash
go-openssl read --file ./certs/cert.pem
```

Update the secret on existing encrypted PEM files:

```bash
go-openssl reencrypt [flags]
```

## Generate Defaults

When flags are omitted, generation uses:

- algorithm: `rsa`
- output directory: `.`
- common name: `localhost`
- DNS SAN: `localhost`
- organization: `PointerByte`
- validity: `365` days
- RSA size: `2048` bits
- ECC curve: `p256`
- files: `cert.pem`, `key.pem`, `public.pem`

Private keys are written with mode `0600`; certificate and public key files are
written with mode `0644`. File contents are staged beside their destinations
and atomically replaced. A generation or rotation error cleans staged files and
restores any targets replaced earlier in the same batch.

## Generate Flags

| Flag | Short | Description |
| --- | --- | --- |
| `--algorithm` | `-a` | `rsa`, `ecc`, or `ed25519` |
| `--dir` | `-d` | output directory |
| `--common-name` | `-n` | certificate common name |
| `--dns` | | DNS Subject Alternative Name; may be repeated or comma-separated |
| `--organization` | | certificate subject organization |
| `--days` | | certificate validity in days |
| `--rsa-bits` | | RSA key size in bits; minimum `2048` |
| `--ecc-curve` | | `p256`, `p384`, or `p521` |
| `--salt` | | optional extra entropy mixed into generation |
| `--cert-file` | | certificate file name |
| `--key-file` | | private key file name |
| `--public-key-file` | | public key file name |
| `--signed-by` | | CA certificate PEM path used to sign the new certificate |
| `--ca-key` | | CA private key PEM path used with `--signed-by` |
| `--ca` | | mark the generated certificate as a CA |
| `--encrypt-secret-env` | | environment variable containing the generated-file encryption secret |
| `--encrypt-secret-file` | | regular file containing the generated-file encryption secret |
| `--signed-by-secret-env` / `--signed-by-secret-file` | | environment or file source for the encrypted `--signed-by` certificate |
| `--ca-key-secret-env` / `--ca-key-secret-file` | | environment or file source for the encrypted `--ca-key` private key |
| `--encrypt-secret`, `--signed-by-secret`, `--ca-key-secret` | | deprecated literal-value compatibility flags |

`--signed-by` and `--ca-key` must be provided together. If either CA file is
encrypted, pass the matching environment-variable name or secret-file path.
Literal secret flags remain compatible but warn because process arguments may
be visible to other users and monitoring tools.

## Read Flags

| Flag | Short | Description |
| --- | --- | --- |
| `--file` | `-f` | plain or encrypted PEM file to read |
| `--secret-env` | | environment variable containing the decryption secret |
| `--secret-file` | | regular file containing the decryption secret |
| `--secret` | `-s` | deprecated literal-value compatibility flag |
| `--out` | `-o` | optional destination for decrypted PEM output |

If `--out` is omitted, the command writes the PEM content to stdout. With
`--out`, it atomically replaces a regular-file target with mode `0600`.

## Reencrypt Flags

| Flag | Description |
| --- | --- |
| `--cert-file` | encrypted certificate PEM path |
| `--key-file` | encrypted private key PEM path |
| `--public-key-file` | encrypted public key PEM path |
| `--encrypt-secret-old-env` / `--encrypt-secret-old-file` | environment or file source for the current secret |
| `--encrypt-secret-new-env` / `--encrypt-secret-new-file` | environment or file source for the new secret |
| `--encrypt-secret-old`, `--encrypt-secret-new` | deprecated literal-value compatibility flags |

Both secrets must be at least 32 bytes. The command atomically replaces the same
files and does not generate a new certificate or key pair.

## Basic Examples

Generate a self-signed RSA certificate:

```bash
go-openssl generate --algorithm rsa --dir ./certs
```

Generate an ECC certificate:

```bash
go-openssl generate \
  --algorithm ecc \
  --ecc-curve p384 \
  --dir ./certs/ecc \
  --common-name api.default.svc \
  --dns api.default.svc \
  --dns api.default.svc.cluster.local
```

Generate an Ed25519 certificate and key pair:

```bash
go-openssl generate \
  --algorithm ed25519 \
  --dir ./certs/jwt \
  --common-name jwt-signing.default.svc \
  --key-file key.pem \
  --public-key-file public.pem
```

## CA And mTLS Example

Create a CA:

```bash
go-openssl generate \
  --algorithm rsa \
  --rsa-bits 4096 \
  --ca \
  --dir ./certs/ca \
  --common-name internal-ca.example.local \
  --organization "Example Internal CA" \
  --days 3650 \
  --cert-file ca.pem \
  --key-file ca-key.pem \
  --public-key-file ca-public.pem
```

Create a server certificate signed by that CA:

```bash
go-openssl generate \
  --algorithm ecc \
  --ecc-curve p256 \
  --dir ./certs/server \
  --common-name my-api.default.svc \
  --dns my-api.default.svc \
  --dns my-api.default.svc.cluster.local \
  --organization "Example Platform" \
  --days 365 \
  --signed-by ./certs/ca/ca.pem \
  --ca-key ./certs/ca/ca-key.pem
```

Create a client certificate for mTLS:

```bash
go-openssl generate \
  --algorithm ecc \
  --ecc-curve p256 \
  --dir ./certs/client \
  --common-name my-api-client.default.svc \
  --dns my-api-client.default.svc \
  --organization "Example Platform" \
  --days 365 \
  --signed-by ./certs/ca/ca.pem \
  --ca-key ./certs/ca/ca-key.pem
```

## Encrypted PEM Files

New encrypted output uses version-2 `GoForge ENCRYPTED PEM` envelopes:
AES-256-GCM with an Argon2id-derived key, a random 16-byte KDF salt, and a
separate random nonce. Version 2 fixes Argon2id at 64 MiB, three passes, two
lanes, and a 32-byte key; unexpected parameters are rejected before allocation.
Secrets must be at least 32 bytes. The reader continues to accept legacy
version-1 envelopes; reading does not rewrite them, while `reencrypt` upgrades
them to version 2.

Prefer a secret-manager mount or an environment variable. Do not place the
secret value directly in a command line:

```bash
go-openssl generate \
  --algorithm rsa \
  --rsa-bits 4096 \
  --dir ./certs/encrypted \
  --common-name api.default.svc \
  --encrypt-secret-file /run/secrets/goforge-pem
```

Read an encrypted PEM to stdout:

```bash
go-openssl read \
  --file ./certs/encrypted/cert.pem \
  --secret-file /run/secrets/goforge-pem
```

Write the decrypted PEM to a new file:

```bash
go-openssl read \
  --file ./certs/encrypted/key.pem \
  --secret-file /run/secrets/goforge-pem \
  --out ./certs/encrypted/key.decrypted.pem
```

Update encrypted PEM files to a new secret without regenerating certificates:

```bash
go-openssl reencrypt \
  --cert-file ./certs/encrypted/cert.pem \
  --key-file ./certs/encrypted/key.pem \
  --public-key-file ./certs/encrypted/public.pem \
  --encrypt-secret-old-file /run/secrets/goforge-pem-current \
  --encrypt-secret-new-env GOFORGE_PEM_SECRET_NEW
```

Use an encrypted CA to sign another certificate:

```bash
go-openssl generate \
  --algorithm ecc \
  --ecc-curve p384 \
  --dir ./certs/service \
  --common-name service.default.svc \
  --dns service.default.svc \
  --signed-by ./certs/ca/ca.pem \
  --ca-key ./certs/ca/ca-key.pem \
  --signed-by-secret-file /run/secrets/goforge-ca \
  --ca-key-secret-file /run/secrets/goforge-ca
```

Each logical secret accepts exactly one environment, file, or deprecated
literal source. Secret files are bounded regular files; one trailing `LF` or
`CRLF` is removed for compatibility with mounted secrets. Values are never
included in command status or error text.

Version-2 files cannot be read by older `go-openssl` releases. Keep an updated
binary available during rollout. Ordinary operation failures trigger cleanup
and rollback, but no multi-file format can guarantee transactionality across a
host crash; use normal backup and recovery controls for key material.

## Kubernetes Examples

Backend certificate for a service behind an Ingress:

```bash
go-openssl generate \
  --algorithm rsa \
  --rsa-bits 4096 \
  --dir ./certs/my-api \
  --common-name my-api.default.svc \
  --dns my-api.default.svc \
  --dns my-api.default.svc.cluster.local \
  --dns api.example.com \
  --organization "Example Platform" \
  --days 365
```

Internal service-to-service certificate:

```bash
go-openssl generate \
  --algorithm ecc \
  --ecc-curve p256 \
  --dir ./certs/orders-to-payments \
  --common-name payments.default.svc \
  --dns payments.default.svc \
  --dns payments.default.svc.cluster.local \
  --organization "Example Internal Services" \
  --days 365
```

## Go API

The generator can also be used directly from Go:

```go
package main

import (
	"log"

	goopenssl "github.com/PointerByte/forge-go/cmd/go-openssl/code"
)

func main() {
	result, err := goopenssl.GenerateCertificates(goopenssl.Options{
		Algorithm:    "ecc",
		ECCCurve:     "p256",
		OutputDir:    "./certs",
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		IPAddresses:  []string{"127.0.0.1"},
		Organization: "Example",
		ValidForDays: 365,
	})
	if err != nil {
		log.Fatal(err)
	}

	cert, err := goopenssl.ReadCertificateFile(result.CertificatePath, "")
	if err != nil {
		log.Fatal(err)
	}

	_ = cert
}
```

To update the secret on existing encrypted PEM files from Go:

```go
_, err := goopenssl.UpdateEncryptionSecret(goopenssl.UpdateEncryptionSecretOptions{
	CertificatePath:   "./certs/encrypted/cert.pem",
	PrivateKeyPath:    "./certs/encrypted/key.pem",
	PublicKeyPath:     "./certs/encrypted/public.pem",
	EncryptSecretOld:  oldSecretFromSecretManager,
	EncryptSecretNew:  newSecretFromSecretManager,
})
if err != nil {
	log.Fatal(err)
}
```

`go-openssl generate` maps to `goopenssl.Options` fields:

| CLI flag | Go field |
| --- | --- |
| `--algorithm` | `Algorithm` |
| `--dir` | `OutputDir` |
| `--common-name` | `CommonName` |
| `--dns` | `DNSNames` |
| Go API only | `IPAddresses` |
| `--organization` | `Organization` |
| `--days` | `ValidForDays` |
| `--rsa-bits` | `RSAKeySize` |
| `--ecc-curve` | `ECCCurve` |
| `--salt` | `Salt` |
| `--cert-file` | `CertFileName` |
| `--key-file` | `KeyFileName` |
| `--public-key-file` | `PublicKeyFileName` |
| `--signed-by` | `SignedBy` |
| `--ca-key` | `CAKeyFile` |
| `--ca` | `IsCA` |
| any `--encrypt-secret-*` source | `EncryptSecret` |
| any `--signed-by-secret-*` source | `SignedBySecret` |
| any `--ca-key-secret-*` source | `CAKeySecret` |

Reader helpers:

- `ReadPEMFile(path, secret)`
- `ReadCertificateFile(path, secret)`
- `ReadPrivateKeyFile(path, secret)`
- `ReadPublicKeyFile(path, secret)`
- `UpdateEncryptionSecret(options)`

Plain PEM files can be read with an empty secret. Encrypted PEM files require
the same secret used during generation. Go callers should obtain secret strings
from their secret manager; the Go API never requires command-line arguments.

## Development

From the `cmd/go-openssl` module directory:

```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
staticcheck ./...
go test ./...
go test -cover -covermode=atomic -coverprofile=coverage.out ./...
```

Use Staticcheck before opening a change. It complements `go test` and `go vet`
by finding suspicious code patterns, incorrect API usage, unreachable code,
deprecated calls, and simplifications that can hide bugs even when the code
still compiles.
