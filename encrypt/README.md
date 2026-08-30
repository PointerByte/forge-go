# forge-go Encrypt

`encrypt` is the standalone cryptography module for forge-go. It exposes a
repository-style API for symmetric encryption, hashing, RSA/ECC helpers, and
digital signatures, with interchangeable local and cloud-backed
implementations.

## Installation

```bash
go get github.com/PointerByte/forge-go/encrypt
```

Update the dependencies used by the current module:

```bash
go get -u ./...
```

Install Staticcheck:

```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
```

Run Staticcheck for this module:

```bash
staticcheck ./...
```

Use Staticcheck before opening a change. It complements `go test` and `go vet`
by finding suspicious code patterns, incorrect API usage, unreachable code,
deprecated calls, and simplifications that can hide bugs even when the code
still compiles.

## Packages

- `github.com/PointerByte/forge-go/encrypt`: shared interfaces and composite repository wrapper
- `github.com/PointerByte/forge-go/encrypt/local`: in-process cryptography
- `github.com/PointerByte/forge-go/encrypt/aws-kms`: AWS KMS-backed operations with local fallback paths
- `github.com/PointerByte/forge-go/encrypt/azure-key-vault`: Azure Key Vault-backed operations with local fallback paths
- `github.com/PointerByte/forge-go/encrypt/gcp-kms`: Google Cloud KMS-backed operations with local fallback paths
- `github.com/PointerByte/forge-go/encrypt/pkcs11`: PKCS#11 (hardware or network HSM) operations with local fallback paths; requires the `pkcs11` build tag

## Capabilities

- AES-GCM encryption and decryption
- HMAC-SHA256 generation
- SHA-256 and BLAKE3 hashing
- RSA key generation and RSA-OAEP encryption/decryption
- ECC key generation and ECDH-derived encryption/decryption
- Ed25519 signing and verification
- RSA-PSS and RSA PKCS#1 v1.5 SHA-256 signing and verification
- context-aware APIs for cancellation and deadlines

## Repository Model

The root package exposes focused interfaces:

- `SymmetricRepository`
- `AsymmetricRepository`
- `HashRepository`
- `SignatureRepository`
- `IRepository`, which combines all of them

Use `encrypt.NewRepository(...)` when you want one value that exposes every
capability from a backend implementation:

```go
repository := encrypt.NewRepository(local.NewRepository())
```

Backend packages also expose their own `NewRepository()` constructors:

```go
localRepository := local.NewRepository()
awsRepository := awskms.NewRepository()
azureRepository := azurekeyvault.NewRepository()
gcpRepository := gcpkms.NewRepository()

_, _, _, _ = localRepository, awsRepository, azureRepository, gcpRepository
```

## Key Data

Key-generation methods return `*models.KeyData`:

- `KeyID`: provider key identifier; the local backend retains key material here
  only for backward compatibility
- `PublicKey`: local public key when exportable
- `KeyRef`: canonical operation reference: local key material or a
  provider-specific ARN, URL, or version name
- `Provider`: backend name, for example `local`, `aws-kms`, `azure-key-vault`, `gcp-kms`, or `pkcs11`

Use `KeyRef` when passing generated keys to operations for every backend. For
local asymmetric keys, use `KeyRef` as the private key and `PublicKey` as the
public key. Local `KeyID` remains equal to `KeyRef` for source compatibility,
but both fields are secret-bearing and must never be logged.

## Quick Start

```go
package main

import (
	"context"

	"github.com/PointerByte/forge-go/encrypt"
	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/local"
	"github.com/PointerByte/forge-go/encrypt/models"
)

func main() {
	ctx := context.Background()
	repository := encrypt.NewRepository(local.NewRepository())

	keyData, err := repository.GenerateSymetrycKeys(ctx, models.GenerateSymmetricKeyRequest{
		UID:  "user-123",
		Size: common.Key256Bits,
	})
	if err != nil {
		panic(err)
	}

	additional := "aad"
	cipherText, err := repository.EncryptAES(ctx, models.EncryptAESRequest{
		UID:        "user-123",
		SecretKey:  keyData.KeyRef,
		Value:      "hello",
		Additional: &additional,
	})
	if err != nil {
		panic(err)
	}

	plainText, err := repository.DecryptAES(ctx, models.DecryptAESRequest{
		UID:         "user-123",
		SecretKey:   keyData.KeyRef,
		CipherValue: cipherText,
		Additional:  &additional,
	})
	if err != nil {
		panic(err)
	}

	_ = plainText
}
```

## Hashing And HMAC

```go
hmacValue := repository.HMAC(ctx, "secret", "message")
sha256Value := repository.Sha256Hex(ctx, "message")
blake3Value := repository.Blake3(ctx, "message")

_, _, _ = hmacValue, sha256Value, blake3Value
```

## RSA

```go
keys, err := repository.GenerateRSAKeys(ctx, models.GenerateRSAKeyRequest{
	UID:  "user-123",
	Size: common.Key2048Bits,
})
if err != nil {
	panic(err)
}

cipherText, err := repository.RSA_OAEP_Encode(ctx, models.RSAOAEPEncodeRequest{
	UID:       "user-123",
	PublicKey: keys.PublicKey,
	Text:      "hello",
})
if err != nil {
	panic(err)
}

plainText, err := repository.RSA_OAEP_Decode(ctx, models.RSAOAEPDecodeRequest{
	UID:        "user-123",
	PrivateKey: keys.KeyRef,
	CipherText: cipherText,
})
if err != nil {
	panic(err)
}

signature, err := repository.SignRSAPSS(ctx, keys.KeyRef, "payload")
if err != nil {
	panic(err)
}

if err := repository.VerifyRSAPSS(ctx, keys.PublicKey, "payload", signature); err != nil {
	panic(err)
}

_ = plainText
```

## ECC

```go
keys, err := repository.GenerateECDHCurveKeys(ctx, models.GenerateECDHCurveKeyRequest{
	UID:   "user-123",
	Curve: common.CurveP256,
})
if err != nil {
	panic(err)
}

cipherText, err := repository.ECDH_Encode(ctx, models.ECDHEncodeRequest{
	UID:       "user-123",
	PublicKey: keys.PublicKey,
	Text:      "hello",
})
if err != nil {
	panic(err)
}

plainText, err := repository.ECDH_Decode(ctx, models.ECDHDecodeRequest{
	UID:        "user-123",
	PrivateKey: keys.KeyRef,
	CipherText: cipherText,
})
if err != nil {
	panic(err)
}

_ = plainText
```

## Ed25519

```go
keys, err := repository.GenerateEd255Keys(ctx)
if err != nil {
	panic(err)
}

signature, err := repository.SignEd25519(ctx, keys.KeyRef, "payload")
if err != nil {
	panic(err)
}

if err := repository.VerifyEd25519(ctx, keys.PublicKey, "payload", signature); err != nil {
	panic(err)
}
```

## Cloud Backends

Cloud packages implement the same repository contract and route operations to
the provider when the supplied key looks like a provider reference. Explicit
local keys are handled by the local fallback where supported.

```go
import (
	awskms "github.com/PointerByte/forge-go/encrypt/aws-kms"
	azurekeyvault "github.com/PointerByte/forge-go/encrypt/azure-key-vault"
	gcpkms "github.com/PointerByte/forge-go/encrypt/gcp-kms"
)
```

Configuration fallback keys:

- AWS KMS: `encrypt.vault.aws-kms.arn`
- Azure Key Vault: `encrypt.vault.azure-key-vault.key-id`
- Google Cloud KMS: `encrypt.vault.gcp-kms.key-id`

Azure and GCP also keep compatibility fallbacks for the older
`encrypt.azure-key-vault.key-id` and `encrypt.gcp-kms.key-id` keys.

## Hardware Backends

The `pkcs11` package talks to a hardware or network HSM through the vendor's
PKCS#11 library. Unlike the cloud backends it needs cgo and is only compiled
when the `pkcs11` build tag is set:

```bash
go build -tags pkcs11 ./...
```

Without the tag a stub is compiled and every constructor returns
`ErrUnavailable`, so `CGO_ENABLED=0` builds and cross-compilation keep working
for consumers that do not need HSM support.

Keys are referenced with RFC 7512 URIs, which makes the routing decision exact
rather than heuristic:

```go
import "github.com/PointerByte/forge-go/encrypt/pkcs11"

repository := pkcs11.NewRepository(
	pkcs11.WithModulePath("/usr/lib64/softhsm/libsofthsm2.so"),
	pkcs11.WithTokenLabel("forge-hsm"),
	pkcs11.WithPinProvider(func(ctx context.Context) (string, error) {
		return readPinFromYourSecretStore(ctx)
	}),
)
defer repository.Close()

signature, err := repository.SignRSAPSS(ctx,
	"pkcs11:token=forge-hsm;object=jwt-signing;type=private", payload)
```

Configuration keys:

- `encrypt.vault.pkcs11.module-path`
- `encrypt.vault.pkcs11.token-label`
- `encrypt.vault.pkcs11.slot-id`
- `encrypt.vault.pkcs11.key-uri`
- `encrypt.vault.pkcs11.max-sessions`

There is deliberately **no** configuration key for the PIN. It is supplied
through `WithPinProvider`, so it never lands in `application.yml`, in a process
environment dump, or in a log.

Behaviour worth knowing before you deploy:

- Generated private and secret keys are created with `CKA_SENSITIVE=true` and
  `CKA_EXTRACTABLE=false`; they cannot be read out of the token.
- When the token does not advertise a mechanism an operation needs, that
  operation fails. It never silently falls back to software, which would void
  the guarantee that the work happened in hardware. Falling back to `local`
  happens only when the caller passes local key material instead of a URI.
- `RotateKey` synthesises rotation, because PKCS#11 has none: it generates an
  equivalent key with a fresh `CKA_ID` and returns a new `KeyRef`. The previous
  key stays usable unless `WithRotateDisablesPrevious` is set.
- `DeactivateKey` clears the object's usage attributes. On most tokens this is
  irreversible, unlike the reversible disable the cloud backends offer.
- `ECDH_Decode` keeps the shared secret inside the token when it implements
  `CKM_HKDF_DERIVE`. Otherwise the ephemeral secret is read out and the
  derivation finishes locally, as the AWS and Azure backends already do; set
  `WithAllowSecretExtraction(false)` to fail instead.
- `HMAC` needs a `CKK_GENERIC_SECRET` key with `CKA_SIGN`. `GenerateSymetrycKeys`
  makes a `CKK_AES` key for `EncryptAES`, and most tokens refuse to MAC with it,
  so HMAC keys are provisioned separately — the same way the AWS backend needs a
  KMS HMAC key rather than an encryption key.
- `RSA_OAEP_Decode` is pinned to SHA-256 with MGF1-SHA256 so the ciphertext stays
  readable by the other backends. A token that only offers OAEP with SHA-1 —
  SoftHSM2 does — returns `ErrOAEPHashUnsupported` instead of silently weakening
  the parameters.

Verified against SoftHSM2 2.7 with `go test -tags 'pkcs11 pkcs11_integration'`;
see `integration_test.go` for the setup.

## Relationship With `security`

`security` depends on this module internally for JWT signing and cryptographic
helpers, but `encrypt` is independent. Use it directly when your application
needs cryptographic primitives outside JWT middleware.

## Tests

From the `encrypt` module directory:

```bash
go test ./...
go test -cover -covermode=atomic -coverprofile=coverage.out ./...
```
