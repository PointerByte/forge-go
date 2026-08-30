// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package pkcs11 provides the same repository-style cryptographic API as the
// local package, backed by a PKCS#11 token (a hardware or network HSM) when a
// RFC 7512 "pkcs11:" key URI is supplied.
//
// The package supports provider-backed symmetric encryption, HMAC, RSA-OAEP,
// RSA signing, Ed25519 signing, and ECDH key agreement through the vendor
// PKCS#11 library, while still routing explicit local key material to the
// local implementation. Operations whose mechanism the token does not report
// in C_GetMechanismList fail with a descriptive error instead of silently
// falling back to software, so a caller can never believe an operation was
// hardware-backed when it was not.
//
// Unlike the cloud backends, this package requires cgo and is only compiled
// when the "pkcs11" build tag is set:
//
//	go build -tags pkcs11 ./...
//
// Without that tag a stub implementation is compiled instead and every
// constructor returns ErrUnavailable, which keeps CGO_ENABLED=0 builds and
// cross-compilation working for consumers that do not need HSM support.
//
// Two token-side requirements are worth knowing before deploying. HMAC needs a
// CKK_GENERIC_SECRET key carrying CKA_SIGN, which GenerateSymetrycKeys does not
// produce -- it creates a CKK_AES key for EncryptAES -- so HMAC keys are
// provisioned separately, as they are with the cloud backends. And RSA-OAEP is
// pinned to SHA-256 with MGF1-SHA256 to stay readable by the other backends; a
// token that only implements OAEP with SHA-1, as SoftHSM2 does, reports
// ErrOAEPHashUnsupported rather than silently weakening the parameters.
//
// Configuration is read from viper using "encrypt.vault.pkcs11.module",
// "encrypt.vault.pkcs11.token-label", "encrypt.vault.pkcs11.slot" and
// "encrypt.vault.pkcs11.max-sessions", and every value can be overridden
// through functional options. The token PIN is never read from configuration:
// it is supplied by the caller through a PinProvider.
package pkcs11
