// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package gcpkms provides the same repository-style cryptographic API as the
// local package, backed by Google Cloud KMS when a Cloud KMS key reference is
// supplied.
//
// The package supports provider-backed symmetric encryption, HMAC, RSA-OAEP,
// RSA signing, and Ed25519 signing through the Google Cloud KMS SDK, while
// still routing explicit local keys to the local implementation. Provider-side
// verification paths that are not exposed by Cloud KMS are completed by
// fetching the public key and verifying locally.
//
// When a provider key identifier is needed, the package reads it from viper
// using "encrypt.vault.gcp-kms.key-id", with compatibility fallback to
// "encrypt.gcp-kms.key-id".
package gcpkms
