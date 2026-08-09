// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package azurekeyvault provides the same repository-style cryptographic API as
// the local package, backed by Azure Key Vault when a Key Vault key reference
// is supplied.
//
// The package supports provider-backed symmetric encryption, RSA-OAEP,
// RSA-PSS, RSA SHA-256, and HMAC through the Azure SDK, while still routing
// explicit local keys to the local implementation. Ed25519 remains local-only
// because Azure Key Vault doesn't expose provider-backed Ed25519 operations in
// this package.
//
// When a provider key identifier is needed, the package reads it from viper
// using "encrypt.vault.azure-key-vault.key-id", with compatibility fallback to
// "encrypt.azure-key-vault.key-id".
package azurekeyvault
