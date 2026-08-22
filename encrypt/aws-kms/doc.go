// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package awskms provides the same repository-style cryptographic API as the
// local package, backed by AWS KMS where the service supports the operation.
//
// AES encryption, HMAC, RSA operations, and Ed25519 signatures can use AWS KMS
// when the caller provides a KMS key identifier or ARN. Hashing helpers remain
// local because they do not require provider-managed key material.
//
// Asymmetric RSA encryption and RSA signatures can use AWS KMS key identifiers.
// When a method requires a KMS key identifier and the key argument is empty,
// the package reads it from viper using "encrypt.vault.aws-kms.arn".
package awskms
