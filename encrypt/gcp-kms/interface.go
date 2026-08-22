// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package gcpkms

import (
	"context"

	"github.com/PointerByte/forge-go/encrypt/models"
)

type SymmetricRepository interface {
	// GenerateSymetrycKeys creates a GCP KMS symmetric key and returns its
	// metadata reference.
	GenerateSymetrycKeys(ctx context.Context, input models.GenerateSymmetricKeyRequest) (*models.KeyData, error)
	// EncryptAES encrypts plaintext with a GCP KMS symmetric key reference or
	// falls back to local AES-GCM when secretKey is a Base64 AES key.
	EncryptAES(ctx context.Context, input models.EncryptAESRequest) (string, error)
	// DecryptAES decrypts ciphertext produced by EncryptAES using GCP KMS or a
	// local Base64 AES key.
	DecryptAES(ctx context.Context, input models.DecryptAESRequest) (string, error)
}

type AsymmetricRepository interface {
	// GenerateRSAKeys creates an RSA decryption key in GCP KMS and returns its
	// public key plus metadata reference.
	GenerateRSAKeys(ctx context.Context, input models.GenerateRSAKeyRequest) (*models.KeyData, error)
	// GenerateECDHCurveKeys creates a GCP KMS key-encapsulation key mapped from
	// the requested curve and returns its public key plus metadata reference.
	GenerateECDHCurveKeys(ctx context.Context, input models.GenerateECDHCurveKeyRequest) (*models.KeyData, error)
	// RSA_OAEP_Encode encrypts plaintext with a GCP KMS key reference or a
	// Base64 RSA public key.
	RSA_OAEP_Encode(ctx context.Context, input models.RSAOAEPEncodeRequest) (string, error)
	// RSA_OAEP_Decode decrypts ciphertext produced by RSA_OAEP_Encode using a
	// GCP KMS key reference or a Base64 RSA private key.
	RSA_OAEP_Decode(ctx context.Context, input models.RSAOAEPDecodeRequest) (string, error)
	// ECDH_Encode encrypts plaintext with a GCP KMS key-encapsulation reference
	// or falls back to a local Base64 ECC public key.
	ECDH_Encode(ctx context.Context, input models.ECDHEncodeRequest) (string, error)
	// ECDH_Decode decrypts ciphertext produced by ECDH_Encode using a GCP KMS
	// key-encapsulation reference or a local Base64 ECC private key.
	ECDH_Decode(ctx context.Context, input models.ECDHDecodeRequest) (string, error)
}

type KeyRepository interface {
	// RotateKey creates a new provider-backed key version or key material by key id.
	RotateKey(ctx context.Context, input models.RotateKeyRequest) (*models.KeyData, error)
	// GetKey returns the provider metadata and public material available for key id.
	GetKey(ctx context.Context, input models.GetKeyRequest) (*models.KeyData, error)
	// DeactivateKey disables a provider-backed key or key version by key id.
	DeactivateKey(ctx context.Context, input models.DeactivateKeyRequest) error
}

type HashRepository interface {
	// HMAC generates an HMAC-SHA256 value with GCP KMS when secretKey is
	// a KMS reference, or locally otherwise.
	HMAC(ctx context.Context, secretKey, message string) string
	// Sha256Hex returns the SHA-256 digest encoded as hexadecimal.
	Sha256Hex(ctx context.Context, message string) string
	// Blake3 returns the BLAKE3 digest encoded as Base64.
	Blake3(ctx context.Context, message string) string
}

type SignatureRepository interface {
	// GenerateEd255Keys creates an Ed25519 signing key in GCP KMS when possible.
	GenerateEd255Keys(ctx context.Context) (*models.KeyData, error)
	// SignEd25519 signs text with a GCP KMS key reference or a Base64 Ed25519
	// private key.
	SignEd25519(ctx context.Context, privateKey, text string) (string, error)
	// VerifyEd25519 verifies a Base64 Ed25519 signature with a GCP KMS key
	// reference or a Base64 Ed25519 public key.
	VerifyEd25519(ctx context.Context, publicKey, text, signature string) error
	// SignRSAPSS signs text with a GCP KMS RSA signing key reference or a
	// Base64 RSA private key.
	SignRSAPSS(ctx context.Context, privateKey, text string) (string, error)
	// VerifyRSAPSS verifies a Base64 RSA-PSS signature with a GCP KMS key
	// reference or a Base64 RSA public key.
	VerifyRSAPSS(ctx context.Context, publicKey, text, signature string) error
	// Sign_RSA_PKCS1v15_SHA256 signs data with RSA PKCS#1 v1.5 using GCP KMS when
	// privateKey is empty, or a local Base64 RSA private key otherwise.
	Sign_RSA_PKCS1v15_SHA256(ctx context.Context, privateKey, data string) (string, error)
	// Verify_RSA_PKCS1v15_SHA256 verifies an RSA PKCS#1 v1.5 SHA-256 signature with GCP KMS
	// when publicKey is empty, or a local Base64 RSA public key otherwise.
	Verify_RSA_PKCS1v15_SHA256(ctx context.Context, data, publicKey string, signature string) error
}
