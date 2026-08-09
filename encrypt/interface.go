// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package encrypt

import (
	"context"

	"github.com/PointerByte/forge-go/encrypt/models"
)

//go:generate mockgen -source=interface.go -destination=mock_repository_test.go -package=encrypt

// SymmetricRepository exposes symmetric encryption helpers.
type SymmetricRepository interface {
	// GenerateSymetrycKeys returns a random Base64-encoded symmetric key.
	GenerateSymetrycKeys(ctx context.Context, input models.GenerateSymmetricKeyRequest) (*models.KeyData, error)

	// EncryptAES encrypts plaintext using a Base64-encoded AES key and optional
	// additional authenticated data, returning the ciphertext in Base64.
	EncryptAES(ctx context.Context, input models.EncryptAESRequest) (string, error)
	// DecryptAES decrypts Base64 ciphertext produced by EncryptAES using the
	// same Base64 AES key and optional additional authenticated data.
	DecryptAES(ctx context.Context, input models.DecryptAESRequest) (string, error)
}

// AsymmetricRepository exposes RSA key generation and RSA-OAEP helpers.
type AsymmetricRepository interface {
	// GenerateRSAKeys creates an RSA key pair and returns the encoded key
	// material plus provider metadata.
	GenerateRSAKeys(ctx context.Context, input models.GenerateRSAKeyRequest) (*models.KeyData, error)
	// GenerateECDHCurveKeys creates an ECC key pair on the requested curve and returns
	// the encoded key material plus provider metadata.
	GenerateECDHCurveKeys(ctx context.Context, input models.GenerateECDHCurveKeyRequest) (*models.KeyData, error)
	// RSA_OAEP_Encode encrypts plaintext with a Base64-encoded RSA public key
	// and returns the ciphertext in Base64.
	RSA_OAEP_Encode(ctx context.Context, input models.RSAOAEPEncodeRequest) (string, error)
	// RSA_OAEP_Decode decrypts Base64 ciphertext with a Base64-encoded RSA
	// private key.
	RSA_OAEP_Decode(ctx context.Context, input models.RSAOAEPDecodeRequest) (string, error)
	// ECDH_Encode encrypts plaintext using an ECC public key with an ECDH-derived
	// AES-GCM key and returns an encoded payload.
	ECDH_Encode(ctx context.Context, input models.ECDHEncodeRequest) (string, error)
	// ECDH_Decode decrypts ciphertext produced by ECDH_Encode using the matching
	// ECC private key.
	ECDH_Decode(ctx context.Context, input models.ECDHDecodeRequest) (string, error)
}

// KeyRepository exposes provider key-management helpers.
type KeyRepository interface {
	// RotateKey creates a new provider-backed key version or key material by key id.
	RotateKey(ctx context.Context, input models.RotateKeyRequest) (*models.KeyData, error)
	// GetKey returns the provider metadata and public material available for key id.
	GetKey(ctx context.Context, input models.GetKeyRequest) (*models.KeyData, error)
	// DeactivateKey disables a provider-backed key or key version by key id.
	DeactivateKey(ctx context.Context, input models.DeactivateKeyRequest) error
}

// HashRepository exposes hashing and message-authentication helpers.
type HashRepository interface {
	// HMAC returns a Base64-encoded HMAC-SHA256 signature.
	HMAC(ctx context.Context, secretKey, message string) string
	// Sha256Hex returns the SHA-256 digest as a hexadecimal string.
	Sha256Hex(ctx context.Context, message string) string
	// Blake3 returns the BLAKE3 digest encoded as Base64.
	Blake3(ctx context.Context, message string) string
}

// SignatureRepository exposes asymmetric signing and verification helpers.
type SignatureRepository interface {
	// GenerateEd255Keys creates an Ed25519 key pair and returns the encoded key
	// material plus provider metadata.
	GenerateEd255Keys(ctx context.Context) (*models.KeyData, error)
	// SignEd25519 signs text using a Base64-encoded Ed25519 private key and
	// returns the signature in Base64.
	SignEd25519(ctx context.Context, privateKey, text string) (string, error)
	// VerifyEd25519 validates an Ed25519 Base64 signature.
	VerifyEd25519(ctx context.Context, publicKey, text, signature string) error

	// SignRSAPSS signs text with RSA-PSS using a Base64-encoded private key and
	// returns the signature in Base64.
	SignRSAPSS(ctx context.Context, privateKey, text string) (string, error)
	// VerifyRSAPSS validates an RSA-PSS Base64 signature.
	VerifyRSAPSS(ctx context.Context, publicKey, text, signature string) error
	// Sign_RSA_PKCS1v15_SHA256 signs data with RSA PKCS#1 v1.5 using SHA-256.
	Sign_RSA_PKCS1v15_SHA256(ctx context.Context, privateKey, data string) (string, error)
	// Verify_RSA_PKCS1v15_SHA256 validates an RSA PKCS#1 v1.5 SHA-256 signature.
	Verify_RSA_PKCS1v15_SHA256(ctx context.Context, data, publicKey string, signature string) error
}

// Repository groups the main encryption and signature capabilities exposed by
// the package in a single composite contract.
type IRepository interface {
	SymmetricRepository
	AsymmetricRepository
	KeyRepository
	HashRepository
	SignatureRepository
}
