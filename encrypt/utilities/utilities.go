// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package utilities

import (
	"crypto/aes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/PointerByte/forge-go/encrypt/common"
)

const eccHKDFInfoPrefix = "GoForge-ecc-aes-gcm:"

// ECCCipherPayload stores the envelope used by ECC hybrid encryption.
type ECCCipherPayload struct {
	Curve              string `json:"curve"`
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	Ciphertext         string `json:"ciphertext"`
}

// ParseRSAPublicKeyFromBase64 decodes a Base64-encoded RSA public key.
func ParseRSAPublicKeyFromBase64(b64 string) (*rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode public key from Base64: %w", err)
	}

	pubIfc, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	pub, ok := pubIfc.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an RSA key")
	}
	return pub, nil
}

// ParseRSAPublicKeyFromPEMFile decodes an RSA public key from a PEM file.
func ParseRSAPublicKeyFromPEMFile(path string) (*rsa.PublicKey, error) {
	der, err := readPEMFile(path)
	if err != nil {
		return nil, err
	}

	pubIfc, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	pub, ok := pubIfc.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an RSA key")
	}
	return pub, nil
}

// ParseRSAPrivateKeyFromBase64 decodes a Base64-encoded RSA private key.
func ParseRSAPrivateKeyFromBase64(b64 string) (*rsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode private key from Base64: %w", err)
	}

	keyIfc, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	priv, ok := keyIfc.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an RSA key")
	}
	return priv, nil
}

// ParseRSAPrivateKeyFromPEMFile decodes an RSA private key from a PEM file.
func ParseRSAPrivateKeyFromPEMFile(path string) (*rsa.PrivateKey, error) {
	der, err := readPEMFile(path)
	if err != nil {
		return nil, err
	}

	keyIfc, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	priv, ok := keyIfc.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an RSA key")
	}
	return priv, nil
}

// ParseEd25519PublicKeyFromBase64 decodes a Base64-encoded Ed25519 public key.
func ParseEd25519PublicKeyFromBase64(b64 string) (ed25519.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode public key from Base64: %w", err)
	}

	publicKeyAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	publicKey, ok := publicKeyAny.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an Ed25519 key")
	}
	return publicKey, nil
}

// ParseEd25519PublicKeyFromPEMFile decodes an Ed25519 public key from a PEM
// file.
func ParseEd25519PublicKeyFromPEMFile(path string) (ed25519.PublicKey, error) {
	der, err := readPEMFile(path)
	if err != nil {
		return nil, err
	}

	publicKeyAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	publicKey, ok := publicKeyAny.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an Ed25519 key")
	}
	return publicKey, nil
}

// ParseEd25519PrivateKeyFromBase64 decodes a Base64-encoded Ed25519 private key.
func ParseEd25519PrivateKeyFromBase64(b64 string) (ed25519.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode private key from Base64: %w", err)
	}

	privateKeyAny, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	privateKey, ok := privateKeyAny.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an Ed25519 key")
	}
	return privateKey, nil
}

// ParseEd25519PrivateKeyFromPEMFile decodes an Ed25519 private key from a PEM
// file.
func ParseEd25519PrivateKeyFromPEMFile(path string) (ed25519.PrivateKey, error) {
	der, err := readPEMFile(path)
	if err != nil {
		return nil, err
	}

	privateKeyAny, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	privateKey, ok := privateKeyAny.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an Ed25519 key")
	}
	return privateKey, nil
}

// ParseECDHPublicKeyFromBase64 decodes a Base64-encoded ECDH public key.
func ParseECDHPublicKeyFromBase64(b64 string) (*ecdh.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode public key from Base64: %w", err)
	}
	return parseECDHPublicKey(der)
}

// ParseECDHPublicKeyFromPEMFile decodes an ECDH public key from a PEM file.
func ParseECDHPublicKeyFromPEMFile(path string) (*ecdh.PublicKey, error) {
	der, err := readPEMFile(path)
	if err != nil {
		return nil, err
	}
	return parseECDHPublicKey(der)
}

// ParseECDHPrivateKeyFromBase64 decodes a Base64-encoded ECDH private key.
func ParseECDHPrivateKeyFromBase64(b64 string) (*ecdh.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode private key from Base64: %w", err)
	}
	return parseECDHPrivateKey(der)
}

// ParseECDHPrivateKeyFromPEMFile decodes an ECDH private key from a PEM file.
func ParseECDHPrivateKeyFromPEMFile(path string) (*ecdh.PrivateKey, error) {
	der, err := readPEMFile(path)
	if err != nil {
		return nil, err
	}
	return parseECDHPrivateKey(der)
}

func parseECDHPublicKey(der []byte) (*ecdh.PublicKey, error) {
	publicKeyAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	switch publicKey := publicKeyAny.(type) {
	case *ecdh.PublicKey:
		return publicKey, nil
	case *ecdsa.PublicKey:
		ecdhPublicKey, err := publicKey.ECDH()
		if err != nil {
			return nil, fmt.Errorf("convert public key to ECDH: %w", err)
		}
		return ecdhPublicKey, nil
	default:
		return nil, errors.New("public key is not an ECC key")
	}
}

func parseECDHPrivateKey(der []byte) (*ecdh.PrivateKey, error) {
	privateKeyAny, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	switch privateKey := privateKeyAny.(type) {
	case *ecdh.PrivateKey:
		return privateKey, nil
	case *ecdsa.PrivateKey:
		ecdhPrivateKey, err := privateKey.ECDH()
		if err != nil {
			return nil, fmt.Errorf("convert private key to ECDH: %w", err)
		}
		return ecdhPrivateKey, nil
	default:
		return nil, errors.New("private key is not an ECC key")
	}
}

// IsLocalAESKey reports whether key looks like a usable Base64-encoded AES key.
func IsLocalAESKey(key string) bool {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return false
	}
	_, err = aes.NewCipher(decoded)
	return err == nil
}

// BytesFromOptionalString converts an optional string into a byte slice.
func BytesFromOptionalString(value *string) []byte {
	if value == nil {
		return nil
	}
	return []byte(*value)
}

// ResolveECDHCurve returns the Go ECDH curve for the provided enum.
func ResolveECDHCurve(curve common.CurveAsymmetricKey) (ecdh.Curve, error) {
	switch curve {
	case common.CurveP256:
		return ecdh.P256(), nil
	case common.CurveP384:
		return ecdh.P384(), nil
	case common.CurveP521:
		return ecdh.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ECC curve: %q", curve)
	}
}

// CurveNameFromECDH returns the serialized name for the provided ECDH curve.
func CurveNameFromECDH(curve ecdh.Curve) (string, error) {
	switch curve {
	case ecdh.P256():
		return common.CurveP256.String(), nil
	case ecdh.P384():
		return common.CurveP384.String(), nil
	case ecdh.P521():
		return common.CurveP521.String(), nil
	default:
		return "", errors.New("unsupported ECC curve")
	}
}

// DeriveECCAESKey derives a 256-bit AES key from an ECDH shared secret.
func DeriveECCAESKey(sharedSecret []byte, curveName string) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, sharedSecret, nil, eccHKDFInfoPrefix+curveName, 32)
	if err != nil {
		return nil, fmt.Errorf("derive AES key from shared secret: %w", err)
	}
	return key, nil
}

// EncodeECCCipherPayload serializes an ECC payload and returns it in Base64.
func EncodeECCCipherPayload(payload ECCCipherPayload) (string, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode ECC payload: %w", err)
	}
	return base64.StdEncoding.EncodeToString(payloadBytes), nil
}

// DecodeECCCipherPayload decodes an ECC payload from Base64.
func DecodeECCCipherPayload(cipherText string) (*ECCCipherPayload, error) {
	payloadBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, fmt.Errorf("decode ECC payload: %w", err)
	}

	var payload ECCCipherPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("decode ECC payload json: %w", err)
	}
	if payload.Curve == "" || payload.EphemeralPublicKey == "" || payload.Ciphertext == "" {
		return nil, errors.New("invalid ECC payload")
	}
	return &payload, nil
}

func readPEMFile(path string) ([]byte, error) {
	// The PEM file path is supplied by the caller (an operator-configured key
	// location), so reading it by variable path is the intended behavior.
	content, err := os.ReadFile(path) // #nosec G304 -- caller-provided key file path

	if err != nil {
		return nil, fmt.Errorf("read PEM file: %w", err)
	}

	block, _ := pem.Decode(content)
	if block == nil {
		return nil, errors.New("decode PEM block: no PEM data found")
	}
	return block.Bytes, nil
}
