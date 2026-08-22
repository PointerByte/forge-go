package models

import "github.com/PointerByte/forge-go/encrypt/common"

type KeyData struct {
	// PublicKey contains exportable public key material when the backend
	// supports it.
	PublicKey string
	// KeyID is the provider identifier. For backward compatibility, the local
	// backend still places key material here; new code should use KeyRef.
	KeyID string
	// KeyRef is the canonical value to pass to cryptographic operations. It is
	// local key material for the local backend and a provider reference for
	// cloud backends. It must be treated as secret whenever it contains key
	// material.
	KeyRef string
	// Provider identifies the backend that created the key data.
	Provider string
}

type RotateKeyRequest struct {
	UID   string
	KeyID string
}

type GetKeyRequest struct {
	UID   string
	KeyID string
}

type DeactivateKeyRequest struct {
	UID   string
	KeyID string
}

type GenerateSymmetricKeyRequest struct {
	UID  string
	Size common.SizeSymetrycKey
}

type EncryptAESRequest struct {
	UID        string
	SecretKey  string
	Value      string
	Additional *string
}

type DecryptAESRequest struct {
	UID         string
	SecretKey   string
	CipherValue string
	Additional  *string
}

type GenerateRSAKeyRequest struct {
	UID  string
	Size common.SizeAsymetrycKey
}

type GenerateECDHCurveKeyRequest struct {
	UID   string
	Curve common.CurveAsymmetricKey
}

type RSAOAEPEncodeRequest struct {
	UID       string
	PublicKey string
	Text      string
}

type RSAOAEPDecodeRequest struct {
	UID        string
	PrivateKey string
	CipherText string
}

type ECDHEncodeRequest struct {
	UID       string
	PublicKey string
	Text      string
}

type ECDHDecodeRequest struct {
	UID        string
	PrivateKey string
	CipherText string
}
