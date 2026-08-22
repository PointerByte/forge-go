// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package azurekeyvault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// TestAzureECJWKFromECDSAPublicKey exercises the *ecdsa.PublicKey branch of
// azureECJWKFromPublicKeyDER (and azureCurveNameFromECDSA) for every supported
// curve plus an unsupported one.
func TestAzureECJWKFromECDSAPublicKey(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
		want  azkeys.CurveName
	}{
		{name: "P256", curve: elliptic.P256(), want: azkeys.CurveNameP256},
		{name: "P384", curve: elliptic.P384(), want: azkeys.CurveNameP384},
		{name: "P521", curve: elliptic.P521(), want: azkeys.CurveNameP521},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(test.curve, rand.Reader)
			if err != nil {
				t.Fatalf("ecdsa.GenerateKey() error = %v", err)
			}
			der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
			if err != nil {
				t.Fatalf("marshal ecdsa public: %v", err)
			}

			jwk, err := azureECJWKFromPublicKeyDER(der)
			if err != nil {
				t.Fatalf("azureECJWKFromPublicKeyDER() error = %v", err)
			}
			if jwk.Curve != string(test.want) || jwk.X == "" || jwk.Y == "" {
				t.Fatalf("azureECJWKFromPublicKeyDER() = %#v, want curve %q", jwk, test.want)
			}
		})
	}

	t.Run("unsupported curve", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey() error = %v", err)
		}
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatalf("marshal ecdsa public: %v", err)
		}
		if _, err := azureECJWKFromPublicKeyDER(der); err == nil {
			t.Fatal("expected unsupported curve error")
		}
	})
}

// TestAzureCurveNameFromECDSAUnsupported covers the default branch directly.
func TestAzureCurveNameFromECDSAUnsupported(t *testing.T) {
	if _, _, err := azureCurveNameFromECDSA(elliptic.P224()); err == nil {
		t.Fatal("expected unsupported curve error")
	}
}

// TestAzureKeyDataFromBundleRSA covers the RSA branch of azureKeyDataFromBundle.
func TestAzureKeyDataFromBundleRSA(t *testing.T) {
	rsaKey := mustAzureRSAKey(t)
	bundle := azkeys.KeyBundle{Key: &azkeys.JSONWebKey{
		Kty: ptr(azkeys.KeyTypeRSA),
		N:   rsaKey.PublicKey.N.Bytes(),
		E:   big.NewInt(int64(rsaKey.PublicKey.E)).Bytes(),
	}}

	keyData, err := azureKeyDataFromBundle(bundle, "https://vault.test", "rsa-key")
	if err != nil {
		t.Fatalf("azureKeyDataFromBundle() error = %v", err)
	}
	if keyData.PublicKey == "" {
		t.Fatal("azureKeyDataFromBundle() returned empty RSA public key")
	}
}

// TestEcdhPublicKeyFromAzureBundleErrors covers the error branches of
// ecdhPublicKeyFromAzureBundle that the happy-path test does not reach.
func TestEcdhPublicKeyFromAzureBundleErrors(t *testing.T) {
	tests := []struct {
		name   string
		bundle azkeys.KeyBundle
	}{
		{
			name: "unsupported curve",
			bundle: azkeys.KeyBundle{Key: &azkeys.JSONWebKey{
				Crv: ptr(azkeys.CurveName("P-111")),
				X:   []byte{0x01},
				Y:   []byte{0x02},
			}},
		},
		{
			name: "coordinate too long",
			bundle: azkeys.KeyBundle{Key: &azkeys.JSONWebKey{
				Crv: ptr(azkeys.CurveNameP256),
				X:   make([]byte, 33),
				Y:   make([]byte, 33),
			}},
		},
		{
			name: "invalid point",
			bundle: azkeys.KeyBundle{Key: &azkeys.JSONWebKey{
				Crv: ptr(azkeys.CurveNameP256),
				X:   make([]byte, 32),
				Y:   make([]byte, 32),
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ecdhPublicKeyFromAzureBundle(test.bundle); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
