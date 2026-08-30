// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/PointerByte/forge-go/encrypt/local"
	"github.com/PointerByte/forge-go/encrypt/models"
	"github.com/PointerByte/forge-go/encrypt/utilities"
)

// ecdhFixture builds a payload with the shared envelope format plus the token
// private key it was addressed to.
type ecdhFixture struct {
	private *ecdh.PrivateKey
	payload string
	curve   string
	secret  []byte
	message string
}

func newECDHFixture(t *testing.T) ecdhFixture {
	t.Helper()

	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	encodedPublic, err := marshalPublicKey(private.PublicKey())
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	const message = "hardware envelope"
	payload, err := local.NewAsymmetricRepository().ECDH_Encode(context.Background(), models.ECDHEncodeRequest{
		PublicKey: encodedPublic,
		Text:      message,
	})
	if err != nil {
		t.Fatalf("local ECDH_Encode() error = %v", err)
	}

	decoded, err := utilities.DecodeECCCipherPayload(payload)
	if err != nil {
		t.Fatalf("DecodeECCCipherPayload() error = %v", err)
	}
	ephemeral, err := utilities.ParseECDHPublicKeyFromBase64(decoded.EphemeralPublicKey)
	if err != nil {
		t.Fatalf("parse ephemeral key: %v", err)
	}
	secret, err := private.ECDH(ephemeral)
	if err != nil {
		t.Fatalf("ECDH() error = %v", err)
	}

	return ecdhFixture{private: private, payload: payload, curve: decoded.Curve, secret: secret, message: message}
}

// TestECDHDecodeInHardware covers the preferred path: the shared secret and the
// AES key are derived inside the token and never cross the boundary, yet the
// payload format stays byte-compatible with the local backend.
func TestECDHDecodeInHardware(t *testing.T) {
	fixture := newECDHFixture(t)

	var derivedMechanisms []mechanism
	var hkdfInfo []byte
	var destroyed int

	fake := &fakeModule{
		deriveKeyFn: func(_ sessionHandle, mech mechanism, params mechanismParams, _ objectHandle, template []attribute) (objectHandle, error) {
			derivedMechanisms = append(derivedMechanisms, mech)
			switch mech {
			case ckmECDH1Derive:
				ecdhParams := params.(ecdh1Params)
				if ecdhParams.KDF != ckdNULL {
					t.Errorf("KDF = %d, want CKD_NULL", ecdhParams.KDF)
				}
				// The derived secret must be non-extractable on this path.
				assertBoolAttribute(t, template, ckaExtractable, false)
				assertBoolAttribute(t, template, ckaSensitive, true)
				return 100, nil
			case ckmHKDFDerive:
				hkdf := params.(hkdfParams)
				if !hkdf.Extract || !hkdf.Expand {
					t.Error("HKDF must both extract and expand")
				}
				if hkdf.SaltType != ckfHKDFSaltNull {
					t.Errorf("SaltType = %d, want CKF_HKDF_SALT_NULL", hkdf.SaltType)
				}
				hkdfInfo = hkdf.Info
				assertBoolAttribute(t, template, ckaExtractable, false)
				return 101, nil
			}
			return 0, errors.New("unexpected mechanism")
		},
		destroyObjectFn: func(sessionHandle, objectHandle) error {
			destroyed++
			return nil
		},
		decryptFn: func(_ sessionHandle, mech mechanism, params mechanismParams, key objectHandle, ciphertext []byte) ([]byte, error) {
			if mech != ckmAESGCM || key != 101 {
				t.Errorf("decrypt used mechanism %v with key %d", mech, key)
			}
			gcm := params.(gcmParams)
			// Emulate the token: derive the same key HKDF would have produced.
			derived, err := utilities.DeriveECCAESKey(fixture.secret, fixture.curve)
			if err != nil {
				return nil, err
			}
			block, _ := aes.NewCipher(derived)
			aead, _ := cipher.NewGCM(block)
			return aead.Open(nil, gcm.IV, ciphertext, gcm.AAD)
		},
	}
	installFake(t, fake)

	repository := NewAsymmetricRepository(testOptions()...)
	plaintext, err := repository.ECDH_Decode(context.Background(), models.ECDHDecodeRequest{
		PrivateKey: "pkcs11:object=ecdh-key;type=private",
		CipherText: fixture.payload,
	})
	if err != nil {
		t.Fatalf("ECDH_Decode() error = %v", err)
	}
	if plaintext != fixture.message {
		t.Fatalf("plaintext = %q, want %q", plaintext, fixture.message)
	}

	if len(derivedMechanisms) != 2 || derivedMechanisms[0] != ckmECDH1Derive || derivedMechanisms[1] != ckmHKDFDerive {
		t.Fatalf("derive sequence = %v, want ECDH1 then HKDF", derivedMechanisms)
	}
	// The HKDF info must match what utilities computes, or the derived key
	// would differ from the local backend's.
	wantInfo := eccHKDFInfoPrefix + fixture.curve
	if string(hkdfInfo) != wantInfo {
		t.Fatalf("HKDF info = %q, want %q", hkdfInfo, wantInfo)
	}
	if destroyed != 2 {
		t.Fatalf("destroyed %d intermediate objects, want both cleaned up", destroyed)
	}
}

// TestECDHDecodeExtractionFallback covers tokens without CKM_HKDF_DERIVE, where
// the ephemeral shared secret is read out and the derivation finishes locally,
// exactly as the aws-kms and azure backends do.
func TestECDHDecodeExtractionFallback(t *testing.T) {
	fixture := newECDHFixture(t)

	fake := &fakeModule{
		mechanismsFn: func(uint64) ([]mechanism, error) {
			return []mechanism{ckmECDH1Derive, ckmAESGCM}, nil
		},
		deriveKeyFn: func(_ sessionHandle, mech mechanism, _ mechanismParams, _ objectHandle, template []attribute) (objectHandle, error) {
			if mech != ckmECDH1Derive {
				t.Errorf("mechanism = %v, want CKM_ECDH1_DERIVE", mech)
			}
			// This path must ask for an extractable secret explicitly.
			assertBoolAttribute(t, template, ckaExtractable, true)
			assertBoolAttribute(t, template, ckaSensitive, false)
			return 200, nil
		},
		getAttributesFn: func(sessionHandle, objectHandle, []attributeType) ([]attribute, error) {
			return []attribute{newBytesAttribute(ckaValue, fixture.secret)}, nil
		},
	}
	installFake(t, fake)

	repository := NewAsymmetricRepository(testOptions()...)
	plaintext, err := repository.ECDH_Decode(context.Background(), models.ECDHDecodeRequest{
		PrivateKey: "pkcs11:object=ecdh-key;type=private",
		CipherText: fixture.payload,
	})
	if err != nil {
		t.Fatalf("ECDH_Decode() error = %v", err)
	}
	if plaintext != fixture.message {
		t.Fatalf("plaintext = %q, want %q", plaintext, fixture.message)
	}
}

// TestECDHDecodeRefusesExtractionWhenDisabled pins the security option: a token
// whose policy must keep everything inside fails loudly instead of silently
// exporting the derived secret.
func TestECDHDecodeRefusesExtractionWhenDisabled(t *testing.T) {
	fixture := newECDHFixture(t)

	installFake(t, &fakeModule{
		mechanismsFn: func(uint64) ([]mechanism, error) {
			return []mechanism{ckmECDH1Derive, ckmAESGCM}, nil
		},
	})

	repository := NewAsymmetricRepository(testOptions(WithAllowSecretExtraction(false))...)
	_, err := repository.ECDH_Decode(context.Background(), models.ECDHDecodeRequest{
		PrivateKey: "pkcs11:object=ecdh-key;type=private",
		CipherText: fixture.payload,
	})
	if !errors.Is(err, ErrSecretNotExtractable) {
		t.Fatalf("ECDH_Decode() = %v, want ErrSecretNotExtractable", err)
	}
}

func TestECDHDecodeReportsSensitiveSecret(t *testing.T) {
	fixture := newECDHFixture(t)

	installFake(t, &fakeModule{
		mechanismsFn: func(uint64) ([]mechanism, error) {
			return []mechanism{ckmECDH1Derive, ckmAESGCM}, nil
		},
		deriveKeyFn: func(sessionHandle, mechanism, mechanismParams, objectHandle, []attribute) (objectHandle, error) {
			return 0, newTokenError("C_DeriveKey", ckrAttributeSensitive)
		},
	})

	repository := NewAsymmetricRepository(testOptions()...)
	_, err := repository.ECDH_Decode(context.Background(), models.ECDHDecodeRequest{
		PrivateKey: "pkcs11:object=ecdh-key;type=private",
		CipherText: fixture.payload,
	})
	if !errors.Is(err, ErrSecretNotExtractable) {
		t.Fatalf("ECDH_Decode() = %v, want it to map to ErrSecretNotExtractable", err)
	}
}

func TestECDHDecodeFallsBackToLocal(t *testing.T) {
	fixture := newECDHFixture(t)
	installFake(t, &fakeModule{})

	encodedPrivate, err := marshalECDHPrivateKey(fixture.private)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	repository := NewAsymmetricRepository(testOptions()...)
	plaintext, err := repository.ECDH_Decode(context.Background(), models.ECDHDecodeRequest{
		PrivateKey: encodedPrivate,
		CipherText: fixture.payload,
	})
	if err != nil {
		t.Fatalf("ECDH_Decode() error = %v", err)
	}
	if plaintext != fixture.message {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestECDHDecodeRejectsMalformedPayloads(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewAsymmetricRepository(testOptions()...)

	badCiphertext, err := utilities.EncodeECCCipherPayload(utilities.ECCCipherPayload{
		Curve:              "P-256",
		EphemeralPublicKey: base64.StdEncoding.EncodeToString([]byte("not a key")),
		Ciphertext:         "AQID",
	})
	if err != nil {
		t.Fatalf("EncodeECCCipherPayload() error = %v", err)
	}

	tests := []struct {
		name    string
		payload string
	}{
		{name: "not a payload", payload: "!!!"},
		{name: "bad ephemeral key", payload: badCiphertext},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := repository.ECDH_Decode(context.Background(), models.ECDHDecodeRequest{
				PrivateKey: "pkcs11:object=k;type=private",
				CipherText: test.payload,
			}); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestECDHDecodeRequiresMechanism(t *testing.T) {
	fixture := newECDHFixture(t)
	installFake(t, &fakeModule{
		mechanismsFn: func(uint64) ([]mechanism, error) { return []mechanism{ckmAESGCM}, nil },
	})

	repository := NewAsymmetricRepository(testOptions()...)
	_, err := repository.ECDH_Decode(context.Background(), models.ECDHDecodeRequest{
		PrivateKey: "pkcs11:object=k;type=private",
		CipherText: fixture.payload,
	})
	var unsupported unsupportedMechanismError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error = %v, want unsupportedMechanismError", err)
	}
}
