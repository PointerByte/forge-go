// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build pkcs11 && cgo && !windows && pkcs11_integration

package pkcs11

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/local"
	"github.com/PointerByte/forge-go/encrypt/models"
)

// These tests need a real, writable PKCS#11 token. They are excluded from every
// normal build by the pkcs11_integration tag, because they mutate the token.
//
// To run them against SoftHSM2:
//
//	dnf install softhsm            # or apt install softhsm2
//	softhsm2-util --init-token --slot 0 --label forge-hsm --pin 1234 --so-pin 1234
//	FORGE_PKCS11_MODULE=/usr/lib64/softhsm/libsofthsm2.so \
//	FORGE_PKCS11_PIN=1234 \
//	go test -tags 'pkcs11 pkcs11_integration' ./pkcs11/... -v
//
// This is the only automated proof that the hand-written function table matches
// a real module for the operations the unit tests can only fake.

func integrationRepository(t *testing.T) *Repository {
	t.Helper()

	modulePath := os.Getenv("FORGE_PKCS11_MODULE")
	pin := os.Getenv("FORGE_PKCS11_PIN")
	if modulePath == "" || pin == "" {
		t.Skip("set FORGE_PKCS11_MODULE and FORGE_PKCS11_PIN to run integration tests")
	}

	label := os.Getenv("FORGE_PKCS11_TOKEN")
	if label == "" {
		label = "forge-hsm"
	}

	repository := NewRepository(
		WithModulePath(modulePath),
		WithTokenLabel(label),
		WithPinProvider(func(context.Context) (string, error) { return pin, nil }),
	)
	t.Cleanup(func() { _ = repository.Close() })
	return repository
}

// TestIntegrationSymmetricRoundTrip is the headline guarantee: a key generated
// on the token encrypts and decrypts, and the ciphertext is readable by the
// local backend only if the key material were known — which it is not, because
// the key is non-extractable.
func TestIntegrationSymmetricRoundTrip(t *testing.T) {
	repository := integrationRepository(t)
	ctx := context.Background()

	key, err := repository.GenerateSymetrycKeys(ctx, models.GenerateSymmetricKeyRequest{
		UID:  "integration",
		Size: common.Key256Bits,
	})
	if err != nil {
		t.Fatalf("GenerateSymetrycKeys() error = %v", err)
	}
	t.Logf("generated %s", key.KeyRef)

	const message = "hardware round trip"
	additional := "aad"
	ciphertext, err := repository.EncryptAES(ctx, models.EncryptAESRequest{
		SecretKey:  key.KeyRef,
		Value:      message,
		Additional: &additional,
	})
	if err != nil {
		t.Fatalf("EncryptAES() error = %v", err)
	}

	plaintext, err := repository.DecryptAES(ctx, models.DecryptAESRequest{
		SecretKey:   key.KeyRef,
		CipherValue: ciphertext,
		Additional:  &additional,
	})
	if err != nil {
		t.Fatalf("DecryptAES() error = %v", err)
	}
	if plaintext != message {
		t.Fatalf("plaintext = %q, want %q", plaintext, message)
	}
}

// TestIntegrationRSASignVerify proves an RSA private key that never leaves the
// token produces signatures the standard library verifies.
func TestIntegrationRSASignVerify(t *testing.T) {
	repository := integrationRepository(t)
	ctx := context.Background()

	key, err := repository.GenerateRSAKeys(ctx, models.GenerateRSAKeyRequest{
		UID:  "integration",
		Size: common.Key2048Bits,
	})
	if err != nil {
		t.Fatalf("GenerateRSAKeys() error = %v", err)
	}

	const payload = "sign in hardware"
	signature, err := repository.SignRSAPSS(ctx, key.KeyRef, payload)
	if err != nil {
		t.Fatalf("SignRSAPSS() error = %v", err)
	}
	// Verified with the exported public key through the local backend, so the
	// check does not depend on the token being correct twice.
	if err := local.NewSignatureRepository().VerifyRSAPSS(ctx, key.PublicKey, payload, signature); err != nil {
		t.Fatalf("local VerifyRSAPSS() rejected a token signature: %v", err)
	}

	pkcs1, err := repository.Sign_RSA_PKCS1v15_SHA256(ctx, key.KeyRef, payload)
	if err != nil {
		t.Fatalf("Sign_RSA_PKCS1v15_SHA256() error = %v", err)
	}
	if err := local.NewSignatureRepository().Verify_RSA_PKCS1v15_SHA256(ctx, payload, key.PublicKey, pkcs1); err != nil {
		t.Fatalf("local Verify_RSA_PKCS1v15_SHA256() rejected a token signature: %v", err)
	}
}

// TestIntegrationECDHInteroperability is the cross-backend property: a payload
// sealed by the local backend against the token's public key must open on the
// token, which is what proves the envelope format survived the HSM path.
func TestIntegrationECDHInteroperability(t *testing.T) {
	repository := integrationRepository(t)
	ctx := context.Background()

	key, err := repository.GenerateECDHCurveKeys(ctx, models.GenerateECDHCurveKeyRequest{
		UID:   "integration",
		Curve: common.CurveP256,
	})
	if err != nil {
		t.Fatalf("GenerateECDHCurveKeys() error = %v", err)
	}

	const message = "sealed to the token"
	payload, err := local.NewAsymmetricRepository().ECDH_Encode(ctx, models.ECDHEncodeRequest{
		PublicKey: key.PublicKey,
		Text:      message,
	})
	if err != nil {
		t.Fatalf("local ECDH_Encode() error = %v", err)
	}

	plaintext, err := repository.ECDH_Decode(ctx, models.ECDHDecodeRequest{
		PrivateKey: key.KeyRef,
		CipherText: payload,
	})
	if err != nil {
		t.Fatalf("ECDH_Decode() error = %v", err)
	}
	if plaintext != message {
		t.Fatalf("plaintext = %q, want %q", plaintext, message)
	}
}

// TestIntegrationRSAOAEPRoundTrip seals with the token public key and opens on
// the token.
func TestIntegrationRSAOAEPRoundTrip(t *testing.T) {
	repository := integrationRepository(t)
	ctx := context.Background()

	key, err := repository.GenerateRSAKeys(ctx, models.GenerateRSAKeyRequest{
		UID:  "integration-oaep",
		Size: common.Key2048Bits,
	})
	if err != nil {
		t.Fatalf("GenerateRSAKeys() error = %v", err)
	}

	const message = "oaep round trip"
	ciphertext, err := repository.RSA_OAEP_Encode(ctx, models.RSAOAEPEncodeRequest{
		PublicKey: key.KeyRef,
		Text:      message,
	})
	if err != nil {
		t.Fatalf("RSA_OAEP_Encode() error = %v", err)
	}
	plaintext, err := repository.RSA_OAEP_Decode(ctx, models.RSAOAEPDecodeRequest{
		PrivateKey: key.KeyRef,
		CipherText: ciphertext,
	})
	if errors.Is(err, ErrOAEPHashUnsupported) {
		// SoftHSM2 hardcodes OAEP to SHA-1, so it cannot run this path. The
		// parameters stay at SHA-256 deliberately: downgrading them would
		// produce ciphertext the other backends cannot read.
		t.Skipf("token does not support RSA-OAEP with SHA-256: %v", err)
	}
	if err != nil {
		t.Fatalf("RSA_OAEP_Decode() error = %v", err)
	}
	if plaintext != message {
		t.Fatalf("plaintext = %q, want %q", plaintext, message)
	}
}

// TestIntegrationEd25519 exercises the pure EdDSA path, including the retry for
// tokens that reject a NULL parameter block.
func TestIntegrationEd25519(t *testing.T) {
	repository := integrationRepository(t)
	ctx := context.Background()

	key, err := repository.GenerateEd255Keys(ctx)
	if err != nil {
		t.Skipf("token cannot generate Ed25519 keys: %v", err)
	}

	const payload = "ed25519 in hardware"
	signature, err := repository.SignEd25519(ctx, key.KeyRef, payload)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}
	if err := local.NewSignatureRepository().VerifyEd25519(ctx, key.PublicKey, payload, signature); err != nil {
		t.Fatalf("local VerifyEd25519() rejected a token signature: %v", err)
	}
	// Verifying through the token path must agree with the local one.
	if err := repository.VerifyEd25519(ctx, key.KeyRef, payload, signature); err != nil {
		t.Fatalf("VerifyEd25519() error = %v", err)
	}
}

// TestIntegrationHMAC checks the token-side MAC path.
//
// CKM_SHA256_HMAC needs a CKK_GENERIC_SECRET key with CKA_SIGN, which is not
// what GenerateSymetrycKeys produces: that makes a CKK_AES key for EncryptAES,
// and most tokens refuse to MAC with it. HMAC keys are provisioned separately,
// the same way the AWS backend needs a KMS HMAC key rather than an encryption
// key. The test provisions one so the path is exercised against real hardware.
func TestIntegrationHMAC(t *testing.T) {
	repository := integrationRepository(t)
	ctx := context.Background()

	key, err := provisionHMACKey(t, ctx)
	if err != nil {
		t.Skipf("token cannot create a generic secret key: %v", err)
	}

	mac := repository.HMAC(ctx, key, "message")
	if mac == "" {
		t.Fatal("HMAC() returned empty for a provisioned generic secret key")
	}
	// The same key and message must be stable across calls.
	if again := repository.HMAC(ctx, key, "message"); again != mac {
		t.Fatal("HMAC() is not deterministic for the same key and message")
	}
	if other := repository.HMAC(ctx, key, "different"); other == mac {
		t.Fatal("HMAC() returned the same value for different messages")
	}
}

// provisionHMACKey creates the CKK_GENERIC_SECRET key CKM_SHA256_HMAC requires
// and returns its URI.
func provisionHMACKey(t *testing.T, ctx context.Context) (string, error) {
	t.Helper()

	backend := newBackend(
		WithModulePath(os.Getenv("FORGE_PKCS11_MODULE")),
		WithTokenLabel(tokenLabel()),
		WithPinProvider(func(context.Context) (string, error) { return os.Getenv("FORGE_PKCS11_PIN"), nil }),
	)

	id, err := newObjectID()
	if err != nil {
		return "", err
	}
	label := newObjectLabel(hmacKeyPrefix, "integration")

	err = backend.withSession(ctx, func(mod module, slot *slotState, session sessionHandle) error {
		if err := slot.requireMechanism(ckmGenericSecretKeyGe); err != nil {
			return err
		}
		template := append(tokenKeyTemplate(label, id),
			newULongAttribute(ckaClass, uint64(classSecretKey)),
			newULongAttribute(ckaKeyType, uint64(ckkGenericSecret)),
			newULongAttribute(ckaValueLen, uint64(common.Key256Bits)),
			newBoolAttribute(ckaSign, true),
			newBoolAttribute(ckaVerify, true),
		)
		_, err := mod.GenerateKey(session, ckmGenericSecretKeyGe, template)
		return err
	})
	if err != nil {
		return "", err
	}

	uri := &keyURI{Object: label, ID: id, Class: classSecretKey, HasClass: true}
	return uri.String(), nil
}

// TestIntegrationKeysAreNotExtractable is the guarantee the whole package
// exists for: a generated private key must be unreadable, even to us.
func TestIntegrationKeysAreNotExtractable(t *testing.T) {
	repository := integrationRepository(t)
	ctx := context.Background()

	generated, err := repository.GenerateRSAKeys(ctx, models.GenerateRSAKeyRequest{
		UID:  "integration-sensitive",
		Size: common.Key2048Bits,
	})
	if err != nil {
		t.Fatalf("GenerateRSAKeys() error = %v", err)
	}

	uri, err := parseKeyURI(generated.KeyRef)
	if err != nil {
		t.Fatalf("parseKeyURI() error = %v", err)
	}

	backend := newBackend(
		WithModulePath(os.Getenv("FORGE_PKCS11_MODULE")),
		WithTokenLabel(tokenLabel()),
		WithPinProvider(func(context.Context) (string, error) { return os.Getenv("FORGE_PKCS11_PIN"), nil }),
	)

	err = backend.withSession(ctx, func(mod module, _ *slotState, session sessionHandle) error {
		handle, err := resolveObject(mod, session, uri, classPrivateKey)
		if err != nil {
			return err
		}
		attributes, err := mod.GetAttributes(session, handle, []attributeType{
			ckaSensitive, ckaExtractable, ckaPrivateExponent,
		})
		if err != nil {
			return err
		}

		sensitive, ok := findAttribute(attributes, ckaSensitive)
		if !ok {
			t.Error("the private key has no CKA_SENSITIVE")
		} else if value, _ := boolValue(sensitive); !value {
			t.Error("CKA_SENSITIVE is false; the key material could be read")
		}

		extractable, ok := findAttribute(attributes, ckaExtractable)
		if !ok {
			t.Error("the private key has no CKA_EXTRACTABLE")
		} else if value, _ := boolValue(extractable); value {
			t.Error("CKA_EXTRACTABLE is true; the key could leave the token")
		}

		// The actual secret must come back absent or empty, never as bytes.
		if raw, ok := findAttribute(attributes, ckaPrivateExponent); ok && len(raw) > 0 {
			t.Errorf("the token returned %d bytes of private key material", len(raw))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("attribute inspection error = %v", err)
	}
}

func tokenLabel() string {
	if label := os.Getenv("FORGE_PKCS11_TOKEN"); label != "" {
		return label
	}
	return "forge-hsm"
}

// TestIntegrationRotateAndDeactivate walks the key-management path end to end.
func TestIntegrationRotateAndDeactivate(t *testing.T) {
	repository := integrationRepository(t)
	ctx := context.Background()

	original, err := repository.GenerateSymetrycKeys(ctx, models.GenerateSymmetricKeyRequest{
		UID:  "integration-rotate",
		Size: common.Key256Bits,
	})
	if err != nil {
		t.Fatalf("GenerateSymetrycKeys() error = %v", err)
	}

	rotated, err := repository.RotateKey(ctx, models.RotateKeyRequest{KeyID: original.KeyRef})
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	if rotated.KeyRef == original.KeyRef {
		t.Fatal("RotateKey() returned the same reference; rotation creates a new object")
	}

	// Rotation is non-destructive by default, so the old key must still work.
	ciphertext, err := repository.EncryptAES(ctx, models.EncryptAESRequest{
		SecretKey: original.KeyRef,
		Value:     "still readable",
	})
	if err != nil {
		t.Fatalf("the previous key stopped working after rotation: %v", err)
	}
	if _, err := repository.DecryptAES(ctx, models.DecryptAESRequest{
		SecretKey:   original.KeyRef,
		CipherValue: ciphertext,
	}); err != nil {
		t.Fatalf("DecryptAES() with the previous key error = %v", err)
	}

	if err := repository.DeactivateKey(ctx, models.DeactivateKeyRequest{KeyID: original.KeyRef}); err != nil {
		t.Fatalf("DeactivateKey() error = %v", err)
	}
	// After deactivation the key must refuse to encrypt.
	if _, err := repository.EncryptAES(ctx, models.EncryptAESRequest{
		SecretKey: original.KeyRef,
		Value:     "should fail",
	}); err == nil {
		t.Fatal("EncryptAES() succeeded with a deactivated key")
	}
}

// TestIntegrationECDHReportsPath makes explicit which of the two ECDH paths the
// token can run, so a passing suite is not mistaken for proof that the
// in-hardware path works here.
func TestIntegrationECDHReportsPath(t *testing.T) {
	repository := integrationRepository(t)
	ctx := context.Background()

	backend := newBackend(
		WithModulePath(os.Getenv("FORGE_PKCS11_MODULE")),
		WithTokenLabel(tokenLabel()),
		WithPinProvider(func(context.Context) (string, error) { return os.Getenv("FORGE_PKCS11_PIN"), nil }),
	)

	var inHardware bool
	if err := backend.withSession(ctx, func(_ module, slot *slotState, _ sessionHandle) error {
		inHardware = supportsInHardwareECDH(slot)
		return nil
	}); err != nil {
		t.Fatalf("withSession() error = %v", err)
	}

	if !inHardware {
		t.Logf("token lacks CKM_HKDF_DERIVE: ECDH_Decode uses the extraction fallback here, "+
			"so the in-hardware path is NOT covered by this run (module %s)",
			os.Getenv("FORGE_PKCS11_MODULE"))
	} else {
		t.Log("token supports CKM_HKDF_DERIVE: ECDH_Decode keeps the secret inside the token")
	}

	_ = repository
}

// TestIntegrationGetKey checks the metadata path against a real token.
func TestIntegrationGetKey(t *testing.T) {
	repository := integrationRepository(t)
	ctx := context.Background()

	generated, err := repository.GenerateRSAKeys(ctx, models.GenerateRSAKeyRequest{
		UID:  "integration-getkey",
		Size: common.Key2048Bits,
	})
	if err != nil {
		t.Fatalf("GenerateRSAKeys() error = %v", err)
	}

	fetched, err := repository.GetKey(ctx, models.GetKeyRequest{KeyID: generated.KeyRef})
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}
	if fetched.PublicKey != generated.PublicKey {
		t.Fatal("GetKey() returned a different public key than generation did")
	}
}
