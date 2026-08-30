// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/local"
	"github.com/PointerByte/forge-go/encrypt/models"
	"github.com/PointerByte/forge-go/encrypt/utilities"
)

// rsaObjectFake serves an RSA public key from the token for the given handle.
func rsaObjectFake(t *testing.T, key *rsa.PrivateKey) *fakeModule {
	t.Helper()
	return &fakeModule{
		getAttributesFn: func(_ sessionHandle, _ objectHandle, types []attributeType) ([]attribute, error) {
			return rsaAttributes(key, types), nil
		},
	}
}

func rsaAttributes(key *rsa.PrivateKey, types []attributeType) []attribute {
	all := map[attributeType]attribute{
		ckaKeyType:     newULongAttribute(ckaKeyType, uint64(ckkRSA)),
		ckaModulus:     newBytesAttribute(ckaModulus, key.N.Bytes()),
		ckaPublicExpon: newBytesAttribute(ckaPublicExpon, big.NewInt(int64(key.E)).Bytes()),
	}
	return selectAttributes(all, types)
}

func selectAttributes(all map[attributeType]attribute, types []attributeType) []attribute {
	result := make([]attribute, 0, len(types))
	for _, kind := range types {
		if attr, ok := all[kind]; ok {
			result = append(result, attr)
			continue
		}
		result = append(result, attribute{Type: kind, Present: false})
	}
	return result
}

func TestGenerateRSAKeys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	var publicTemplate, privateTemplate []attribute
	fake := rsaObjectFake(t, key)
	fake.generateKeyPairFn = func(_ sessionHandle, mech mechanism, public, private []attribute) (objectHandle, objectHandle, error) {
		if mech != ckmRSAPKCSKeyPairGen {
			t.Errorf("mechanism = %v, want CKM_RSA_PKCS_KEY_PAIR_GEN", mech)
		}
		publicTemplate, privateTemplate = public, private
		return 1, 2, nil
	}
	installFake(t, fake)

	repository := NewAsymmetricRepository(testOptions()...)
	data, err := repository.GenerateRSAKeys(context.Background(), models.GenerateRSAKeyRequest{
		UID:  "svc",
		Size: common.Key2048Bits,
	})
	if err != nil {
		t.Fatalf("GenerateRSAKeys() error = %v", err)
	}

	parsed, err := utilities.ParseRSAPublicKeyFromBase64(data.PublicKey)
	if err != nil {
		t.Fatalf("the returned public key is not parseable: %v", err)
	}
	if parsed.N.Cmp(key.N) != 0 {
		t.Fatal("the returned public key does not match the token key")
	}

	// The private half must be sensitive and non-extractable: that is the
	// entire reason for putting the key in an HSM.
	assertBoolAttribute(t, privateTemplate, ckaSensitive, true)
	assertBoolAttribute(t, privateTemplate, ckaExtractable, false)
	assertBoolAttribute(t, privateTemplate, ckaSign, true)
	assertBoolAttribute(t, publicTemplate, ckaVerify, true)

	exponent, ok := findAttribute(publicTemplate, ckaPublicExpon)
	if !ok || len(exponent) != 3 || exponent[0] != 0x01 || exponent[2] != 0x01 {
		t.Fatalf("CKA_PUBLIC_EXPONENT = %x, want big-endian 65537", exponent)
	}
	bits, _ := findAttribute(publicTemplate, ckaModulusBits)
	decoded, _ := uLongValue(bits)
	if decoded != 2048 {
		t.Fatalf("CKA_MODULUS_BITS = %d, want 2048", decoded)
	}
}

func TestGenerateRSAKeysRejectsUnsupportedSize(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewAsymmetricRepository(testOptions()...)

	if _, err := repository.GenerateRSAKeys(context.Background(), models.GenerateRSAKeyRequest{
		Size: common.SizeAsymetrycKey(1024),
	}); err == nil {
		t.Fatal("expected an error for an unsupported key size")
	}
}

func TestGenerateECDHCurveKeys(t *testing.T) {
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	params, _ := asn1.Marshal(oidP256)

	fake := &fakeModule{
		generateKeyPairFn: func(_ sessionHandle, mech mechanism, _, privateTemplate []attribute) (objectHandle, objectHandle, error) {
			if mech != ckmECKeyPairGen {
				t.Errorf("mechanism = %v, want CKM_EC_KEY_PAIR_GEN", mech)
			}
			assertBoolAttribute(t, privateTemplate, ckaDerive, true)
			return 1, 2, nil
		},
		getAttributesFn: func(sessionHandle, objectHandle, []attributeType) ([]attribute, error) {
			return []attribute{
				newBytesAttribute(ckaECPoint, private.PublicKey().Bytes()),
				newBytesAttribute(ckaECParams, params),
			}, nil
		},
	}
	installFake(t, fake)

	repository := NewAsymmetricRepository(testOptions()...)
	data, err := repository.GenerateECDHCurveKeys(context.Background(), models.GenerateECDHCurveKeyRequest{
		Curve: common.CurveP256,
	})
	if err != nil {
		t.Fatalf("GenerateECDHCurveKeys() error = %v", err)
	}

	parsed, err := utilities.ParseECDHPublicKeyFromBase64(data.PublicKey)
	if err != nil {
		t.Fatalf("the returned public key is not parseable: %v", err)
	}
	if !parsed.Equal(private.PublicKey()) {
		t.Fatal("the returned public key does not match")
	}
}

func TestGenerateECDHCurveKeysRejectsUnsupportedCurve(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewAsymmetricRepository(testOptions()...)

	if _, err := repository.GenerateECDHCurveKeys(context.Background(), models.GenerateECDHCurveKeyRequest{
		Curve: common.CurveAsymmetricKey(1),
	}); err == nil {
		t.Fatal("expected an error for an unsupported curve")
	}
}

// TestRSAOAEPEncodeUsesTokenPublicKeyLocally pins the design decision that
// encryption never touches the token's private side: the public key is fetched
// and the operation completes locally, which keeps the format identical to the
// other backends.
func TestRSAOAEPEncodeUsesTokenPublicKeyLocally(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	installFake(t, rsaObjectFake(t, key))

	repository := NewAsymmetricRepository(testOptions()...)
	ciphertext, err := repository.RSA_OAEP_Encode(context.Background(), models.RSAOAEPEncodeRequest{
		PublicKey: "pkcs11:object=rsa-key;type=public",
		Text:      "secret payload",
	})
	if err != nil {
		t.Fatalf("RSA_OAEP_Encode() error = %v", err)
	}

	// The local backend holding the matching private key must be able to read
	// it, which proves the parameters match.
	encodedPrivate, err := marshalPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	plaintext, err := local.NewAsymmetricRepository().RSA_OAEP_Decode(context.Background(), models.RSAOAEPDecodeRequest{
		PrivateKey: encodedPrivate,
		CipherText: ciphertext,
	})
	if err != nil {
		t.Fatalf("local RSA_OAEP_Decode() error = %v", err)
	}
	if plaintext != "secret payload" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestRSAOAEPDecodeOnToken(t *testing.T) {
	fake := &fakeModule{
		decryptFn: func(_ sessionHandle, mech mechanism, params mechanismParams, _ objectHandle, ciphertext []byte) ([]byte, error) {
			if mech != ckmRSAPKCSOAEP {
				t.Errorf("mechanism = %v, want CKM_RSA_PKCS_OAEP", mech)
			}
			oaep, ok := params.(oaepParams)
			if !ok {
				t.Fatalf("params = %T, want oaepParams", params)
			}
			// SHA-256 with MGF1-SHA256 is what the local backend uses, so the
			// two are interchangeable.
			if oaep.HashAlg != ckmSHA256 || oaep.MGF != ckgMGF1SHA256 {
				t.Fatalf("params = %+v, want SHA-256 with MGF1-SHA256", oaep)
			}
			return []byte("decrypted"), nil
		},
	}
	installFake(t, fake)

	repository := NewAsymmetricRepository(testOptions()...)
	got, err := repository.RSA_OAEP_Decode(context.Background(), models.RSAOAEPDecodeRequest{
		PrivateKey: "pkcs11:object=rsa-key;type=private",
		CipherText: "AQID",
	})
	if err != nil {
		t.Fatalf("RSA_OAEP_Decode() error = %v", err)
	}
	if got != "decrypted" {
		t.Fatalf("RSA_OAEP_Decode() = %q", got)
	}
}

func TestRSAOAEPDecodeRejectsBadBase64(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewAsymmetricRepository(testOptions()...)

	if _, err := repository.RSA_OAEP_Decode(context.Background(), models.RSAOAEPDecodeRequest{
		PrivateKey: "pkcs11:object=k",
		CipherText: "!!!",
	}); err == nil {
		t.Fatal("expected an error for a ciphertext that is not base64")
	}
}

func TestAsymmetricFallsBackToLocal(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewAsymmetricRepository(testOptions()...)
	ctx := context.Background()

	// The public key is encoded as PKIX here rather than taken from
	// local.GenerateRSAKeys, which emits PKCS#1: utilities only parses PKIX, so
	// PKCS#1 input would not be recognised as local material by any backend.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	encodedPublic, err := marshalPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	encodedPrivate, err := marshalPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	ciphertext, err := repository.RSA_OAEP_Encode(ctx, models.RSAOAEPEncodeRequest{
		PublicKey: encodedPublic,
		Text:      "local path",
	})
	if err != nil {
		t.Fatalf("RSA_OAEP_Encode() error = %v", err)
	}
	plaintext, err := repository.RSA_OAEP_Decode(ctx, models.RSAOAEPDecodeRequest{
		PrivateKey: encodedPrivate,
		CipherText: ciphertext,
	})
	if err != nil {
		t.Fatalf("RSA_OAEP_Decode() error = %v", err)
	}
	if plaintext != "local path" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestECDHEncodeFallsBackToLocalAndUsesTokenPublicKey(t *testing.T) {
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	params, _ := asn1.Marshal(oidP256)

	fake := &fakeModule{
		getAttributesFn: func(_ sessionHandle, _ objectHandle, types []attributeType) ([]attribute, error) {
			all := map[attributeType]attribute{
				ckaKeyType:  newULongAttribute(ckaKeyType, uint64(ckkEC)),
				ckaECPoint:  newBytesAttribute(ckaECPoint, private.PublicKey().Bytes()),
				ckaECParams: newBytesAttribute(ckaECParams, params),
			}
			return selectAttributes(all, types), nil
		},
	}
	installFake(t, fake)

	repository := NewAsymmetricRepository(testOptions()...)
	payload, err := repository.ECDH_Encode(context.Background(), models.ECDHEncodeRequest{
		PublicKey: "pkcs11:object=ecdh-key;type=public",
		Text:      "envelope",
	})
	if err != nil {
		t.Fatalf("ECDH_Encode() error = %v", err)
	}

	// The payload must be readable by the local backend holding the private
	// key, which proves the shared envelope format is preserved.
	encodedPrivate, err := marshalECDHPrivateKey(private)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	plaintext, err := local.NewAsymmetricRepository().ECDH_Decode(context.Background(), models.ECDHDecodeRequest{
		PrivateKey: encodedPrivate,
		CipherText: payload,
	})
	if err != nil {
		t.Fatalf("local ECDH_Decode() error = %v", err)
	}
	if plaintext != "envelope" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestAsymmetricRequiresKeyReference(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewAsymmetricRepository(testOptions()...)
	ctx := context.Background()

	if _, err := repository.RSA_OAEP_Encode(ctx, models.RSAOAEPEncodeRequest{Text: "x"}); !errors.Is(err, ErrKeyURIRequired) {
		t.Fatalf("RSA_OAEP_Encode() = %v, want ErrKeyURIRequired", err)
	}
	if _, err := repository.RSA_OAEP_Decode(ctx, models.RSAOAEPDecodeRequest{CipherText: "AQID"}); !errors.Is(err, ErrKeyURIRequired) {
		t.Fatalf("RSA_OAEP_Decode() = %v, want ErrKeyURIRequired", err)
	}
	if _, err := repository.ECDH_Encode(ctx, models.ECDHEncodeRequest{Text: "x"}); !errors.Is(err, ErrKeyURIRequired) {
		t.Fatalf("ECDH_Encode() = %v, want ErrKeyURIRequired", err)
	}
}

// TestRSAOAEPDecodeSetsDataSpecifiedSource pins a parameter that is easy to
// leave zero and that strict tokens reject outright: CK_RSA_PKCS_OAEP_PARAMS
// requires CKZ_DATA_SPECIFIED even when no label is supplied.
func TestRSAOAEPDecodeSetsDataSpecifiedSource(t *testing.T) {
	var captured oaepParams
	installFake(t, &fakeModule{
		decryptFn: func(_ sessionHandle, _ mechanism, params mechanismParams, _ objectHandle, _ []byte) ([]byte, error) {
			captured = params.(oaepParams)
			return []byte("ok"), nil
		},
	})

	repository := NewAsymmetricRepository(testOptions()...)
	if _, err := repository.RSA_OAEP_Decode(context.Background(), models.RSAOAEPDecodeRequest{
		PrivateKey: "pkcs11:object=rsa;type=private",
		CipherText: "AQID",
	}); err != nil {
		t.Fatalf("RSA_OAEP_Decode() error = %v", err)
	}

	if captured.Source != ckzDataSpecified {
		t.Fatalf("Source = %d, want CKZ_DATA_SPECIFIED (%d)", captured.Source, ckzDataSpecified)
	}
	if captured.HashAlg != ckmSHA256 || captured.MGF != ckgMGF1SHA256 {
		t.Fatalf("params = %+v, want SHA-256 with MGF1-SHA256", captured)
	}
}

// TestRSAOAEPDecodeReportsHashRejection covers the token that advertises
// CKM_RSA_PKCS_OAEP but refuses the digest, which C_GetMechanismList cannot
// express. The parameters stay at SHA-256 on purpose: downgrading them would
// produce ciphertext the other backends cannot read.
func TestRSAOAEPDecodeReportsHashRejection(t *testing.T) {
	installFake(t, &fakeModule{
		decryptFn: func(sessionHandle, mechanism, mechanismParams, objectHandle, []byte) ([]byte, error) {
			return nil, newTokenError("C_DecryptInit", ckrArgumentsBad)
		},
	})

	repository := NewAsymmetricRepository(testOptions()...)
	_, err := repository.RSA_OAEP_Decode(context.Background(), models.RSAOAEPDecodeRequest{
		PrivateKey: "pkcs11:object=rsa;type=private",
		CipherText: "AQID",
	})
	if !errors.Is(err, ErrOAEPHashUnsupported) {
		t.Fatalf("RSA_OAEP_Decode() = %v, want ErrOAEPHashUnsupported", err)
	}
}
