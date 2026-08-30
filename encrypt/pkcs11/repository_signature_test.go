// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/PointerByte/forge-go/encrypt/local"
	"github.com/PointerByte/forge-go/encrypt/utilities"
)

func TestGenerateEd255Keys(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	var privateTemplate, publicTemplate []attribute
	fake := &fakeModule{
		generateKeyPairFn: func(_ sessionHandle, mech mechanism, pub, priv []attribute) (objectHandle, objectHandle, error) {
			if mech != ckmECEdwardsKeyPairGe {
				t.Errorf("mechanism = %v, want CKM_EC_EDWARDS_KEY_PAIR_GEN", mech)
			}
			publicTemplate, privateTemplate = pub, priv
			return 1, 2, nil
		},
		getAttributesFn: func(sessionHandle, objectHandle, []attributeType) ([]attribute, error) {
			return []attribute{newBytesAttribute(ckaECPoint, public)}, nil
		},
	}
	installFake(t, fake)

	repository := NewSignatureRepository(testOptions()...)
	data, err := repository.GenerateEd255Keys(context.Background())
	if err != nil {
		t.Fatalf("GenerateEd255Keys() error = %v", err)
	}

	parsed, err := utilities.ParseEd25519PublicKeyFromBase64(data.PublicKey)
	if err != nil {
		t.Fatalf("the returned public key is not parseable: %v", err)
	}
	if !parsed.Equal(public) {
		t.Fatal("the returned public key does not match the token key")
	}

	assertBoolAttribute(t, privateTemplate, ckaSign, true)
	assertBoolAttribute(t, privateTemplate, ckaExtractable, false)
	assertBoolAttribute(t, publicTemplate, ckaVerify, true)

	params, ok := findAttribute(publicTemplate, ckaECParams)
	if !ok {
		t.Fatal("public template has no CKA_EC_PARAMS")
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(params, &oid); err != nil || !oid.Equal(oidEd25519) {
		t.Fatalf("CKA_EC_PARAMS oid = %v, want %v", oid, oidEd25519)
	}
}

func TestGenerateEd255KeysRequiresMechanism(t *testing.T) {
	installFake(t, &fakeModule{
		mechanismsFn: func(uint64) ([]mechanism, error) { return []mechanism{ckmAESGCM}, nil },
	})
	repository := NewSignatureRepository(testOptions()...)

	_, err := repository.GenerateEd255Keys(context.Background())
	var unsupported unsupportedMechanismError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error = %v, want unsupportedMechanismError", err)
	}
}

// TestSignEd25519OnToken checks the two things that matter: the pure EdDSA
// mechanism is used, and the message reaches it unhashed.
func TestSignEd25519OnToken(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	const message = "sign this"

	fake := &fakeModule{
		signFn: func(_ sessionHandle, mech mechanism, _ mechanismParams, _ objectHandle, payload []byte) ([]byte, error) {
			if mech != ckmEdDSA {
				t.Errorf("mechanism = %v, want CKM_EDDSA", mech)
			}
			if string(payload) != message {
				t.Errorf("payload = %q, want the raw message", payload)
			}
			return ed25519.Sign(private, payload), nil
		},
	}
	installFake(t, fake)

	repository := NewSignatureRepository(testOptions()...)
	signature, err := repository.SignEd25519(context.Background(), "pkcs11:object=ed;type=private", message)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}

	// The signature must verify with the plain standard library, proving the
	// token path produces a normal Ed25519 signature.
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	if !ed25519.Verify(public, []byte(message), raw) {
		t.Fatal("the produced signature does not verify")
	}
}

func TestVerifyEd25519FetchesTokenPublicKey(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	const message = "verify this"
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte(message)))

	fake := &fakeModule{
		getAttributesFn: func(_ sessionHandle, _ objectHandle, types []attributeType) ([]attribute, error) {
			all := map[attributeType]attribute{
				ckaKeyType: newULongAttribute(ckaKeyType, uint64(ckkECEdwards)),
				ckaECPoint: newBytesAttribute(ckaECPoint, public),
			}
			return selectAttributes(all, types), nil
		},
	}
	installFake(t, fake)

	repository := NewSignatureRepository(testOptions()...)
	if err := repository.VerifyEd25519(context.Background(), "pkcs11:object=ed;type=public", message, signature); err != nil {
		t.Fatalf("VerifyEd25519() error = %v", err)
	}

	if err := repository.VerifyEd25519(context.Background(), "pkcs11:object=ed;type=public", "tampered", signature); err == nil {
		t.Fatal("VerifyEd25519() accepted a signature over different data")
	}
}

// TestSignRSAPSSVerifiesWithAutoSalt pins the interoperability note: this
// backend signs with a digest-sized salt while local uses the maximum salt, and
// both must verify under PSSSaltLengthAuto.
func TestSignRSAPSSVerifiesWithAutoSalt(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	const message = "pss payload"

	fake := rsaObjectFake(t, key)
	fake.signFn = func(_ sessionHandle, mech mechanism, params mechanismParams, _ objectHandle, payload []byte) ([]byte, error) {
		if mech != ckmSHA256RSAPKCSPSS {
			t.Errorf("mechanism = %v, want CKM_SHA256_RSA_PKCS_PSS", mech)
		}
		pss := params.(pssParams)
		digest := sha256.Sum256(payload)
		return rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], &rsa.PSSOptions{
			SaltLength: int(pss.SaltLen),
			Hash:       crypto.SHA256,
		})
	}
	installFake(t, fake)

	repository := NewSignatureRepository(testOptions()...)
	signature, err := repository.SignRSAPSS(context.Background(), "pkcs11:object=rsa;type=private", message)
	if err != nil {
		t.Fatalf("SignRSAPSS() error = %v", err)
	}

	if err := repository.VerifyRSAPSS(context.Background(), "pkcs11:object=rsa;type=public", message, signature); err != nil {
		t.Fatalf("VerifyRSAPSS() error = %v", err)
	}

	// A signature made by the local backend, with the maximum salt, must verify
	// through the same path.
	encodedPrivate, err := marshalPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	localSignature, err := local.NewSignatureRepository().SignRSAPSS(context.Background(), encodedPrivate, message)
	if err != nil {
		t.Fatalf("local SignRSAPSS() error = %v", err)
	}
	if err := repository.VerifyRSAPSS(context.Background(), "pkcs11:object=rsa;type=public", message, localSignature); err != nil {
		t.Fatalf("VerifyRSAPSS() rejected a local signature: %v", err)
	}
}

func TestSignRSAPKCS1v15OnToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	const message = "pkcs1 payload"

	fake := rsaObjectFake(t, key)
	fake.signFn = func(_ sessionHandle, mech mechanism, _ mechanismParams, _ objectHandle, payload []byte) ([]byte, error) {
		if mech != ckmSHA256RSAPKCS {
			t.Errorf("mechanism = %v, want CKM_SHA256_RSA_PKCS", mech)
		}
		digest := sha256.Sum256(payload)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	}
	installFake(t, fake)

	repository := NewSignatureRepository(testOptions()...)
	signature, err := repository.Sign_RSA_PKCS1v15_SHA256(context.Background(), "pkcs11:object=rsa;type=private", message)
	if err != nil {
		t.Fatalf("Sign_RSA_PKCS1v15_SHA256() error = %v", err)
	}
	if err := repository.Verify_RSA_PKCS1v15_SHA256(context.Background(), message, "pkcs11:object=rsa;type=public", signature); err != nil {
		t.Fatalf("Verify_RSA_PKCS1v15_SHA256() error = %v", err)
	}
}

// TestSignRSAPKCS1v15DegradesToRawMechanism covers the most valuable
// degradation: CKM_RSA_PKCS is universal, so a token lacking the combined
// mechanism still produces an identical signature.
func TestSignRSAPKCS1v15DegradesToRawMechanism(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	const message = "degraded payload"

	fake := rsaObjectFake(t, key)
	fake.mechanismsFn = func(uint64) ([]mechanism, error) {
		return []mechanism{ckmRSAPKCS}, nil
	}
	fake.signFn = func(_ sessionHandle, mech mechanism, _ mechanismParams, _ objectHandle, payload []byte) ([]byte, error) {
		if mech != ckmRSAPKCS {
			t.Errorf("mechanism = %v, want the raw fallback", mech)
		}
		// CKM_RSA_PKCS pads whatever it is given, which is DigestInfo||digest.
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.Hash(0), payload)
	}
	installFake(t, fake)

	repository := NewSignatureRepository(testOptions()...)
	signature, err := repository.Sign_RSA_PKCS1v15_SHA256(context.Background(), "pkcs11:object=rsa;type=private", message)
	if err != nil {
		t.Fatalf("Sign_RSA_PKCS1v15_SHA256() error = %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	digest := sha256.Sum256([]byte(message))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], raw); err != nil {
		t.Fatalf("the degraded signature is not a valid PKCS#1 v1.5 SHA-256 signature: %v", err)
	}
}

func TestSignatureFallsBackToLocal(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewSignatureRepository(testOptions()...)
	reference := local.NewSignatureRepository()
	ctx := context.Background()

	generated, err := reference.GenerateEd255Keys(ctx)
	if err != nil {
		t.Fatalf("local GenerateEd255Keys() error = %v", err)
	}

	signature, err := repository.SignEd25519(ctx, generated.KeyRef, "local path")
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}
	if err := repository.VerifyEd25519(ctx, generated.PublicKey, "local path", signature); err != nil {
		t.Fatalf("VerifyEd25519() error = %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	encodedPrivate, err := marshalPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	encodedPublic, err := marshalPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	pss, err := repository.SignRSAPSS(ctx, encodedPrivate, "local pss")
	if err != nil {
		t.Fatalf("SignRSAPSS() error = %v", err)
	}
	if err := repository.VerifyRSAPSS(ctx, encodedPublic, "local pss", pss); err != nil {
		t.Fatalf("VerifyRSAPSS() error = %v", err)
	}

	pkcs1, err := repository.Sign_RSA_PKCS1v15_SHA256(ctx, encodedPrivate, "local pkcs1")
	if err != nil {
		t.Fatalf("Sign_RSA_PKCS1v15_SHA256() error = %v", err)
	}
	if err := repository.Verify_RSA_PKCS1v15_SHA256(ctx, "local pkcs1", encodedPublic, pkcs1); err != nil {
		t.Fatalf("Verify_RSA_PKCS1v15_SHA256() error = %v", err)
	}
}

func TestSignaturePropagatesTokenErrors(t *testing.T) {
	signErr := newTokenError("C_Sign", ckrKeyFunctionNotPerm)
	installFake(t, &fakeModule{
		signFn: func(sessionHandle, mechanism, mechanismParams, objectHandle, []byte) ([]byte, error) {
			return nil, signErr
		},
	})

	repository := NewSignatureRepository(testOptions()...)
	if _, err := repository.SignEd25519(context.Background(), "pkcs11:object=ed;type=private", "x"); !errors.Is(err, signErr) {
		t.Fatalf("SignEd25519() = %v, want the token error", err)
	}
}

func TestSignatureRequiresKeyReference(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewSignatureRepository(testOptions()...)
	ctx := context.Background()

	if _, err := repository.Sign_RSA_PKCS1v15_SHA256(ctx, "", "data"); !errors.Is(err, ErrKeyURIRequired) {
		t.Fatalf("Sign_RSA_PKCS1v15_SHA256() = %v, want ErrKeyURIRequired", err)
	}
	if err := repository.Verify_RSA_PKCS1v15_SHA256(ctx, "data", "", "sig"); !errors.Is(err, ErrKeyURIRequired) {
		t.Fatalf("Verify_RSA_PKCS1v15_SHA256() = %v, want ErrKeyURIRequired", err)
	}
}

// TestSignEd25519RetriesWithParams covers a real vendor difference: CKM_EDDSA
// takes no parameter block in the specification, but several tokens reject a
// NULL one. The retry is invisible in C_GetMechanismList, so it can only be
// discovered at call time.
func TestSignEd25519RetriesWithParams(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	const message = "retry me"

	var attempts int
	installFake(t, &fakeModule{
		signFn: func(_ sessionHandle, _ mechanism, params mechanismParams, _ objectHandle, payload []byte) ([]byte, error) {
			attempts++
			if params == nil {
				return nil, newTokenError("C_Sign", ckrMechanismParamInval)
			}
			if _, ok := params.(eddsaParams); !ok {
				t.Fatalf("retry params = %T, want eddsaParams", params)
			}
			return ed25519.Sign(private, payload), nil
		},
	})

	repository := NewSignatureRepository(testOptions()...)
	signature, err := repository.SignEd25519(context.Background(), "pkcs11:object=ed;type=private", message)
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("made %d attempts, want a retry after the parameter rejection", attempts)
	}

	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	if !ed25519.Verify(public, []byte(message), raw) {
		t.Fatal("the retried signature does not verify")
	}
}

func TestIsMechanismParamError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "param invalid", err: newTokenError("C_Sign", ckrMechanismParamInval), want: true},
		{name: "arguments bad", err: newTokenError("C_Sign", ckrArgumentsBad), want: true},
		{name: "other token error", err: newTokenError("C_Sign", ckrDeviceError), want: false},
		{name: "not a token error", err: errors.New("boom"), want: false},
		{name: "nil", err: nil, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isMechanismParamError(test.err); got != test.want {
				t.Fatalf("isMechanismParamError(%v) = %v, want %v", test.err, got, test.want)
			}
		})
	}
}
