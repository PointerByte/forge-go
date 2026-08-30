// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/local"
	"github.com/PointerByte/forge-go/encrypt/models"
)

func TestNewRepositoryComposesEveryInterface(t *testing.T) {
	repository := NewRepository(testOptions()...)

	if repository.SymmetricRepository == nil || repository.AsymmetricRepository == nil ||
		repository.KeyRepository == nil || repository.SignatureRepository == nil ||
		repository.HashRepository == nil {
		t.Fatal("NewRepository() left an interface unset")
	}
	if repository.backend == nil {
		t.Fatal("NewRepository() left the backend unset")
	}
}

func TestFocusedConstructors(t *testing.T) {
	if NewSymmetricRepository(testOptions()...) == nil {
		t.Fatal("NewSymmetricRepository() returned nil")
	}
	if NewAsymmetricRepository(testOptions()...) == nil {
		t.Fatal("NewAsymmetricRepository() returned nil")
	}
	if NewKeyRepository(testOptions()...) == nil {
		t.Fatal("NewKeyRepository() returned nil")
	}
	if NewSignatureRepository(testOptions()...) == nil {
		t.Fatal("NewSignatureRepository() returned nil")
	}
	if NewHashRepository(testOptions()...) == nil {
		t.Fatal("NewHashRepository() returned nil")
	}
}

func TestCloseIsSafeWithoutBackend(t *testing.T) {
	repository := &Repository{}
	if err := repository.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestClose(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewRepository(testOptions()...)

	if err := repository.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

// TestConfigurationErrorsSurfaceOnFirstUse pins the lifecycle decision: the
// constructors never fail, so a misconfigured backend reports the problem when
// an operation runs, the way the Azure backend defers credential resolution.
func TestConfigurationErrorsSurfaceOnFirstUse(t *testing.T) {
	installFake(t, &fakeModule{})

	tests := []struct {
		name string
		opts []Option
		want error
	}{
		{name: "no module", opts: []Option{WithTokenLabel("t"), WithPinProvider(testPin)}, want: ErrModuleRequired},
		{name: "no token", opts: []Option{WithModulePath("/x.so"), WithPinProvider(testPin)}, want: ErrTokenRequired},
		{name: "no pin", opts: []Option{WithModulePath("/x.so"), WithTokenLabel("t")}, want: ErrPinRequired},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := NewSymmetricRepository(test.opts...)
			_, err := repository.GenerateSymetrycKeys(context.Background(), models.GenerateSymmetricKeyRequest{Size: common.Key256Bits})
			if !errors.Is(err, test.want) {
				t.Fatalf("GenerateSymetrycKeys() = %v, want %v", err, test.want)
			}
		})
	}
}

func TestWithSessionHonoursCancellation(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewSymmetricRepository(testOptions()...)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := repository.GenerateSymetrycKeys(cancelled, models.GenerateSymmetricKeyRequest{Size: common.Key256Bits})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("GenerateSymetrycKeys(cancelled) = %v, want context.Canceled", err)
	}
}

func TestGenerateSymetrycKeys(t *testing.T) {
	var template []attribute
	fake := &fakeModule{
		generateKeyFn: func(_ sessionHandle, mech mechanism, tmpl []attribute) (objectHandle, error) {
			if mech != ckmAESKeyGen {
				t.Errorf("mechanism = %v, want CKM_AES_KEY_GEN", mech)
			}
			template = tmpl
			return 5, nil
		},
	}
	installFake(t, fake)

	repository := NewSymmetricRepository(testOptions()...)
	data, err := repository.GenerateSymetrycKeys(context.Background(), models.GenerateSymmetricKeyRequest{
		UID:  "svc",
		Size: common.Key256Bits,
	})
	if err != nil {
		t.Fatalf("GenerateSymetrycKeys() error = %v", err)
	}

	if data.Provider != providerName {
		t.Fatalf("Provider = %q, want %q", data.Provider, providerName)
	}
	// A token-generated symmetric key has no exportable material; the URI is
	// the whole reference.
	if data.PublicKey != "" {
		t.Fatalf("PublicKey = %q, want empty for a symmetric key", data.PublicKey)
	}
	if !isKeyURI(data.KeyRef) {
		t.Fatalf("KeyRef = %q, want a pkcs11 uri", data.KeyRef)
	}
	if !strings.Contains(data.KeyRef, "svc") {
		t.Fatalf("KeyRef = %q, want it to carry the uid in the label", data.KeyRef)
	}

	// The security-critical part of the template: the key lives on the token
	// and can never be read out.
	assertBoolAttribute(t, template, ckaSensitive, true)
	assertBoolAttribute(t, template, ckaExtractable, false)
	assertBoolAttribute(t, template, ckaToken, true)

	valueLen, ok := findAttribute(template, ckaValueLen)
	if !ok {
		t.Fatal("template has no CKA_VALUE_LEN")
	}
	decoded, _ := uLongValue(valueLen)
	if decoded != uint64(common.Key256Bits) {
		t.Fatalf("CKA_VALUE_LEN = %d, want %d bytes", decoded, common.Key256Bits)
	}
}

func assertBoolAttribute(t *testing.T, template []attribute, kind attributeType, want bool) {
	t.Helper()
	raw, ok := findAttribute(template, kind)
	if !ok {
		t.Fatalf("template has no attribute %d", kind)
	}
	got, ok := boolValue(raw)
	if !ok {
		t.Fatalf("attribute %d is not a CK_BBOOL", kind)
	}
	if got != want {
		t.Fatalf("attribute %d = %v, want %v", kind, got, want)
	}
}

func TestGenerateSymetrycKeysRejectsUnsupportedSize(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewSymmetricRepository(testOptions()...)

	if _, err := repository.GenerateSymetrycKeys(context.Background(), models.GenerateSymmetricKeyRequest{
		Size: common.SizeSymetrycKey(7),
	}); err == nil {
		t.Fatal("expected an error for an unsupported key size")
	}
}

func TestGenerateSymetrycKeysRequiresMechanism(t *testing.T) {
	installFake(t, &fakeModule{
		mechanismsFn: func(uint64) ([]mechanism, error) { return []mechanism{ckmAESGCM}, nil },
	})
	repository := NewSymmetricRepository(testOptions()...)

	_, err := repository.GenerateSymetrycKeys(context.Background(), models.GenerateSymmetricKeyRequest{Size: common.Key256Bits})
	var unsupported unsupportedMechanismError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error = %v, want unsupportedMechanismError", err)
	}
}

// TestEncryptAESWireFormatMatchesLocal is the interoperability property that
// justifies supplying the IV ourselves: a ciphertext produced on the token must
// decrypt with the local backend and vice versa.
func TestEncryptAESWireFormatMatchesLocal(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	encodedKey := base64.StdEncoding.EncodeToString(key)

	fake := &fakeModule{
		encryptFn: func(_ sessionHandle, mech mechanism, params mechanismParams, _ objectHandle, plaintext []byte) ([]byte, error) {
			if mech != ckmAESGCM {
				t.Errorf("mechanism = %v, want CKM_AES_GCM", mech)
			}
			gcm, ok := params.(gcmParams)
			if !ok {
				t.Fatalf("params = %T, want gcmParams", params)
			}
			if len(gcm.IV) != gcmNonceLength {
				t.Fatalf("IV length = %d, want %d", len(gcm.IV), gcmNonceLength)
			}
			if gcm.TagBits != gcmTagBits {
				t.Fatalf("TagBits = %d, want %d", gcm.TagBits, gcmTagBits)
			}
			// Emulate the token by doing exactly what AES-GCM specifies.
			return softwareGCMSeal(t, key, gcm.IV, gcm.AAD, plaintext), nil
		},
	}
	installFake(t, fake)

	repository := NewSymmetricRepository(testOptions()...)
	additional := "aad"
	ciphertext, err := repository.EncryptAES(context.Background(), models.EncryptAESRequest{
		SecretKey:  "pkcs11:object=aes-key;type=secret-key",
		Value:      "top secret",
		Additional: &additional,
	})
	if err != nil {
		t.Fatalf("EncryptAES() error = %v", err)
	}

	// The local backend must be able to read it.
	plaintext, err := local.NewSymmetricRepository().DecryptAES(context.Background(), models.DecryptAESRequest{
		SecretKey:   encodedKey,
		CipherValue: ciphertext,
		Additional:  &additional,
	})
	if err != nil {
		t.Fatalf("local DecryptAES() of a token ciphertext error = %v", err)
	}
	if plaintext != "top secret" {
		t.Fatalf("plaintext = %q, want %q", plaintext, "top secret")
	}
}

func softwareGCMSeal(t *testing.T, key, nonce, aad, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM() error = %v", err)
	}
	return gcm.Seal(nil, nonce, plaintext, aad)
}

func TestDecryptAESReadsLocalCiphertext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	encodedKey := base64.StdEncoding.EncodeToString(key)
	additional := "curve"

	produced, err := local.NewSymmetricRepository().EncryptAES(context.Background(), models.EncryptAESRequest{
		SecretKey:  encodedKey,
		Value:      "from local",
		Additional: &additional,
	})
	if err != nil {
		t.Fatalf("local EncryptAES() error = %v", err)
	}

	fake := &fakeModule{
		decryptFn: func(_ sessionHandle, _ mechanism, params mechanismParams, _ objectHandle, ciphertext []byte) ([]byte, error) {
			gcm := params.(gcmParams)
			block, _ := aes.NewCipher(key)
			aead, _ := cipher.NewGCM(block)
			return aead.Open(nil, gcm.IV, ciphertext, gcm.AAD)
		},
	}
	installFake(t, fake)

	repository := NewSymmetricRepository(testOptions()...)
	plaintext, err := repository.DecryptAES(context.Background(), models.DecryptAESRequest{
		SecretKey:   "pkcs11:object=aes-key;type=secret-key",
		CipherValue: produced,
		Additional:  &additional,
	})
	if err != nil {
		t.Fatalf("DecryptAES() error = %v", err)
	}
	if plaintext != "from local" {
		t.Fatalf("plaintext = %q, want %q", plaintext, "from local")
	}
}

// TestSymmetricFallsBackToLocal covers the routing rule shared by every
// backend: the decision is made on the shape of the input, never on capability.
func TestSymmetricFallsBackToLocal(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewSymmetricRepository(testOptions()...)

	generated, err := local.NewSymmetricRepository().GenerateSymetrycKeys(context.Background(), models.GenerateSymmetricKeyRequest{
		Size: common.Key256Bits,
	})
	if err != nil {
		t.Fatalf("local GenerateSymetrycKeys() error = %v", err)
	}

	ciphertext, err := repository.EncryptAES(context.Background(), models.EncryptAESRequest{
		SecretKey: generated.KeyRef,
		Value:     "local path",
	})
	if err != nil {
		t.Fatalf("EncryptAES() error = %v", err)
	}
	plaintext, err := repository.DecryptAES(context.Background(), models.DecryptAESRequest{
		SecretKey:   generated.KeyRef,
		CipherValue: ciphertext,
	})
	if err != nil {
		t.Fatalf("DecryptAES() error = %v", err)
	}
	if plaintext != "local path" {
		t.Fatalf("plaintext = %q, want %q", plaintext, "local path")
	}
}

func TestDecryptAESRejectsShortCiphertext(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewSymmetricRepository(testOptions()...)

	tests := []struct {
		name  string
		value string
	}{
		{name: "not base64", value: "!!!not base64!!!"},
		{name: "shorter than the nonce", value: base64.StdEncoding.EncodeToString([]byte("short"))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := repository.DecryptAES(context.Background(), models.DecryptAESRequest{
				SecretKey:   "pkcs11:object=aes-key",
				CipherValue: test.value,
			})
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestSymmetricRequiresKeyReference(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewSymmetricRepository(testOptions()...)

	if _, err := repository.EncryptAES(context.Background(), models.EncryptAESRequest{Value: "x"}); !errors.Is(err, ErrKeyURIRequired) {
		t.Fatalf("EncryptAES() = %v, want ErrKeyURIRequired", err)
	}
}

func TestHashDelegatesToLocal(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewHashRepository(testOptions()...)
	reference := local.NewHashRepository()
	ctx := context.Background()

	if got, want := repository.Sha256Hex(ctx, "abc"), reference.Sha256Hex(ctx, "abc"); got != want {
		t.Fatalf("Sha256Hex() = %q, want %q", got, want)
	}
	if got, want := repository.Blake3(ctx, "abc"), reference.Blake3(ctx, "abc"); got != want {
		t.Fatalf("Blake3() = %q, want %q", got, want)
	}
	// A non-URI secret means local key material, so the HMAC is computed here.
	if got, want := repository.HMAC(ctx, "secret", "abc"), reference.HMAC(ctx, "secret", "abc"); got != want {
		t.Fatalf("HMAC() = %q, want %q", got, want)
	}
}

func TestHMACOnToken(t *testing.T) {
	fake := &fakeModule{
		signFn: func(_ sessionHandle, mech mechanism, _ mechanismParams, _ objectHandle, message []byte) ([]byte, error) {
			if mech != ckmSHA256HMAC {
				t.Errorf("mechanism = %v, want CKM_SHA256_HMAC", mech)
			}
			return append([]byte("mac:"), message...), nil
		},
	}
	installFake(t, fake)

	repository := NewHashRepository(testOptions()...)
	got := repository.HMAC(context.Background(), "pkcs11:object=hmac-key;type=secret-key", "abc")

	want := base64.StdEncoding.EncodeToString([]byte("mac:abc"))
	if got != want {
		t.Fatalf("HMAC() = %q, want %q", got, want)
	}
}

// TestHMACReturnsEmptyOnFailure matches the contract the other backends use:
// the signature has no error result, so failures surface as an empty string
// rather than a silently local-computed MAC with the wrong key.
func TestHMACReturnsEmptyOnFailure(t *testing.T) {
	tests := []struct {
		name string
		fake *fakeModule
	}{
		{name: "token error", fake: &fakeModule{
			signFn: func(sessionHandle, mechanism, mechanismParams, objectHandle, []byte) ([]byte, error) {
				return nil, newTokenError("C_Sign", ckrKeyFunctionNotPerm)
			},
		}},
		{name: "mechanism missing", fake: &fakeModule{
			mechanismsFn: func(uint64) ([]mechanism, error) { return []mechanism{ckmAESGCM}, nil },
		}},
		{name: "key not found", fake: &fakeModule{
			findObjectsFn: func(sessionHandle, []attribute) ([]objectHandle, error) { return nil, nil },
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			installFake(t, test.fake)
			repository := NewHashRepository(testOptions()...)
			if got := repository.HMAC(context.Background(), "pkcs11:object=k", "abc"); got != "" {
				t.Fatalf("HMAC() = %q, want an empty string on failure", got)
			}
		})
	}
}

func TestHMACWithUnparseableURI(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewHashRepository(testOptions()...)

	if got := repository.HMAC(context.Background(), "pkcs11:", "abc"); got != "" {
		t.Fatalf("HMAC() = %q, want empty for a malformed uri", got)
	}
}

func TestNewObjectLabel(t *testing.T) {
	if got := newObjectLabel(rsaKeyPrefix, "svc"); got != rsaKeyPrefix+"-svc" {
		t.Fatalf("newObjectLabel() = %q", got)
	}
	got := newObjectLabel(rsaKeyPrefix, "")
	if !strings.HasPrefix(got, rsaKeyPrefix+"-") || got == rsaKeyPrefix+"-" {
		t.Fatalf("newObjectLabel() = %q, want a timestamp suffix", got)
	}
}

func TestNewObjectIDPropagatesEntropyFailure(t *testing.T) {
	previous := randReadFn
	t.Cleanup(func() { randReadFn = previous })
	randReadFn = func([]byte) (int, error) { return 0, errors.New("no entropy") }

	if _, err := newObjectID(); err == nil {
		t.Fatal("newObjectID() must propagate an entropy failure")
	}
}
