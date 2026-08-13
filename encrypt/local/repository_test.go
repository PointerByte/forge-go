// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/models"
	"github.com/PointerByte/forge-go/encrypt/utilities"
	"github.com/zeebo/blake3"
)

var testContext = context.Background()

func TestNewRepositoryBuildsAllRepositories(t *testing.T) {
	repository := NewRepository()
	if repository.SymmetricRepository == nil || repository.AsymmetricRepository == nil || repository.KeyRepository == nil || repository.SignatureRepository == nil || repository.HashRepository == nil {
		t.Fatal("expected all repositories to be initialized")
	}
}

func TestSymmetricRepositoryAES(t *testing.T) {
	repository := NewSymmetricRepository()

	key, err := repository.GenerateSymetrycKeys(testContext, models.GenerateSymmetricKeyRequest{Size: common.Key256Bits})
	if err != nil {
		t.Fatalf("GenerateSymetrycKeys() error = %v", err)
	}
	if key == nil || key.KeyID == "" || key.KeyRef == "" || key.Provider != "local" {
		t.Fatalf("GenerateSymetrycKeys() = %#v, want populated local key data", key)
	}
	if key.KeyRef != key.KeyID {
		t.Fatalf("local key reference = %q, want legacy key id value", key.KeyRef)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(key.KeyID)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	if len(keyBytes) != int(common.Key256Bits) {
		t.Fatalf("key length = %d, want %d", len(keyBytes), common.Key256Bits)
	}

	additional := "aad"
	ciphertext, err := repository.EncryptAES(testContext, models.EncryptAESRequest{SecretKey: key.KeyID, Value: "hello", Additional: &additional})
	if err != nil {
		t.Fatalf("EncryptAES() error = %v", err)
	}
	plaintext, err := repository.DecryptAES(testContext, models.DecryptAESRequest{SecretKey: key.KeyID, CipherValue: ciphertext, Additional: &additional})
	if err != nil {
		t.Fatalf("DecryptAES() error = %v", err)
	}
	if plaintext != "hello" {
		t.Fatalf("DecryptAES() = %q, want %q", plaintext, "hello")
	}
}

func TestSymmetricRepositoryErrors(t *testing.T) {
	repository := NewSymmetricRepository()

	additional := "aad"
	if _, err := repository.EncryptAES(testContext, models.EncryptAESRequest{SecretKey: "%%%", Value: "value", Additional: &additional}); err == nil {
		t.Fatal("expected EncryptAES() base64 error")
	}
	if _, err := repository.EncryptAES(testContext, models.EncryptAESRequest{SecretKey: base64.StdEncoding.EncodeToString([]byte("short")), Value: "value", Additional: &additional}); err == nil {
		t.Fatal("expected EncryptAES() invalid key error")
	}
	if _, err := repository.DecryptAES(testContext, models.DecryptAESRequest{SecretKey: "%%%", CipherValue: "cipher", Additional: &additional}); err == nil {
		t.Fatal("expected DecryptAES() key error")
	}

	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, err := repository.DecryptAES(testContext, models.DecryptAESRequest{SecretKey: key, CipherValue: "%%%", Additional: &additional}); err == nil {
		t.Fatal("expected DecryptAES() ciphertext error")
	}
	if _, err := repository.DecryptAES(testContext, models.DecryptAESRequest{SecretKey: key, CipherValue: base64.StdEncoding.EncodeToString([]byte("short")), Additional: &additional}); err == nil {
		t.Fatal("expected DecryptAES() short ciphertext error")
	}

	ciphertext, err := repository.EncryptAES(testContext, models.EncryptAESRequest{SecretKey: key, Value: "hello", Additional: &additional})
	if err != nil {
		t.Fatalf("EncryptAES() error = %v", err)
	}
	wrongAdditional := "wrong"
	if _, err := repository.DecryptAES(testContext, models.DecryptAESRequest{SecretKey: key, CipherValue: ciphertext, Additional: &wrongAdditional}); err == nil {
		t.Fatal("expected DecryptAES() authentication error")
	}

}

func TestHashRepository(t *testing.T) {
	repository := NewHashRepository()

	got := repository.HMAC(testContext, "secret", "message")
	if got == "" {
		t.Fatal("HMAC() returned empty value")
	}

	wantSHA := hex.EncodeToString(mustSHA256Bytes([]byte("message")))
	if got := repository.Sha256Hex(testContext, "message"); got != wantSHA {
		t.Fatalf("Sha256Hex() = %q, want %q", got, wantSHA)
	}

	blakeSum := blake3.Sum256([]byte("message"))
	wantBlake := base64.StdEncoding.EncodeToString(blakeSum[:])
	if got := repository.Blake3(testContext, "message"); got != wantBlake {
		t.Fatalf("Blake3() = %q, want %q", got, wantBlake)
	}
}

func TestRepositoriesRespectCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(testContext)
	cancel()

	symmetricRepository := NewSymmetricRepository()
	if _, err := symmetricRepository.GenerateSymetrycKeys(ctx, models.GenerateSymmetricKeyRequest{Size: common.Key128Bits}); !errors.Is(err, context.Canceled) {
		t.Fatalf("GenerateSymetrycKeys() error = %v, want context.Canceled", err)
	}
	if _, err := symmetricRepository.EncryptAES(ctx, models.EncryptAESRequest{SecretKey: base64.StdEncoding.EncodeToString(make([]byte, 16)), Value: "payload", Additional: nil}); !errors.Is(err, context.Canceled) {
		t.Fatalf("EncryptAES() error = %v, want context.Canceled", err)
	}

	hashRepository := NewHashRepository()
	if got := hashRepository.HMAC(ctx, "secret", "message"); got != "" {
		t.Fatalf("HMAC() = %q, want empty string for canceled context", got)
	}

	asymmetricRepository := NewAsymmetricRepository()
	if _, err := asymmetricRepository.GenerateRSAKeys(ctx, models.GenerateRSAKeyRequest{Size: common.Key2048Bits}); !errors.Is(err, context.Canceled) {
		t.Fatalf("GenerateRSAKeys() error = %v, want context.Canceled", err)
	}

	keyRepository := NewKeyRepository()
	if _, err := keyRepository.RotateKey(ctx, models.RotateKeyRequest{KeyID: "key"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("RotateKey() error = %v, want context.Canceled", err)
	}
	if _, err := keyRepository.GetKey(ctx, models.GetKeyRequest{KeyID: "key"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("GetKey() error = %v, want context.Canceled", err)
	}
	if err := keyRepository.DeactivateKey(ctx, models.DeactivateKeyRequest{KeyID: "key"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("DeactivateKey() error = %v, want context.Canceled", err)
	}

	signatureRepository := NewSignatureRepository()
	if _, err := signatureRepository.GenerateEd255Keys(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("GenerateEd255Keys() error = %v, want context.Canceled", err)
	}

	timeoutCtx, timeoutCancel := context.WithTimeout(testContext, 0)
	defer timeoutCancel()
	if _, err := symmetricRepository.DecryptAES(timeoutCtx, models.DecryptAESRequest{SecretKey: "bad", CipherValue: "bad", Additional: nil}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DecryptAES() error = %v, want context.DeadlineExceeded", err)
	}
}

func TestKeyRepositoryUnsupported(t *testing.T) {
	repository := NewKeyRepository()

	if _, err := repository.RotateKey(testContext, models.RotateKeyRequest{KeyID: "key"}); err == nil {
		t.Fatal("expected RotateKey() unsupported error")
	}
	if _, err := repository.GetKey(testContext, models.GetKeyRequest{KeyID: "key"}); err == nil {
		t.Fatal("expected GetKey() unsupported error")
	}
	if err := repository.DeactivateKey(testContext, models.DeactivateKeyRequest{KeyID: "key"}); err == nil {
		t.Fatal("expected DeactivateKey() unsupported error")
	}
}

func TestAsymmetricAndSignatureRepositories(t *testing.T) {
	asymmetricRepository := NewAsymmetricRepository()
	signatureRepository := NewSignatureRepository()

	keyData, err := asymmetricRepository.GenerateRSAKeys(testContext, models.GenerateRSAKeyRequest{Size: common.Key2048Bits})
	if err != nil {
		t.Fatalf("GenerateRSAKeys() error = %v", err)
	}
	if keyData == nil || keyData.KeyID == "" || keyData.KeyRef == "" || keyData.PublicKey == "" || keyData.Provider != "local" {
		t.Fatalf("GenerateRSAKeys() = %#v, want populated local key data", keyData)
	}
	if keyData.KeyRef != keyData.KeyID {
		t.Fatalf("local RSA key reference does not preserve the legacy key id")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(mustBase64Decode(t, keyData.KeyID))
	if err != nil {
		t.Fatalf("ParsePKCS1PrivateKey() error = %v", err)
	}
	publicKey, err := x509.ParsePKCS1PublicKey(mustBase64Decode(t, keyData.PublicKey))
	if err != nil {
		t.Fatalf("ParsePKCS1PublicKey() error = %v", err)
	}

	ciphertext, err := asymmetricRepository.RSA_OAEP_Encode(testContext, models.RSAOAEPEncodeRequest{PublicKey: mustMarshalPKIXRSAPublicKey(t, publicKey), Text: "hello"})
	if err != nil {
		t.Fatalf("RSA_OAEP_Encode() error = %v", err)
	}
	plaintext, err := asymmetricRepository.RSA_OAEP_Decode(testContext, models.RSAOAEPDecodeRequest{PrivateKey: mustMarshalPKCS8RSAPrivateKey(t, privateKey), CipherText: ciphertext})
	if err != nil {
		t.Fatalf("RSA_OAEP_Decode() error = %v", err)
	}
	if plaintext != "hello" {
		t.Fatalf("RSA_OAEP_Decode() = %q, want %q", plaintext, "hello")
	}

	eccKeyData, err := asymmetricRepository.GenerateECDHCurveKeys(testContext, models.GenerateECDHCurveKeyRequest{Curve: common.CurveP256})
	if err != nil {
		t.Fatalf("GenerateECDHCurveKeys() error = %v", err)
	}
	if eccKeyData == nil || eccKeyData.KeyID == "" || eccKeyData.KeyRef == "" || eccKeyData.PublicKey == "" || eccKeyData.Provider != "local" {
		t.Fatalf("GenerateECDHCurveKeys() = %#v, want populated local key data", eccKeyData)
	}
	if eccKeyData.KeyRef != eccKeyData.KeyID {
		t.Fatalf("local ECDH key reference does not preserve the legacy key id")
	}

	eccPublicKey, err := utilities.ParseECDHPublicKeyFromBase64(eccKeyData.PublicKey)
	if err != nil {
		t.Fatalf("ParseECDHPublicKeyFromBase64() error = %v", err)
	}
	if eccPublicKey.Curve() != ecdh.P256() {
		t.Fatalf("ECC public key curve = %v, want P-256", eccPublicKey.Curve())
	}

	eccCiphertext, err := asymmetricRepository.ECDH_Encode(testContext, models.ECDHEncodeRequest{PublicKey: eccKeyData.PublicKey, Text: "hello"})
	if err != nil {
		t.Fatalf("ECDH_Encode() error = %v", err)
	}
	eccPlaintext, err := asymmetricRepository.ECDH_Decode(testContext, models.ECDHDecodeRequest{PrivateKey: eccKeyData.KeyID, CipherText: eccCiphertext})
	if err != nil {
		t.Fatalf("ECDH_Decode() error = %v", err)
	}
	if eccPlaintext != "hello" {
		t.Fatalf("ECDH_Decode() = %q, want %q", eccPlaintext, "hello")
	}

	signature, err := signatureRepository.SignRSAPSS(testContext, mustMarshalPKCS8RSAPrivateKey(t, privateKey), "payload")
	if err != nil {
		t.Fatalf("SignRSAPSS() error = %v", err)
	}
	if err := signatureRepository.VerifyRSAPSS(testContext, mustMarshalPKIXRSAPublicKey(t, publicKey), "payload", signature); err != nil {
		t.Fatalf("VerifyRSAPSS() error = %v", err)
	}

	pkcs1v15Signature, err := signatureRepository.Sign_RSA_PKCS1v15_SHA256(testContext, mustMarshalPKCS8RSAPrivateKey(t, privateKey), "payload")
	if err != nil {
		t.Fatalf("Sign_RSA_PKCS1v15_SHA256() error = %v", err)
	}
	if err := signatureRepository.Verify_RSA_PKCS1v15_SHA256(testContext, "payload", mustMarshalPKIXRSAPublicKey(t, publicKey), pkcs1v15Signature); err != nil {
		t.Fatalf("Verify_RSA_PKCS1v15_SHA256() error = %v", err)
	}

	edKeyData, err := signatureRepository.GenerateEd255Keys(testContext)
	if err != nil {
		t.Fatalf("GenerateEd255Keys() error = %v", err)
	}
	if edKeyData == nil || edKeyData.KeyID == "" || edKeyData.KeyRef == "" || edKeyData.PublicKey == "" || edKeyData.Provider != "local" {
		t.Fatalf("GenerateEd255Keys() = %#v, want populated local key data", edKeyData)
	}
	if edKeyData.KeyRef != edKeyData.KeyID {
		t.Fatalf("local Ed25519 key reference does not preserve the legacy key id")
	}
	edSignature, err := signatureRepository.SignEd25519(testContext, edKeyData.KeyID, "payload")
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}
	if err := signatureRepository.VerifyEd25519(testContext, edKeyData.PublicKey, "payload", edSignature); err != nil {
		t.Fatalf("VerifyEd25519() error = %v", err)
	}

	if err := signatureRepository.VerifyEd25519(testContext, edKeyData.PublicKey, "payload", edSignature[:len(edSignature)-2]+"ab"); err == nil {
		t.Fatal("expected VerifyEd25519() invalid signature error")
	}

	if err := signatureRepository.VerifyRSAPSS(testContext, mustMarshalPKIXRSAPublicKey(t, publicKey), "payload", signature[:len(signature)-2]+"ab"); err == nil {
		t.Fatal("expected VerifyRSAPSS() invalid signature error")
	}

	if err := signatureRepository.Verify_RSA_PKCS1v15_SHA256(testContext, "payload", mustMarshalPKIXRSAPublicKey(t, publicKey), pkcs1v15Signature[:len(pkcs1v15Signature)-2]+"ab"); err == nil {
		t.Fatal("expected Verify_RSA_PKCS1v15_SHA256() invalid signature error")
	}
}

func TestAsymmetricAndSignatureRepositoryErrors(t *testing.T) {
	asymmetricRepository := NewAsymmetricRepository()
	signatureRepository := NewSignatureRepository()

	if _, err := asymmetricRepository.RSA_OAEP_Encode(testContext, models.RSAOAEPEncodeRequest{PublicKey: "%%%", Text: "payload"}); err == nil {
		t.Fatal("expected RSA_OAEP_Encode() key error")
	}
	if _, err := asymmetricRepository.RSA_OAEP_Decode(testContext, models.RSAOAEPDecodeRequest{PrivateKey: "%%%", CipherText: "payload"}); err == nil {
		t.Fatal("expected RSA_OAEP_Decode() key error")
	}
	if _, err := asymmetricRepository.RSA_OAEP_Decode(testContext, models.RSAOAEPDecodeRequest{PrivateKey: mustMarshalPKCS8RSAPrivateKey(t, mustRSAKey(t)), CipherText: "%%%"}); err == nil {
		t.Fatal("expected RSA_OAEP_Decode() ciphertext error")
	}
	if _, err := asymmetricRepository.GenerateRSAKeys(testContext, models.GenerateRSAKeyRequest{Size: 0}); err == nil {
		t.Fatal("expected GenerateRSAKeys() error")
	}
	if _, err := asymmetricRepository.GenerateECDHCurveKeys(testContext, models.GenerateECDHCurveKeyRequest{Curve: common.CurveAsymmetricKey(99)}); err == nil {
		t.Fatal("expected GenerateECDHCurveKeys() error")
	}
	if _, err := asymmetricRepository.ECDH_Encode(testContext, models.ECDHEncodeRequest{PublicKey: "%%%", Text: "payload"}); err == nil {
		t.Fatal("expected ECDH_Encode() key error")
	}
	if _, err := asymmetricRepository.ECDH_Decode(testContext, models.ECDHDecodeRequest{PrivateKey: "%%%", CipherText: "payload"}); err == nil {
		t.Fatal("expected ECDH_Decode() key error")
	}
	if _, err := asymmetricRepository.ECDH_Decode(testContext, models.ECDHDecodeRequest{PrivateKey: mustECCPrivateKeyBase64(t, ecdh.P256()), CipherText: "%%%"}); err == nil {
		t.Fatal("expected ECDH_Decode() payload error")
	}
	p256Private := mustECCPrivateKeyBase64(t, ecdh.P256())
	p521Private := mustECCPrivateKeyBase64(t, ecdh.P521())
	p256Public := mustECCPublicKeyBase64(t, p256Private)
	eccCiphertext, err := asymmetricRepository.ECDH_Encode(testContext, models.ECDHEncodeRequest{PublicKey: p256Public, Text: "payload"})
	if err != nil {
		t.Fatalf("ECDH_Encode() error = %v", err)
	}
	if _, err := asymmetricRepository.ECDH_Decode(testContext, models.ECDHDecodeRequest{PrivateKey: p521Private, CipherText: eccCiphertext}); err == nil {
		t.Fatal("expected ECDH_Decode() curve mismatch error")
	}

	if _, err := signatureRepository.SignEd25519(testContext, "%%%", "payload"); err == nil {
		t.Fatal("expected SignEd25519() key error")
	}
	if err := signatureRepository.VerifyEd25519(testContext, "%%%", "payload", "sig"); err == nil {
		t.Fatal("expected VerifyEd25519() key error")
	}

	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	if err := signatureRepository.VerifyEd25519(testContext, mustMarshalEd25519PublicKey(t, edPublic), "payload", "%%%"); err == nil {
		t.Fatal("expected VerifyEd25519() signature decode error")
	}

	if _, err := signatureRepository.SignRSAPSS(testContext, "%%%", "payload"); err == nil {
		t.Fatal("expected SignRSAPSS() key error")
	}
	if err := signatureRepository.VerifyRSAPSS(testContext, "%%%", "payload", "sig"); err == nil {
		t.Fatal("expected VerifyRSAPSS() key error")
	}
	if err := signatureRepository.VerifyRSAPSS(testContext, mustMarshalPKIXRSAPublicKey(t, &mustRSAKey(t).PublicKey), "payload", "%%%"); err == nil {
		t.Fatal("expected VerifyRSAPSS() signature decode error")
	}

	if _, err := signatureRepository.Sign_RSA_PKCS1v15_SHA256(testContext, "", "payload"); err == nil {
		t.Fatal("expected Sign_RSA_PKCS1v15_SHA256() empty private key error")
	}
	if err := signatureRepository.Verify_RSA_PKCS1v15_SHA256(testContext, "payload", "", "sig"); err == nil {
		t.Fatal("expected Verify_RSA_PKCS1v15_SHA256() empty public key error")
	}
	if err := signatureRepository.Verify_RSA_PKCS1v15_SHA256(testContext, "payload", mustMarshalPKIXRSAPublicKey(t, &mustRSAKey(t).PublicKey), "%%%"); err == nil {
		t.Fatal("expected Verify_RSA_PKCS1v15_SHA256() signature decode error")
	}
}

func TestParseKeyUtilities(t *testing.T) {
	privateKey := mustRSAKey(t)
	publicKey := &privateKey.PublicKey
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	if _, err := utilities.ParseRSAPublicKeyFromBase64(mustMarshalPKIXRSAPublicKey(t, publicKey)); err != nil {
		t.Fatalf("ParseRSAPublicKeyFromBase64() error = %v", err)
	}
	if _, err := utilities.ParseRSAPrivateKeyFromBase64(mustMarshalPKCS8RSAPrivateKey(t, privateKey)); err != nil {
		t.Fatalf("ParseRSAPrivateKeyFromBase64() error = %v", err)
	}
	if _, err := utilities.ParseEd25519PublicKeyFromBase64(mustMarshalEd25519PublicKey(t, edPublic)); err != nil {
		t.Fatalf("ParseEd25519PublicKeyFromBase64() error = %v", err)
	}
	if _, err := utilities.ParseEd25519PrivateKeyFromBase64(mustMarshalEd25519PrivateKey(t, edPrivate)); err != nil {
		t.Fatalf("ParseEd25519PrivateKeyFromBase64() error = %v", err)
	}

	if _, err := utilities.ParseRSAPublicKeyFromBase64("%%%"); err == nil {
		t.Fatal("expected ParseRSAPublicKeyFromBase64() error")
	}
	if _, err := utilities.ParseRSAPrivateKeyFromBase64("%%%"); err == nil {
		t.Fatal("expected ParseRSAPrivateKeyFromBase64() error")
	}
	if _, err := utilities.ParseEd25519PublicKeyFromBase64("%%%"); err == nil {
		t.Fatal("expected ParseEd25519PublicKeyFromBase64() error")
	}
	if _, err := utilities.ParseEd25519PrivateKeyFromBase64("%%%"); err == nil {
		t.Fatal("expected ParseEd25519PrivateKeyFromBase64() error")
	}

	rsaPublicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	rsaPrivateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	edPublicDER, err := x509.MarshalPKIXPublicKey(edPublic)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	edPrivateDER, err := x509.MarshalPKCS8PrivateKey(edPrivate)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}

	if _, err := utilities.ParseRSAPublicKeyFromBase64(base64.StdEncoding.EncodeToString([]byte("bad"))); err == nil {
		t.Fatal("expected ParseRSAPublicKeyFromBase64() parse error")
	}
	if _, err := utilities.ParseRSAPrivateKeyFromBase64(base64.StdEncoding.EncodeToString([]byte("bad"))); err == nil {
		t.Fatal("expected ParseRSAPrivateKeyFromBase64() parse error")
	}
	if _, err := utilities.ParseEd25519PublicKeyFromBase64(base64.StdEncoding.EncodeToString([]byte("bad"))); err == nil {
		t.Fatal("expected ParseEd25519PublicKeyFromBase64() parse error")
	}
	if _, err := utilities.ParseEd25519PrivateKeyFromBase64(base64.StdEncoding.EncodeToString([]byte("bad"))); err == nil {
		t.Fatal("expected ParseEd25519PrivateKeyFromBase64() parse error")
	}

	if _, err := utilities.ParseRSAPublicKeyFromBase64(base64.StdEncoding.EncodeToString(edPublicDER)); err == nil {
		t.Fatal("expected ParseRSAPublicKeyFromBase64() wrong type error")
	}
	if _, err := utilities.ParseRSAPrivateKeyFromBase64(base64.StdEncoding.EncodeToString(edPrivateDER)); err == nil {
		t.Fatal("expected ParseRSAPrivateKeyFromBase64() wrong type error")
	}
	if _, err := utilities.ParseEd25519PublicKeyFromBase64(base64.StdEncoding.EncodeToString(rsaPublicDER)); err == nil {
		t.Fatal("expected ParseEd25519PublicKeyFromBase64() wrong type error")
	}
	if _, err := utilities.ParseEd25519PrivateKeyFromBase64(base64.StdEncoding.EncodeToString(rsaPrivateDER)); err == nil {
		t.Fatal("expected ParseEd25519PrivateKeyFromBase64() wrong type error")
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return privateKey
}

func mustECCKey(t *testing.T, curve ecdh.Curve) *ecdh.PrivateKey {
	t.Helper()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh.GenerateKey() error = %v", err)
	}
	return privateKey
}

func mustECCPrivateKeyBase64(t *testing.T, curve ecdh.Curve) string {
	t.Helper()
	privateKey := mustECCKey(t, curve)
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(privateDER)
}

func mustECCPublicKeyBase64(t *testing.T, privateKeyBase64 string) string {
	t.Helper()
	privateKey, err := utilities.ParseECDHPrivateKeyFromBase64(privateKeyBase64)
	if err != nil {
		t.Fatalf("ParseECDHPrivateKeyFromBase64() error = %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(publicDER)
}

func mustMarshalPKCS8RSAPrivateKey(t *testing.T, privateKey *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func mustMarshalPKIXRSAPublicKey(t *testing.T, publicKey *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func mustMarshalEd25519PrivateKey(t *testing.T, privateKey ed25519.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func mustMarshalEd25519PublicKey(t *testing.T, publicKey ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func mustBase64Decode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	return decoded
}

func mustSHA256Bytes(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}
