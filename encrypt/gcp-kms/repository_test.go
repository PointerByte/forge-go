// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package gcpkms

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/local"
	"github.com/PointerByte/forge-go/encrypt/models"
	"github.com/PointerByte/forge-go/encrypt/utilities"
	"github.com/spf13/viper"
)

type fakeGCPClient struct {
	createCryptoKeyFn        func(context.Context, *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error)
	createCryptoKeyVersionFn func(context.Context, *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error)
	getCryptoKeyFn           func(context.Context, *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error)
	getPublicKeyFn           func(context.Context, *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error)
	updateKeyVersionFn       func(context.Context, *kmspb.UpdateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error)
	updatePrimaryFn          func(context.Context, *kmspb.UpdateCryptoKeyPrimaryVersionRequest) (*kmspb.CryptoKey, error)
	encryptFn                func(context.Context, *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error)
	decryptFn                func(context.Context, *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error)
	asymmetricSignFn         func(context.Context, *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error)
	asymmetricDecryptFn      func(context.Context, *kmspb.AsymmetricDecryptRequest) (*kmspb.AsymmetricDecryptResponse, error)
	decapsulateFn            func(context.Context, *kmspb.DecapsulateRequest) (*kmspb.DecapsulateResponse, error)
	macSignFn                func(context.Context, *kmspb.MacSignRequest) (*kmspb.MacSignResponse, error)
	macVerifyFn              func(context.Context, *kmspb.MacVerifyRequest) (*kmspb.MacVerifyResponse, error)
	closeFn                  func() error
}

func (fake fakeGCPClient) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	return fake.createCryptoKeyFn(ctx, req)
}
func (fake fakeGCPClient) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	return fake.createCryptoKeyVersionFn(ctx, req)
}
func (fake fakeGCPClient) GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	if fake.getCryptoKeyFn == nil {
		return nil, errors.New("get crypto key not configured")
	}
	return fake.getCryptoKeyFn(ctx, req)
}
func (fake fakeGCPClient) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	return fake.getPublicKeyFn(ctx, req)
}
func (fake fakeGCPClient) UpdateCryptoKeyVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if fake.updateKeyVersionFn == nil {
		return nil, errors.New("update crypto key version not configured")
	}
	return fake.updateKeyVersionFn(ctx, req)
}
func (fake fakeGCPClient) UpdateCryptoKeyPrimaryVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyPrimaryVersionRequest) (*kmspb.CryptoKey, error) {
	if fake.updatePrimaryFn == nil {
		return nil, errors.New("update primary not configured")
	}
	return fake.updatePrimaryFn(ctx, req)
}
func (fake fakeGCPClient) Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	return fake.encryptFn(ctx, req)
}
func (fake fakeGCPClient) Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	return fake.decryptFn(ctx, req)
}
func (fake fakeGCPClient) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	return fake.asymmetricSignFn(ctx, req)
}
func (fake fakeGCPClient) AsymmetricDecrypt(ctx context.Context, req *kmspb.AsymmetricDecryptRequest) (*kmspb.AsymmetricDecryptResponse, error) {
	return fake.asymmetricDecryptFn(ctx, req)
}
func (fake fakeGCPClient) Decapsulate(ctx context.Context, req *kmspb.DecapsulateRequest) (*kmspb.DecapsulateResponse, error) {
	if fake.decapsulateFn == nil {
		return nil, errors.New("decapsulate not configured")
	}
	return fake.decapsulateFn(ctx, req)
}
func (fake fakeGCPClient) MacSign(ctx context.Context, req *kmspb.MacSignRequest) (*kmspb.MacSignResponse, error) {
	return fake.macSignFn(ctx, req)
}
func (fake fakeGCPClient) MacVerify(ctx context.Context, req *kmspb.MacVerifyRequest) (*kmspb.MacVerifyResponse, error) {
	return fake.macVerifyFn(ctx, req)
}
func (fake fakeGCPClient) Close() error {
	return fake.closeFn()
}

func TestUIDMetadataHelpers(t *testing.T) {
	if labels := gcpUIDLabels(""); labels != nil {
		t.Fatalf("gcpUIDLabels() = %#v, want nil", labels)
	}
	labels := gcpUIDLabels("User.123/XYZ")
	if labels["uid"] != "user-123-xyz" {
		t.Fatalf("gcpUIDLabels() = %#v, want sanitized uid label", labels)
	}

	additional := "aad"
	if got := string(gcpAuthenticatedData("", &additional)); got != "aad" {
		t.Fatalf("gcpAuthenticatedData() = %q, want aad", got)
	}
	if got := string(gcpAuthenticatedData("user-123", &additional)); got != "user-123\x00aad" {
		t.Fatalf("gcpAuthenticatedData() = %q, want uid and aad", got)
	}
}

func TestGCPKeyRepositoryRotateAndGetKey(t *testing.T) {
	t.Cleanup(viper.Reset)
	previousClient := newGCPClientFn
	t.Cleanup(func() { newGCPClientFn = previousClient })

	privateKey := mustGCPRSAKey(t)
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}

	newGCPClientFn = func(context.Context) (gcpKMSClient, error) {
		return fakeGCPClient{
			createCryptoKeyVersionFn: func(_ context.Context, req *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
				return &kmspb.CryptoKeyVersion{Name: req.Parent + "/cryptoKeyVersions/2"}, nil
			},
			getCryptoKeyFn: func(_ context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
				switch {
				case strings.HasSuffix(req.Name, "/cryptoKeys/sym-key"):
					return &kmspb.CryptoKey{
						Name:    req.Name,
						Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
							Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
						},
						Primary: &kmspb.CryptoKeyVersion{Name: req.Name + "/cryptoKeyVersions/1"},
					}, nil
				case strings.HasSuffix(req.Name, "/cryptoKeys/rsa-key"):
					return &kmspb.CryptoKey{
						Name:    req.Name,
						Purpose: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
						VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
							Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
						},
					}, nil
				default:
					return nil, errors.New("unexpected crypto key")
				}
			},
			getPublicKeyFn: func(_ context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
				if req.Name != "projects/test/locations/global/keyRings/ring/cryptoKeys/rsa-key/cryptoKeyVersions/1" {
					t.Fatalf("GetPublicKey() name = %q", req.Name)
				}
				return &kmspb.PublicKey{Pem: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))}, nil
			},
			updateKeyVersionFn: func(_ context.Context, req *kmspb.UpdateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
				if req.CryptoKeyVersion.GetName() != "projects/test/locations/global/keyRings/ring/cryptoKeys/rsa-key/cryptoKeyVersions/1" {
					t.Fatalf("UpdateCryptoKeyVersion() name = %q", req.CryptoKeyVersion.GetName())
				}
				if req.CryptoKeyVersion.GetState() != kmspb.CryptoKeyVersion_DISABLED {
					t.Fatalf("UpdateCryptoKeyVersion() state = %s, want DISABLED", req.CryptoKeyVersion.GetState())
				}
				if req.UpdateMask == nil || len(req.UpdateMask.Paths) != 1 || req.UpdateMask.Paths[0] != "state" {
					t.Fatalf("UpdateCryptoKeyVersion() update mask = %#v", req.UpdateMask)
				}
				return &kmspb.CryptoKeyVersion{Name: req.CryptoKeyVersion.GetName(), State: kmspb.CryptoKeyVersion_DISABLED}, nil
			},
			updatePrimaryFn: func(_ context.Context, req *kmspb.UpdateCryptoKeyPrimaryVersionRequest) (*kmspb.CryptoKey, error) {
				if req.Name != "projects/test/locations/global/keyRings/ring/cryptoKeys/sym-key" || req.CryptoKeyVersionId != "2" {
					t.Fatalf("UpdateCryptoKeyPrimaryVersion() = %#v", req)
				}
				return &kmspb.CryptoKey{
					Name:    req.Name,
					Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
					Primary: &kmspb.CryptoKeyVersion{
						Name: req.Name + "/cryptoKeyVersions/" + req.CryptoKeyVersionId,
					},
				}, nil
			},
			closeFn: func() error { return nil },
		}, nil
	}

	viper.Set(defaultGCPKeyIDKey, "projects/test/locations/global/keyRings/ring/cryptoKeys/default/cryptoKeyVersions/1")
	repository := NewKeyRepository()

	rotatedKey, err := repository.RotateKey(context.Background(), models.RotateKeyRequest{KeyID: "sym-key"})
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	if rotatedKey.KeyID != "sym-key" || rotatedKey.KeyRef != "projects/test/locations/global/keyRings/ring/cryptoKeys/sym-key" || rotatedKey.Provider != gcpProviderName {
		t.Fatalf("RotateKey() = %#v, want symmetric key metadata", rotatedKey)
	}

	rsaKey, err := repository.GetKey(context.Background(), models.GetKeyRequest{KeyID: "rsa-key"})
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}
	if rsaKey.KeyID != "rsa-key" || rsaKey.KeyRef != "projects/test/locations/global/keyRings/ring/cryptoKeys/rsa-key/cryptoKeyVersions/1" || rsaKey.PublicKey == "" {
		t.Fatalf("GetKey() = %#v, want RSA key metadata", rsaKey)
	}

	if err := repository.DeactivateKey(context.Background(), models.DeactivateKeyRequest{KeyID: "rsa-key"}); err != nil {
		t.Fatalf("DeactivateKey() error = %v", err)
	}
}

func TestGCPRepositoryProviderFlowsAndHelpers(t *testing.T) {
	t.Cleanup(viper.Reset)
	previousClient := newGCPClientFn
	t.Cleanup(func() { newGCPClientFn = previousClient })

	privateKey := mustGCPRSAKey(t)
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	edPublicDER, err := x509.MarshalPKIXPublicKey(edPublic)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	edPrivateDER, err := x509.MarshalPKCS8PrivateKey(edPrivate)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	kemPrivate, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("mlkem.GenerateKey768() error = %v", err)
	}

	newGCPClientFn = func(context.Context) (gcpKMSClient, error) {
		return fakeGCPClient{
			createCryptoKeyFn: func(_ context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
				name := req.Parent + "/cryptoKeys/" + req.CryptoKeyId
				primary := &kmspb.CryptoKeyVersion{Name: name + "/cryptoKeyVersions/1"}
				if req.CryptoKey.GetPurpose() == kmspb.CryptoKey_ENCRYPT_DECRYPT || req.CryptoKey.GetPurpose() == kmspb.CryptoKey_KEY_ENCAPSULATION {
					return &kmspb.CryptoKey{Name: name, Primary: primary}, nil
				}
				return &kmspb.CryptoKey{Name: name}, nil
			},
			createCryptoKeyVersionFn: func(_ context.Context, req *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
				return &kmspb.CryptoKeyVersion{Name: req.Parent + "/cryptoKeyVersions/1"}, nil
			},
			getPublicKeyFn: func(_ context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
				if req.PublicKeyFormat == kmspb.PublicKey_NIST_PQC {
					return &kmspb.PublicKey{
						Algorithm: kmspb.CryptoKeyVersion_ML_KEM_768,
						PublicKey: &kmspb.ChecksummedData{Data: kemPrivate.EncapsulationKey().Bytes()},
					}, nil
				}
				if req.Name == "projects/test/locations/global/keyRings/ring/cryptoKeys/ed/cryptoKeyVersions/1" {
					return &kmspb.PublicKey{Pem: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edPublicDER}))}, nil
				}
				return &kmspb.PublicKey{Pem: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))}, nil
			},
			encryptFn: func(_ context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
				return &kmspb.EncryptResponse{Ciphertext: []byte("cipher")}, nil
			},
			decryptFn: func(_ context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
				return &kmspb.DecryptResponse{Plaintext: []byte("hello")}, nil
			},
			asymmetricSignFn: func(_ context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
				if len(req.Data) > 0 {
					return &kmspb.AsymmetricSignResponse{Signature: ed25519.Sign(edPrivate, req.Data)}, nil
				}
				hashed := req.Digest.GetSha256()
				var (
					signature []byte
					err       error
				)
				if req.Name == "projects/test/locations/global/keyRings/ring/cryptoKeys/rsa-pss/cryptoKeyVersions/1" {
					signature, err = rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed, nil)
				} else {
					signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
				}
				if err != nil {
					return nil, err
				}
				return &kmspb.AsymmetricSignResponse{Signature: signature}, nil
			},
			asymmetricDecryptFn: func(_ context.Context, req *kmspb.AsymmetricDecryptRequest) (*kmspb.AsymmetricDecryptResponse, error) {
				return &kmspb.AsymmetricDecryptResponse{Plaintext: []byte("plain")}, nil
			},
			decapsulateFn: func(_ context.Context, req *kmspb.DecapsulateRequest) (*kmspb.DecapsulateResponse, error) {
				sharedSecret, err := kemPrivate.Decapsulate(req.Ciphertext)
				if err != nil {
					return nil, err
				}
				return &kmspb.DecapsulateResponse{SharedSecret: sharedSecret}, nil
			},
			macSignFn: func(_ context.Context, req *kmspb.MacSignRequest) (*kmspb.MacSignResponse, error) {
				return &kmspb.MacSignResponse{Mac: []byte("mac")}, nil
			},
			macVerifyFn: func(_ context.Context, req *kmspb.MacVerifyRequest) (*kmspb.MacVerifyResponse, error) {
				return &kmspb.MacVerifyResponse{Success: true}, nil
			},
			closeFn: func() error { return nil },
		}, nil
	}

	viper.Set(defaultGCPKeyIDKey, "projects/test/locations/global/keyRings/ring/cryptoKeys/default/cryptoKeyVersions/1")
	repository := NewRepository()
	keyName := "projects/test/locations/global/keyRings/ring/cryptoKeys/sym"
	additional := "aad"

	key, err := repository.GenerateSymetrycKeys(context.Background(), models.GenerateSymmetricKeyRequest{Size: common.Key256Bits})
	if err != nil || key == nil || key.Provider != gcpProviderName {
		t.Fatalf("GenerateSymetrycKeys() = %#v, %v", key, err)
	}
	ciphertext, err := repository.EncryptAES(context.Background(), models.EncryptAESRequest{SecretKey: keyName, Value: "hello", Additional: &additional})
	if err != nil {
		t.Fatalf("EncryptAES() error = %v", err)
	}
	if plaintext, err := repository.DecryptAES(context.Background(), models.DecryptAESRequest{SecretKey: keyName, CipherValue: ciphertext, Additional: &additional}); err != nil || plaintext != "hello" {
		t.Fatalf("DecryptAES() = %q, %v", plaintext, err)
	}
	if got := repository.HMAC(context.Background(), viper.GetString(defaultGCPKeyIDKey), "message"); got == "" {
		t.Fatal("expected HMAC() to return a value")
	}
	if repository.Sha256Hex(context.Background(), "message") == "" || repository.Blake3(context.Background(), "message") == "" {
		t.Fatal("expected hash helpers to return values")
	}

	rsaKey, err := repository.GenerateRSAKeys(context.Background(), models.GenerateRSAKeyRequest{Size: common.Key2048Bits})
	if err != nil || rsaKey == nil || rsaKey.PublicKey == "" {
		t.Fatalf("GenerateRSAKeys() = %#v, %v", rsaKey, err)
	}
	if _, err := repository.RSA_OAEP_Encode(context.Background(), models.RSAOAEPEncodeRequest{PublicKey: "projects/test/locations/global/keyRings/ring/cryptoKeys/rsa/cryptoKeyVersions/1", Text: "payload"}); err != nil {
		t.Fatalf("RSA_OAEP_Encode() error = %v", err)
	}
	if plaintext, err := repository.RSA_OAEP_Decode(context.Background(), models.RSAOAEPDecodeRequest{PrivateKey: "projects/test/locations/global/keyRings/ring/cryptoKeys/rsa/cryptoKeyVersions/1", CipherText: base64.StdEncoding.EncodeToString([]byte("cipher"))}); err != nil || plaintext != "plain" {
		t.Fatalf("RSA_OAEP_Decode() = %q, %v", plaintext, err)
	}
	if _, err := repository.GenerateEd255Keys(context.Background()); err != nil {
		t.Fatalf("GenerateEd255Keys() error = %v", err)
	}
	kemKey, err := repository.GenerateECDHCurveKeys(context.Background(), models.GenerateECDHCurveKeyRequest{Curve: common.CurveP256})
	if err != nil || kemKey == nil || kemKey.PublicKey == "" {
		t.Fatalf("GenerateECDHCurveKeys() = %#v, %v", kemKey, err)
	}
	kemCiphertext, err := repository.ECDH_Encode(context.Background(), models.ECDHEncodeRequest{PublicKey: kemKey.KeyRef, Text: "payload"})
	if err != nil {
		t.Fatalf("ECDH_Encode() gcp kem error = %v", err)
	}
	if plaintext, err := repository.ECDH_Decode(context.Background(), models.ECDHDecodeRequest{PrivateKey: kemKey.KeyRef, CipherText: kemCiphertext}); err != nil || plaintext != "payload" {
		t.Fatalf("ECDH_Decode() gcp kem = %q, %v", plaintext, err)
	}
	edSignature, err := repository.SignEd25519(context.Background(), "projects/test/locations/global/keyRings/ring/cryptoKeys/ed/cryptoKeyVersions/1", "payload")
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}
	if err := repository.VerifyEd25519(context.Background(), "projects/test/locations/global/keyRings/ring/cryptoKeys/ed/cryptoKeyVersions/1", "payload", edSignature); err != nil {
		t.Fatalf("VerifyEd25519() error = %v", err)
	}
	rsaPSSSignature, err := repository.SignRSAPSS(context.Background(), "projects/test/locations/global/keyRings/ring/cryptoKeys/rsa-pss/cryptoKeyVersions/1", "payload")
	if err != nil {
		t.Fatalf("SignRSAPSS() error = %v", err)
	}
	if err := repository.VerifyRSAPSS(context.Background(), "projects/test/locations/global/keyRings/ring/cryptoKeys/rsa-pss/cryptoKeyVersions/1", "payload", rsaPSSSignature); err != nil {
		t.Fatalf("VerifyRSAPSS() error = %v", err)
	}
	rsaSignature, err := repository.Sign_RSA_PKCS1v15_SHA256(context.Background(), "", "payload")
	if err != nil {
		t.Fatalf("Sign_RSA_PKCS1v15_SHA256() error = %v", err)
	}
	if err := repository.Verify_RSA_PKCS1v15_SHA256(context.Background(), "payload", "", rsaSignature); err != nil {
		t.Fatalf("Verify_RSA_PKCS1v15_SHA256() error = %v", err)
	}

	localRepository := local.NewRepository()
	localSymmetricKey, err := localRepository.GenerateSymetrycKeys(context.Background(), models.GenerateSymmetricKeyRequest{Size: common.Key256Bits})
	if err != nil {
		t.Fatalf("local GenerateSymetrycKeys() error = %v", err)
	}
	localCiphertext, err := localRepository.EncryptAES(context.Background(), models.EncryptAESRequest{SecretKey: localSymmetricKey.KeyID, Value: "hello", Additional: &additional})
	if err != nil {
		t.Fatalf("local EncryptAES() error = %v", err)
	}
	if _, err := repository.DecryptAES(context.Background(), models.DecryptAESRequest{SecretKey: localSymmetricKey.KeyID, CipherValue: localCiphertext, Additional: &additional}); err != nil {
		t.Fatalf("DecryptAES() local fallback error = %v", err)
	}
	localRSAPrivate := mustGCPRSAPrivateBase64(t, privateKey)
	localRSAPublic := mustGCPRSAPublicBase64(t, &privateKey.PublicKey)
	localRSACiphertext, err := repository.RSA_OAEP_Encode(context.Background(), models.RSAOAEPEncodeRequest{PublicKey: localRSAPublic, Text: "payload"})
	if err != nil {
		t.Fatalf("RSA_OAEP_Encode() local fallback error = %v", err)
	}
	if _, err := repository.RSA_OAEP_Decode(context.Background(), models.RSAOAEPDecodeRequest{PrivateKey: localRSAPrivate, CipherText: localRSACiphertext}); err != nil {
		t.Fatalf("RSA_OAEP_Decode() local fallback error = %v", err)
	}
	localECCPrivate := mustGCPECCPrivateBase64(t, ecdh.P256())
	localECCPublic := mustGCPECCPublicBase64(t, localECCPrivate)
	localEccCiphertext, err := repository.ECDH_Encode(context.Background(), models.ECDHEncodeRequest{PublicKey: localECCPublic, Text: "payload"})
	if err != nil {
		t.Fatalf("ECDH_Encode() local fallback error = %v", err)
	}
	if plaintext, err := repository.ECDH_Decode(context.Background(), models.ECDHDecodeRequest{PrivateKey: localECCPrivate, CipherText: localEccCiphertext}); err != nil || plaintext != "payload" {
		t.Fatalf("ECDH_Decode() local fallback = %q, %v", plaintext, err)
	}
	localPSSSignature, err := repository.SignRSAPSS(context.Background(), localRSAPrivate, "payload")
	if err != nil {
		t.Fatalf("SignRSAPSS() local fallback error = %v", err)
	}
	if err := repository.VerifyRSAPSS(context.Background(), localRSAPublic, "payload", localPSSSignature); err != nil {
		t.Fatalf("VerifyRSAPSS() local fallback error = %v", err)
	}
	localSHA256Signature, err := repository.Sign_RSA_PKCS1v15_SHA256(context.Background(), localRSAPrivate, "payload")
	if err != nil {
		t.Fatalf("Sign_RSA_PKCS1v15_SHA256() local fallback error = %v", err)
	}
	if err := repository.Verify_RSA_PKCS1v15_SHA256(context.Background(), "payload", localRSAPublic, localSHA256Signature); err != nil {
		t.Fatalf("Verify_RSA_PKCS1v15_SHA256() local fallback error = %v", err)
	}
	localEdPrivate := base64.StdEncoding.EncodeToString(edPrivateDER)
	localEdPublic := base64.StdEncoding.EncodeToString(edPublicDER)
	localEdSignature, err := repository.SignEd25519(context.Background(), localEdPrivate, "payload")
	if err != nil {
		t.Fatalf("SignEd25519() local fallback error = %v", err)
	}
	if err := repository.VerifyEd25519(context.Background(), localEdPublic, "payload", localEdSignature); err != nil {
		t.Fatalf("VerifyEd25519() local fallback error = %v", err)
	}

	if got := configuredGCPKeyID(); got == "" {
		t.Fatal("expected configuredGCPKeyID() value")
	}
	if got, err := resolveGCPKeyRingName("projects/test/locations/global/keyRings/ring/cryptoKeys/key"); err != nil || got != "projects/test/locations/global/keyRings/ring" {
		t.Fatalf("resolveGCPKeyRingName() = %q, %v", got, err)
	}
	if got, err := resolveGCPCryptoKeyName("projects/test/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1"); err != nil || got != "projects/test/locations/global/keyRings/ring/cryptoKeys/key" {
		t.Fatalf("resolveGCPCryptoKeyName() = %q, %v", got, err)
	}
	if !looksLikeGCPKMSKeyReference("projects/test/locations/global/keyRings/ring/cryptoKeys/key") || looksLikeGCPKMSKeyReference("local") {
		t.Fatal("unexpected looksLikeGCPKMSKeyReference() result")
	}
	if got := utilities.BytesFromOptionalString(nil); got != nil {
		t.Fatal("expected utilities.BytesFromOptionalString(nil) to return nil")
	}
	if utilities.IsLocalAESKey("%%%") {
		t.Fatal("expected utilities.IsLocalAESKey() false for invalid base64")
	}
}

func TestGCPRepositoryErrorBranches(t *testing.T) {
	t.Cleanup(viper.Reset)
	previousClient := newGCPClientFn
	t.Cleanup(func() { newGCPClientFn = previousClient })

	if _, err := NewSymmetricRepository().GenerateSymetrycKeys(context.Background(), models.GenerateSymmetricKeyRequest{Size: common.Key128Bits}); err == nil {
		t.Fatal("expected unsupported symmetric size error")
	}
	if _, err := NewAsymmetricRepository().GenerateRSAKeys(context.Background(), models.GenerateRSAKeyRequest{Size: 0}); err == nil {
		t.Fatal("expected unsupported rsa size error")
	}
	if _, err := resolveGCPKeyRingName(""); err == nil {
		t.Fatal("expected resolveGCPKeyRingName() error")
	}
	if _, err := resolveGCPCryptoKeyName(""); err == nil {
		t.Fatal("expected resolveGCPCryptoKeyName() error")
	}
	if _, err := resolveGCPCryptoKeyVersionName("projects/test/locations/global/keyRings/ring/cryptoKeys/key"); err == nil {
		t.Fatal("expected resolveGCPCryptoKeyVersionName() error")
	}
	if _, err := gcpRSADecryptAlgorithm(0); err == nil {
		t.Fatal("expected gcpRSADecryptAlgorithm() error")
	}
	if _, err := gcpRSADecryptAlgorithm(common.Key3072Bits); err != nil {
		t.Fatalf("gcpRSADecryptAlgorithm(3072) error = %v", err)
	}
	if _, err := gcpRSADecryptAlgorithm(common.Key4096Bits); err != nil {
		t.Fatalf("gcpRSADecryptAlgorithm(4096) error = %v", err)
	}
	viper.Set(defaultGCPKeyIDKey, "projects/test/locations/global/keyRings/ring/cryptoKeys/default/cryptoKeyVersions/1")
	if !looksLikeGCPKMSKeyReference("") {
		t.Fatal("expected looksLikeGCPKMSKeyReference(\"\") to be true with config")
	}

	newGCPClientFn = func(context.Context) (gcpKMSClient, error) {
		return nil, errors.New("client boom")
	}
	if _, err := newGCPClient(context.Background()); err == nil {
		t.Fatal("expected newGCPClient() error")
	}

	newGCPClientFn = func(context.Context) (gcpKMSClient, error) {
		return fakeGCPClient{
			createCryptoKeyFn: func(context.Context, *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
				return nil, errors.New("create boom")
			},
			createCryptoKeyVersionFn: func(context.Context, *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
				return nil, errors.New("create version boom")
			},
			getPublicKeyFn: func(context.Context, *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
				return &kmspb.PublicKey{Pem: "bad pem"}, nil
			},
			encryptFn: func(context.Context, *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
				return nil, errors.New("encrypt boom")
			},
			decryptFn: func(context.Context, *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
				return nil, errors.New("decrypt boom")
			},
			asymmetricSignFn: func(context.Context, *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
				return nil, errors.New("sign boom")
			},
			asymmetricDecryptFn: func(context.Context, *kmspb.AsymmetricDecryptRequest) (*kmspb.AsymmetricDecryptResponse, error) {
				return nil, errors.New("decrypt boom")
			},
			macSignFn: func(context.Context, *kmspb.MacSignRequest) (*kmspb.MacSignResponse, error) {
				return nil, errors.New("mac sign boom")
			},
			macVerifyFn: func(context.Context, *kmspb.MacVerifyRequest) (*kmspb.MacVerifyResponse, error) {
				return nil, errors.New("mac verify boom")
			},
			closeFn: func() error { return nil },
		}, nil
	}

	viper.Set(defaultGCPKeyIDKey, "projects/test/locations/global/keyRings/ring/cryptoKeys/default/cryptoKeyVersions/1")
	symmetricRepository := NewSymmetricRepository()
	hashRepository := NewHashRepository()
	keyRepository := NewKeyRepository()
	asymmetricRepository := NewAsymmetricRepository()
	signatureRepository := NewSignatureRepository()

	if _, err := symmetricRepository.GenerateSymetrycKeys(context.Background(), models.GenerateSymmetricKeyRequest{Size: common.Key256Bits}); err == nil {
		t.Fatal("expected GenerateSymetrycKeys() provider error")
	}
	if _, err := symmetricRepository.EncryptAES(context.Background(), models.EncryptAESRequest{SecretKey: "", Value: "payload", Additional: nil}); err == nil {
		t.Fatal("expected EncryptAES() key name error")
	}
	if _, err := symmetricRepository.EncryptAES(context.Background(), models.EncryptAESRequest{SecretKey: "projects/test/locations/global/keyRings/ring/cryptoKeys/key", Value: "payload", Additional: nil}); err == nil {
		t.Fatal("expected EncryptAES() provider error")
	}
	if _, err := symmetricRepository.DecryptAES(context.Background(), models.DecryptAESRequest{SecretKey: "projects/test/locations/global/keyRings/ring/cryptoKeys/key", CipherValue: "%%%", Additional: nil}); err == nil {
		t.Fatal("expected DecryptAES() decode error")
	}
	if _, err := symmetricRepository.DecryptAES(context.Background(), models.DecryptAESRequest{SecretKey: "projects/test/locations/global/keyRings/ring/cryptoKeys/key", CipherValue: base64.StdEncoding.EncodeToString([]byte("cipher")), Additional: nil}); err == nil {
		t.Fatal("expected DecryptAES() provider error")
	}
	if _, err := asymmetricRepository.GenerateRSAKeys(context.Background(), models.GenerateRSAKeyRequest{Size: common.Key2048Bits}); err == nil {
		t.Fatal("expected GenerateRSAKeys() provider error")
	}
	if _, err := asymmetricRepository.RSA_OAEP_Encode(context.Background(), models.RSAOAEPEncodeRequest{PublicKey: "", Text: "payload"}); err == nil {
		t.Fatal("expected RSA_OAEP_Encode() version error")
	}
	if _, err := asymmetricRepository.RSA_OAEP_Encode(context.Background(), models.RSAOAEPEncodeRequest{PublicKey: "projects/test/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1", Text: "payload"}); err == nil {
		t.Fatal("expected RSA_OAEP_Encode() provider error")
	}
	if _, err := asymmetricRepository.RSA_OAEP_Decode(context.Background(), models.RSAOAEPDecodeRequest{PrivateKey: "", CipherText: "%%%"}); err == nil {
		t.Fatal("expected RSA_OAEP_Decode() decode error")
	}
	if _, err := asymmetricRepository.RSA_OAEP_Decode(context.Background(), models.RSAOAEPDecodeRequest{PrivateKey: "projects/test/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1", CipherText: base64.StdEncoding.EncodeToString([]byte("cipher"))}); err == nil {
		t.Fatal("expected RSA_OAEP_Decode() provider error")
	}
	if _, err := asymmetricRepository.GenerateECDHCurveKeys(context.Background(), models.GenerateECDHCurveKeyRequest{Curve: common.CurveP256}); err == nil {
		t.Fatal("expected GenerateECDHCurveKeys() provider error")
	}
	if _, err := asymmetricRepository.ECDH_Encode(context.Background(), models.ECDHEncodeRequest{PublicKey: "projects/test/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1", Text: "payload"}); err == nil {
		t.Fatal("expected ECDH_Encode() provider error")
	}
	if _, err := asymmetricRepository.ECDH_Decode(context.Background(), models.ECDHDecodeRequest{PrivateKey: "projects/test/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1", CipherText: "payload"}); err == nil {
		t.Fatal("expected ECDH_Decode() payload error")
	}
	if got := hashRepository.HMAC(context.Background(), viper.GetString(defaultGCPKeyIDKey), "message"); got != "" {
		t.Fatalf("HMAC() = %q, want empty string on provider error", got)
	}
	if _, err := keyRepository.RotateKey(context.Background(), models.RotateKeyRequest{KeyID: "projects/test/locations/global/keyRings/ring/cryptoKeys/key"}); err == nil {
		t.Fatal("expected RotateKey() provider error")
	}
	if _, err := keyRepository.GetKey(context.Background(), models.GetKeyRequest{KeyID: "projects/test/locations/global/keyRings/ring/cryptoKeys/key"}); err == nil {
		t.Fatal("expected GetKey() provider error")
	}
	if err := keyRepository.DeactivateKey(context.Background(), models.DeactivateKeyRequest{KeyID: "projects/test/locations/global/keyRings/ring/cryptoKeys/key"}); err == nil {
		t.Fatal("expected DeactivateKey() provider error")
	}
	if _, err := signatureRepository.GenerateEd255Keys(context.Background()); err == nil {
		t.Fatal("expected GenerateEd255Keys() provider error")
	}
	if _, err := signatureRepository.SignEd25519(context.Background(), "", "payload"); err == nil {
		t.Fatal("expected SignEd25519() version error")
	}
	if err := signatureRepository.VerifyEd25519(context.Background(), "", "payload", "%%%"); err == nil {
		t.Fatal("expected VerifyEd25519() decode error")
	}
	if _, err := signatureRepository.SignEd25519(context.Background(), "projects/test/locations/global/keyRings/ring/cryptoKeys/ed/cryptoKeyVersions/1", "payload"); err == nil {
		t.Fatal("expected SignEd25519() provider error")
	}
	if err := signatureRepository.VerifyEd25519(context.Background(), "projects/test/locations/global/keyRings/ring/cryptoKeys/ed/cryptoKeyVersions/1", "payload", base64.StdEncoding.EncodeToString([]byte("sig"))); err == nil {
		t.Fatal("expected VerifyEd25519() wrong public key error")
	}
	if _, err := signatureRepository.SignRSAPSS(context.Background(), "", "payload"); err == nil {
		t.Fatal("expected SignRSAPSS() version error")
	}
	if err := signatureRepository.VerifyRSAPSS(context.Background(), "", "payload", "%%%"); err == nil {
		t.Fatal("expected VerifyRSAPSS() decode error")
	}
	if _, err := signatureRepository.SignRSAPSS(context.Background(), "projects/test/locations/global/keyRings/ring/cryptoKeys/rsa-pss/cryptoKeyVersions/1", "payload"); err == nil {
		t.Fatal("expected SignRSAPSS() provider error")
	}
	if err := signatureRepository.VerifyRSAPSS(context.Background(), "projects/test/locations/global/keyRings/ring/cryptoKeys/rsa-pss/cryptoKeyVersions/1", "payload", base64.StdEncoding.EncodeToString([]byte("sig"))); err == nil {
		t.Fatal("expected VerifyRSAPSS() wrong public key error")
	}
	if _, err := signatureRepository.Sign_RSA_PKCS1v15_SHA256(context.Background(), "", "payload"); err == nil {
		t.Fatal("expected Sign_RSA_PKCS1v15_SHA256() provider error")
	}
	if err := signatureRepository.Verify_RSA_PKCS1v15_SHA256(context.Background(), "payload", "", "%%%"); err == nil {
		t.Fatal("expected Verify_RSA_PKCS1v15_SHA256() decode error")
	}
	if err := signatureRepository.Verify_RSA_PKCS1v15_SHA256(context.Background(), "payload", "", base64.StdEncoding.EncodeToString([]byte("sig"))); err == nil {
		t.Fatal("expected Verify_RSA_PKCS1v15_SHA256() wrong public key error")
	}
	if _, err := ensureGCPVersion(context.Background(), fakeGCPClient{
		createCryptoKeyFn: func(context.Context, *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) { return nil, nil },
		createCryptoKeyVersionFn: func(context.Context, *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
			return &kmspb.CryptoKeyVersion{}, nil
		},
		getPublicKeyFn: func(context.Context, *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) { return nil, nil },
		encryptFn:      func(context.Context, *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) { return nil, nil },
		decryptFn:      func(context.Context, *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) { return nil, nil },
		asymmetricSignFn: func(context.Context, *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
			return nil, nil
		},
		asymmetricDecryptFn: func(context.Context, *kmspb.AsymmetricDecryptRequest) (*kmspb.AsymmetricDecryptResponse, error) {
			return nil, nil
		},
		macSignFn:   func(context.Context, *kmspb.MacSignRequest) (*kmspb.MacSignResponse, error) { return nil, nil },
		macVerifyFn: func(context.Context, *kmspb.MacVerifyRequest) (*kmspb.MacVerifyResponse, error) { return nil, nil },
		closeFn:     func() error { return nil },
	}, "name", kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256, nil); err == nil {
		t.Fatal("expected ensureGCPVersion() missing metadata error")
	}
	if _, err := fetchGCPPublicKey(context.Background(), fakeGCPClient{
		getPublicKeyFn: func(context.Context, *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
			return &kmspb.PublicKey{Pem: "bad pem"}, nil
		},
		createCryptoKeyFn: func(context.Context, *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) { return nil, nil },
		createCryptoKeyVersionFn: func(context.Context, *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
			return nil, nil
		},
		encryptFn: func(context.Context, *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) { return nil, nil },
		decryptFn: func(context.Context, *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) { return nil, nil },
		asymmetricSignFn: func(context.Context, *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
			return nil, nil
		},
		asymmetricDecryptFn: func(context.Context, *kmspb.AsymmetricDecryptRequest) (*kmspb.AsymmetricDecryptResponse, error) {
			return nil, nil
		},
		macSignFn:   func(context.Context, *kmspb.MacSignRequest) (*kmspb.MacSignResponse, error) { return nil, nil },
		macVerifyFn: func(context.Context, *kmspb.MacVerifyRequest) (*kmspb.MacVerifyResponse, error) { return nil, nil },
		closeFn:     func() error { return nil },
	}, "name"); err == nil {
		t.Fatal("expected fetchGCPPublicKey() invalid PEM error")
	}
}

func TestGCPHelperBranches(t *testing.T) {
	t.Cleanup(viper.Reset)

	viper.Set(defaultGCPKeyIDKey, "projects/test/locations/global/keyRings/ring/cryptoKeys/default/cryptoKeyVersions/7")
	keyName, versionName, err := resolveGCPKeyLookupNames("")
	if err != nil || keyName != "projects/test/locations/global/keyRings/ring/cryptoKeys/default" || versionName != "projects/test/locations/global/keyRings/ring/cryptoKeys/default/cryptoKeyVersions/7" {
		t.Fatalf("resolveGCPKeyLookupNames(default) = %q, %q, %v", keyName, versionName, err)
	}
	keyName, versionName, err = resolveGCPKeyLookupNames("projects/test/locations/global/keyRings/ring/cryptoKeys/direct")
	if err != nil || keyName != "projects/test/locations/global/keyRings/ring/cryptoKeys/direct" || versionName != "" {
		t.Fatalf("resolveGCPKeyLookupNames(key) = %q, %q, %v", keyName, versionName, err)
	}
	keyName, versionName, err = resolveGCPKeyLookupNames("short")
	if err != nil || keyName != "projects/test/locations/global/keyRings/ring/cryptoKeys/short" || versionName != "" {
		t.Fatalf("resolveGCPKeyLookupNames(short) = %q, %q, %v", keyName, versionName, err)
	}
	viper.Reset()
	if _, _, err := resolveGCPKeyLookupNames(""); err == nil {
		t.Fatal("expected resolveGCPKeyLookupNames() missing key error")
	}

	if got, err := gcpRotationAlgorithm(&kmspb.CryptoKey{VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256}}); err != nil || got != kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256 {
		t.Fatalf("gcpRotationAlgorithm(template) = %s, %v", got, err)
	}
	if got, err := gcpRotationAlgorithm(&kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT}); err != nil || got != kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION {
		t.Fatalf("gcpRotationAlgorithm(symmetric) = %s, %v", got, err)
	}
	if _, err := gcpRotationAlgorithm(&kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN}); err == nil {
		t.Fatal("expected gcpRotationAlgorithm() missing algorithm error")
	}

	if got := gcpPublicVersionName("key", &kmspb.CryptoKey{}, "explicit"); got != "explicit" {
		t.Fatalf("gcpPublicVersionName(explicit) = %q", got)
	}
	if got := gcpPublicVersionName("key", &kmspb.CryptoKey{Primary: &kmspb.CryptoKeyVersion{Name: "primary"}}, ""); got != "primary" {
		t.Fatalf("gcpPublicVersionName(primary) = %q", got)
	}
	if got := gcpPublicVersionName("key/", &kmspb.CryptoKey{}, ""); got != "key/cryptoKeyVersions/1" {
		t.Fatalf("gcpPublicVersionName(fallback) = %q", got)
	}

	if got := gcpLabelValue("___"); got != "" {
		t.Fatalf("gcpLabelValue(only separators) = %q, want empty", got)
	}
	long := strings.Repeat("a", 70)
	if got := gcpLabelValue(long); len(got) != 63 {
		t.Fatalf("gcpLabelValue(long) len = %d, want 63", len(got))
	}
}

func TestGCPKeyDataAndKEMHelpers(t *testing.T) {
	privateKey := mustGCPRSAKey(t)
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	kemPrivate768, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("mlkem.GenerateKey768() error = %v", err)
	}
	kemPrivate1024, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatalf("mlkem.GenerateKey1024() error = %v", err)
	}

	client := fakeGCPClient{
		getPublicKeyFn: func(_ context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
			if req.PublicKeyFormat == kmspb.PublicKey_NIST_PQC {
				return &kmspb.PublicKey{
					Algorithm: kmspb.CryptoKeyVersion_ML_KEM_768,
					PublicKey: &kmspb.ChecksummedData{Data: kemPrivate768.EncapsulationKey().Bytes()},
				}, nil
			}
			return &kmspb.PublicKey{Pem: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))}, nil
		},
	}

	if _, err := gcpKeyDataFromCryptoKey(context.Background(), client, &kmspb.CryptoKey{}, "", ""); err == nil {
		t.Fatal("expected gcpKeyDataFromCryptoKey() missing metadata error")
	}
	keyData, err := gcpKeyDataFromCryptoKey(context.Background(), client, &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT}, "projects/test/locations/global/keyRings/ring/cryptoKeys/sym", "")
	if err != nil || keyData.KeyID != "sym" || keyData.KeyRef != "projects/test/locations/global/keyRings/ring/cryptoKeys/sym" || keyData.Provider != gcpProviderName {
		t.Fatalf("gcpKeyDataFromCryptoKey(symmetric) = %#v, %v", keyData, err)
	}
	keyData, err = gcpKeyDataFromCryptoKey(context.Background(), client, &kmspb.CryptoKey{
		Name:    "projects/test/locations/global/keyRings/ring/cryptoKeys/rsa",
		Purpose: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
	}, "", "projects/test/locations/global/keyRings/ring/cryptoKeys/rsa/cryptoKeyVersions/3")
	if err != nil || keyData.PublicKey == "" || keyData.KeyRef != "projects/test/locations/global/keyRings/ring/cryptoKeys/rsa/cryptoKeyVersions/3" {
		t.Fatalf("gcpKeyDataFromCryptoKey(asymmetric) = %#v, %v", keyData, err)
	}
	keyData, err = gcpKeyDataFromCryptoKey(context.Background(), client, &kmspb.CryptoKey{
		Name:    "projects/test/locations/global/keyRings/ring/cryptoKeys/kem",
		Purpose: kmspb.CryptoKey_KEY_ENCAPSULATION,
	}, "", "")
	if err != nil || keyData.PublicKey == "" || !strings.HasSuffix(keyData.KeyRef, "/cryptoKeyVersions/1") {
		t.Fatalf("gcpKeyDataFromCryptoKey(kem) = %#v, %v", keyData, err)
	}

	if got, err := gcpKEMAlgorithm(common.CurveP384); err != nil || got != kmspb.CryptoKeyVersion_ML_KEM_1024 {
		t.Fatalf("gcpKEMAlgorithm(P384) = %s, %v", got, err)
	}
	if got, err := gcpKEMAlgorithm(common.CurveP521); err != nil || got != kmspb.CryptoKeyVersion_ML_KEM_1024 {
		t.Fatalf("gcpKEMAlgorithm(P521) = %s, %v", got, err)
	}
	if _, err := gcpKEMAlgorithm(common.CurveAsymmetricKey(99)); err == nil {
		t.Fatal("expected gcpKEMAlgorithm() unsupported curve error")
	}
	if got, err := gcpKEMAlgorithmName(kmspb.CryptoKeyVersion_ML_KEM_1024); err != nil || got != "ML_KEM_1024" {
		t.Fatalf("gcpKEMAlgorithmName(1024) = %q, %v", got, err)
	}
	if _, err := gcpKEMAlgorithmName(kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256); err == nil {
		t.Fatal("expected gcpKEMAlgorithmName() unsupported algorithm error")
	}
	if got, err := gcpKEMAlgorithmFromPublicKey(kemPrivate768.EncapsulationKey().Bytes()); err != nil || got != kmspb.CryptoKeyVersion_ML_KEM_768 {
		t.Fatalf("gcpKEMAlgorithmFromPublicKey(768) = %s, %v", got, err)
	}
	if got, err := gcpKEMAlgorithmFromPublicKey(kemPrivate1024.EncapsulationKey().Bytes()); err != nil || got != kmspb.CryptoKeyVersion_ML_KEM_1024 {
		t.Fatalf("gcpKEMAlgorithmFromPublicKey(1024) = %s, %v", got, err)
	}
	if _, err := gcpKEMAlgorithmFromPublicKey([]byte("bad")); err == nil {
		t.Fatal("expected gcpKEMAlgorithmFromPublicKey() size error")
	}

	sharedSecret, ciphertext, err := encapsulateGCPKEM(kemPrivate1024.EncapsulationKey().Bytes(), kmspb.CryptoKeyVersion_ML_KEM_1024)
	if err != nil || len(sharedSecret) == 0 || len(ciphertext) == 0 {
		t.Fatalf("encapsulateGCPKEM(1024) = %d, %d, %v", len(sharedSecret), len(ciphertext), err)
	}
	if _, _, err := encapsulateGCPKEM([]byte("bad"), kmspb.CryptoKeyVersion_ML_KEM_768); err == nil {
		t.Fatal("expected encapsulateGCPKEM() parse error")
	}
	if _, _, err := encapsulateGCPKEM(kemPrivate768.EncapsulationKey().Bytes(), kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256); err == nil {
		t.Fatal("expected encapsulateGCPKEM() unsupported algorithm error")
	}

	if _, _, err := fetchGCPKEMPublicKey(context.Background(), fakeGCPClient{
		getPublicKeyFn: func(context.Context, *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
			return &kmspb.PublicKey{Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256}, nil
		},
	}, "name"); err == nil {
		t.Fatal("expected fetchGCPKEMPublicKey() unsupported algorithm error")
	}
	if _, _, err := fetchGCPKEMPublicKey(context.Background(), fakeGCPClient{
		getPublicKeyFn: func(context.Context, *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
			return &kmspb.PublicKey{Algorithm: kmspb.CryptoKeyVersion_ML_KEM_768, PublicKey: &kmspb.ChecksummedData{}}, nil
		},
	}, "name"); err == nil {
		t.Fatal("expected fetchGCPKEMPublicKey() missing material error")
	}
}

func TestGCPClientAdapterMethodsEnterWrappedCalls(t *testing.T) {
	adapter := &gcpClientAdapter{KeyManagementClient: (*kms.KeyManagementClient)(nil)}
	assertGCPPanic(t, func() { _, _ = adapter.CreateCryptoKey(context.Background(), &kmspb.CreateCryptoKeyRequest{}) })
	assertGCPPanic(t, func() {
		_, _ = adapter.CreateCryptoKeyVersion(context.Background(), &kmspb.CreateCryptoKeyVersionRequest{})
	})
	assertGCPPanic(t, func() { _, _ = adapter.GetCryptoKey(context.Background(), &kmspb.GetCryptoKeyRequest{}) })
	assertGCPPanic(t, func() { _, _ = adapter.GetPublicKey(context.Background(), &kmspb.GetPublicKeyRequest{}) })
	assertGCPPanic(t, func() {
		_, _ = adapter.UpdateCryptoKeyVersion(context.Background(), &kmspb.UpdateCryptoKeyVersionRequest{})
	})
	assertGCPPanic(t, func() {
		_, _ = adapter.UpdateCryptoKeyPrimaryVersion(context.Background(), &kmspb.UpdateCryptoKeyPrimaryVersionRequest{})
	})
	assertGCPPanic(t, func() { _, _ = adapter.Encrypt(context.Background(), &kmspb.EncryptRequest{}) })
	assertGCPPanic(t, func() { _, _ = adapter.Decrypt(context.Background(), &kmspb.DecryptRequest{}) })
	assertGCPPanic(t, func() { _, _ = adapter.AsymmetricSign(context.Background(), &kmspb.AsymmetricSignRequest{}) })
	assertGCPPanic(t, func() { _, _ = adapter.AsymmetricDecrypt(context.Background(), &kmspb.AsymmetricDecryptRequest{}) })
	assertGCPPanic(t, func() { _, _ = adapter.Decapsulate(context.Background(), &kmspb.DecapsulateRequest{}) })
	assertGCPPanic(t, func() { _, _ = adapter.MacSign(context.Background(), &kmspb.MacSignRequest{}) })
	assertGCPPanic(t, func() { _, _ = adapter.MacVerify(context.Background(), &kmspb.MacVerifyRequest{}) })
}

func mustGCPRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return privateKey
}

func mustGCPRSAPrivateBase64(t *testing.T, privateKey *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func mustGCPRSAPublicBase64(t *testing.T, publicKey *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func mustGCPECCPrivateBase64(t *testing.T, curve ecdh.Curve) string {
	t.Helper()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh.GenerateKey() error = %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func mustGCPECCPublicBase64(t *testing.T, privateKeyBase64 string) string {
	t.Helper()
	privateKey, err := utilities.ParseECDHPrivateKeyFromBase64(privateKeyBase64)
	if err != nil {
		t.Fatalf("ParseECDHPrivateKeyFromBase64() error = %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func assertGCPPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	fn()
}
