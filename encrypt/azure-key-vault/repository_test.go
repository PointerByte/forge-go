// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package azurekeyvault

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/local"
	"github.com/PointerByte/forge-go/encrypt/models"
	"github.com/PointerByte/forge-go/encrypt/utilities"
	"github.com/spf13/viper"
)

type fakeTokenCredential struct{}

func (fakeTokenCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

type failingTokenCredential struct{}

func (failingTokenCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, errors.New("token boom")
}

type fakeAzureKeysClient struct {
	createKeyFn func(context.Context, string, azkeys.CreateKeyParameters, *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error)
	encryptFn   func(context.Context, string, string, azkeys.KeyOperationParameters, *azkeys.EncryptOptions) (azkeys.EncryptResponse, error)
	decryptFn   func(context.Context, string, string, azkeys.KeyOperationParameters, *azkeys.DecryptOptions) (azkeys.DecryptResponse, error)
	getKeyFn    func(context.Context, string, string, *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
	rotateKeyFn func(context.Context, string, *azkeys.RotateKeyOptions) (azkeys.RotateKeyResponse, error)
	updateKeyFn func(context.Context, string, string, azkeys.UpdateKeyParameters, *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error)
	signFn      func(context.Context, string, string, azkeys.SignParameters, *azkeys.SignOptions) (azkeys.SignResponse, error)
	verifyFn    func(context.Context, string, string, azkeys.VerifyParameters, *azkeys.VerifyOptions) (azkeys.VerifyResponse, error)
}

func (fake fakeAzureKeysClient) CreateKey(ctx context.Context, name string, parameters azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
	return fake.createKeyFn(ctx, name, parameters, options)
}
func (fake fakeAzureKeysClient) Encrypt(ctx context.Context, name, version string, parameters azkeys.KeyOperationParameters, options *azkeys.EncryptOptions) (azkeys.EncryptResponse, error) {
	return fake.encryptFn(ctx, name, version, parameters, options)
}
func (fake fakeAzureKeysClient) Decrypt(ctx context.Context, name, version string, parameters azkeys.KeyOperationParameters, options *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
	return fake.decryptFn(ctx, name, version, parameters, options)
}
func (fake fakeAzureKeysClient) GetKey(ctx context.Context, name, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	if fake.getKeyFn == nil {
		return azkeys.GetKeyResponse{}, errors.New("get key not configured")
	}
	return fake.getKeyFn(ctx, name, version, options)
}
func (fake fakeAzureKeysClient) RotateKey(ctx context.Context, name string, options *azkeys.RotateKeyOptions) (azkeys.RotateKeyResponse, error) {
	if fake.rotateKeyFn == nil {
		return azkeys.RotateKeyResponse{}, errors.New("rotate key not configured")
	}
	return fake.rotateKeyFn(ctx, name, options)
}
func (fake fakeAzureKeysClient) UpdateKey(ctx context.Context, name, version string, parameters azkeys.UpdateKeyParameters, options *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error) {
	if fake.updateKeyFn == nil {
		return azkeys.UpdateKeyResponse{}, errors.New("update key not configured")
	}
	return fake.updateKeyFn(ctx, name, version, parameters, options)
}
func (fake fakeAzureKeysClient) Sign(ctx context.Context, name, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error) {
	return fake.signFn(ctx, name, version, parameters, options)
}
func (fake fakeAzureKeysClient) Verify(ctx context.Context, name, version string, parameters azkeys.VerifyParameters, options *azkeys.VerifyOptions) (azkeys.VerifyResponse, error) {
	return fake.verifyFn(ctx, name, version, parameters, options)
}

type fakeAzureECDHDeriver struct {
	privateKey *ecdh.PrivateKey
}

func (fake fakeAzureECDHDeriver) DeriveSharedSecret(_ context.Context, _ azureKeyReference, publicKeyDER []byte) ([]byte, error) {
	publicKey, err := utilities.ParseECDHPublicKeyFromBase64(base64.StdEncoding.EncodeToString(publicKeyDER))
	if err != nil {
		return nil, err
	}
	return fake.privateKey.ECDH(publicKey)
}

func TestUIDMetadataHelpers(t *testing.T) {
	if tags := azureUIDTags(""); tags != nil {
		t.Fatalf("azureUIDTags() = %#v, want nil", tags)
	}
	tags := azureUIDTags("user-123")
	if tags["uid"] == nil || *tags["uid"] != "user-123" {
		t.Fatalf("azureUIDTags() = %#v, want uid tag", tags)
	}

	additional := "aad"
	if got := string(azureAuthenticatedData("", &additional)); got != "aad" {
		t.Fatalf("azureAuthenticatedData() = %q, want aad", got)
	}
	if got := string(azureAuthenticatedData("user-123", &additional)); got != "user-123\x00aad" {
		t.Fatalf("azureAuthenticatedData() = %q, want uid and aad", got)
	}
}

func TestAzureKeyRepositoryRotateAndGetKey(t *testing.T) {
	t.Cleanup(viper.Reset)
	previousCredential := newAzureCredentialFn
	previousClient := newAzureClientFn
	t.Cleanup(func() {
		newAzureCredentialFn = previousCredential
		newAzureClientFn = previousClient
	})

	privateKey := mustAzureRSAKey(t)
	rotatedKID := azkeys.ID("https://vault.test/keys/sym-key/v2")
	rsaKID := azkeys.ID("https://vault.test/keys/rsa-key/v1")

	newAzureCredentialFn = func(*azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) {
		return fakeTokenCredential{}, nil
	}
	newAzureClientFn = func(vaultURL string, _ azcore.TokenCredential) (azureKeysClient, error) {
		if vaultURL != "https://vault.test" {
			t.Fatalf("vaultURL = %q, want https://vault.test", vaultURL)
		}
		return fakeAzureKeysClient{
			getKeyFn: func(_ context.Context, name, version string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
				switch name {
				case "sym-key":
					if version != "" && version != "v2" {
						t.Fatalf("GetKey() sym-key version = %q, want latest or v2", version)
					}
					return azkeys.GetKeyResponse{KeyBundle: azkeys.KeyBundle{Key: &azkeys.JSONWebKey{
						KID: &rotatedKID,
						Kty: ptr(azkeys.KeyTypeOctHSM),
					}}}, nil
				case "rsa-key":
					return azkeys.GetKeyResponse{KeyBundle: azkeys.KeyBundle{Key: &azkeys.JSONWebKey{
						KID: &rsaKID,
						Kty: ptr(azkeys.KeyTypeRSA),
						N:   privateKey.PublicKey.N.Bytes(),
						E:   []byte{0x01, 0x00, 0x01},
					}}}, nil
				default:
					return azkeys.GetKeyResponse{}, errors.New("unexpected key name")
				}
			},
			rotateKeyFn: func(_ context.Context, name string, _ *azkeys.RotateKeyOptions) (azkeys.RotateKeyResponse, error) {
				if name != "sym-key" {
					t.Fatalf("RotateKey() name = %q, want sym-key", name)
				}
				return azkeys.RotateKeyResponse{KeyBundle: azkeys.KeyBundle{Key: &azkeys.JSONWebKey{
					KID: &rotatedKID,
					Kty: ptr(azkeys.KeyTypeOctHSM),
				}}}, nil
			},
			updateKeyFn: func(_ context.Context, name, version string, parameters azkeys.UpdateKeyParameters, _ *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error) {
				if name != "sym-key" || version != "v2" {
					t.Fatalf("UpdateKey() = %q %q, want sym-key v2", name, version)
				}
				if parameters.KeyAttributes == nil || parameters.KeyAttributes.Enabled == nil || *parameters.KeyAttributes.Enabled {
					t.Fatalf("UpdateKey() parameters = %#v, want Enabled=false", parameters)
				}
				return azkeys.UpdateKeyResponse{KeyBundle: azkeys.KeyBundle{Key: &azkeys.JSONWebKey{
					KID: &rotatedKID,
					Kty: ptr(azkeys.KeyTypeOctHSM),
				}}}, nil
			},
		}, nil
	}

	viper.Set(defaultAzureVaultURLKey, "https://vault.test")
	repository := NewKeyRepository()

	rotatedKey, err := repository.RotateKey(context.Background(), models.RotateKeyRequest{KeyID: "sym-key"})
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	if rotatedKey.KeyID != "sym-key" || rotatedKey.KeyRef != string(rotatedKID) || rotatedKey.Provider != azureProviderName || rotatedKey.PublicKey != "" {
		t.Fatalf("RotateKey() = %#v, want rotated symmetric metadata", rotatedKey)
	}

	rsaKey, err := repository.GetKey(context.Background(), models.GetKeyRequest{KeyID: "rsa-key"})
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}
	if rsaKey.KeyID != "rsa-key" || rsaKey.KeyRef != string(rsaKID) || rsaKey.PublicKey == "" {
		t.Fatalf("GetKey() = %#v, want RSA public metadata", rsaKey)
	}

	if err := repository.DeactivateKey(context.Background(), models.DeactivateKeyRequest{KeyID: "sym-key"}); err != nil {
		t.Fatalf("DeactivateKey() error = %v", err)
	}
}

func TestAzureRepositoryProviderFlowsAndHelpers(t *testing.T) {
	t.Cleanup(viper.Reset)
	previousCredential := newAzureCredentialFn
	previousClient := newAzureClientFn
	previousDeriver := newAzureECDHDeriverFn
	t.Cleanup(func() {
		newAzureCredentialFn = previousCredential
		newAzureClientFn = previousClient
		newAzureECDHDeriverFn = previousDeriver
	})

	privateKey := mustAzureRSAKey(t)
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
	ecdhPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh.GenerateKey() error = %v", err)
	}
	ecdhPublicBytes := ecdhPrivate.PublicKey().Bytes()

	newAzureCredentialFn = func(*azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) {
		return fakeTokenCredential{}, nil
	}
	newAzureClientFn = func(string, azcore.TokenCredential) (azureKeysClient, error) {
		return fakeAzureKeysClient{
			createKeyFn: func(_ context.Context, name string, parameters azkeys.CreateKeyParameters, _ *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
				kid := azkeys.ID("https://vault.test/keys/" + name + "/v1")
				key := &azkeys.JSONWebKey{KID: &kid}
				if parameters.Kty != nil && *parameters.Kty == azkeys.KeyTypeRSA {
					key.N = privateKey.PublicKey.N.Bytes()
					key.E = []byte{0x01, 0x00, 0x01}
				}
				if parameters.Kty != nil && *parameters.Kty == azkeys.KeyTypeEC {
					if parameters.Curve == nil || *parameters.Curve != azkeys.CurveNameP256 {
						t.Fatalf("expected P-256 EC key creation, got %#v", parameters.Curve)
					}
					key.Crv = parameters.Curve
					key.X = ecdhPublicBytes[1:33]
					key.Y = ecdhPublicBytes[33:]
				}
				return azkeys.CreateKeyResponse{KeyBundle: azkeys.KeyBundle{Key: key}}, nil
			},
			encryptFn: func(_ context.Context, _, _ string, parameters azkeys.KeyOperationParameters, _ *azkeys.EncryptOptions) (azkeys.EncryptResponse, error) {
				if parameters.Algorithm != nil && *parameters.Algorithm == azkeys.EncryptionAlgorithmA256GCM {
					return azkeys.EncryptResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: []byte("cipher"), IV: []byte("iv"), AuthenticationTag: []byte("tag")}}, nil
				}
				return azkeys.EncryptResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: []byte("rsa-cipher")}}, nil
			},
			decryptFn: func(_ context.Context, _, _ string, parameters azkeys.KeyOperationParameters, _ *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
				if parameters.Algorithm != nil && *parameters.Algorithm == azkeys.EncryptionAlgorithmA256GCM {
					return azkeys.DecryptResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: []byte("hello")}}, nil
				}
				return azkeys.DecryptResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: []byte("plain")}}, nil
			},
			getKeyFn: func(_ context.Context, name, version string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
				if name == "" || version == "" {
					t.Fatalf("expected key name and version, got %q %q", name, version)
				}
				kid := azkeys.ID("https://vault.test/keys/" + name + "/" + version)
				return azkeys.GetKeyResponse{KeyBundle: azkeys.KeyBundle{Key: &azkeys.JSONWebKey{
					KID: &kid,
					Kty: ptr(azkeys.KeyTypeEC),
					Crv: ptr(azkeys.CurveNameP256),
					X:   ecdhPublicBytes[1:33],
					Y:   ecdhPublicBytes[33:],
				}}}, nil
			},
			signFn: func(_ context.Context, _, _ string, parameters azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
				return azkeys.SignResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: append([]byte("sig-"), parameters.Value...)}}, nil
			},
			verifyFn: func(_ context.Context, _, _ string, _ azkeys.VerifyParameters, _ *azkeys.VerifyOptions) (azkeys.VerifyResponse, error) {
				valid := true
				return azkeys.VerifyResponse{KeyVerifyResult: azkeys.KeyVerifyResult{Value: &valid}}, nil
			},
		}, nil
	}
	newAzureECDHDeriverFn = func(context.Context, string) (azureECDHDeriver, error) {
		return fakeAzureECDHDeriver{privateKey: ecdhPrivate}, nil
	}

	viper.Set(defaultAzureVaultURLKey, "https://vault.test")
	viper.Set(defaultAzureKeyIDKey, "https://vault.test/keys/default-key/v1")
	repository := NewRepository()

	symmetricKey, err := repository.GenerateSymetrycKeys(context.Background(), models.GenerateSymmetricKeyRequest{Size: common.Key256Bits})
	if err != nil || symmetricKey == nil || symmetricKey.Provider != azureProviderName {
		t.Fatalf("GenerateSymetrycKeys() = %#v, %v", symmetricKey, err)
	}
	additional := "aad"
	ciphertext, err := repository.EncryptAES(context.Background(), models.EncryptAESRequest{SecretKey: symmetricKey.KeyRef, Value: "hello", Additional: &additional})
	if err != nil {
		t.Fatalf("EncryptAES() error = %v", err)
	}
	plaintext, err := repository.DecryptAES(context.Background(), models.DecryptAESRequest{SecretKey: symmetricKey.KeyRef, CipherValue: ciphertext, Additional: &additional})
	if err != nil || plaintext != "hello" {
		t.Fatalf("DecryptAES() = %q, %v", plaintext, err)
	}
	if got := repository.HMAC(context.Background(), symmetricKey.KeyRef, "message"); got == "" {
		t.Fatal("expected HMAC() to return a value")
	}
	if repository.Sha256Hex(context.Background(), "message") == "" || repository.Blake3(context.Background(), "message") == "" {
		t.Fatal("expected hash helpers to return values")
	}

	rsaKey, err := repository.GenerateRSAKeys(context.Background(), models.GenerateRSAKeyRequest{Size: common.Key2048Bits})
	if err != nil || rsaKey == nil || rsaKey.PublicKey == "" {
		t.Fatalf("GenerateRSAKeys() = %#v, %v", rsaKey, err)
	}
	if _, err := repository.RSA_OAEP_Encode(context.Background(), models.RSAOAEPEncodeRequest{PublicKey: rsaKey.KeyRef, Text: "payload"}); err != nil {
		t.Fatalf("RSA_OAEP_Encode() error = %v", err)
	}
	if plaintext, err := repository.RSA_OAEP_Decode(context.Background(), models.RSAOAEPDecodeRequest{PrivateKey: rsaKey.KeyRef, CipherText: base64.StdEncoding.EncodeToString([]byte("cipher"))}); err != nil || plaintext != "plain" {
		t.Fatalf("RSA_OAEP_Decode() = %q, %v", plaintext, err)
	}
	if _, err := repository.SignRSAPSS(context.Background(), rsaKey.KeyRef, "payload"); err != nil {
		t.Fatalf("SignRSAPSS() error = %v", err)
	}
	if err := repository.VerifyRSAPSS(context.Background(), rsaKey.KeyRef, "payload", base64.StdEncoding.EncodeToString([]byte("sig"))); err != nil {
		t.Fatalf("VerifyRSAPSS() error = %v", err)
	}
	if _, err := repository.Sign_RSA_PKCS1v15_SHA256(context.Background(), "", "payload"); err != nil {
		t.Fatalf("Sign_RSA_PKCS1v15_SHA256() error = %v", err)
	}
	if err := repository.Verify_RSA_PKCS1v15_SHA256(context.Background(), "payload", "", base64.StdEncoding.EncodeToString([]byte("sig"))); err != nil {
		t.Fatalf("Verify_RSA_PKCS1v15_SHA256() error = %v", err)
	}
	if _, err := repository.GenerateEd255Keys(context.Background()); !errors.Is(err, errAzureEd25519Unsupported) {
		t.Fatalf("GenerateEd255Keys() error = %v", err)
	}
	ecdhKey, err := repository.GenerateECDHCurveKeys(context.Background(), models.GenerateECDHCurveKeyRequest{Curve: common.CurveP256})
	if err != nil || ecdhKey == nil || ecdhKey.PublicKey == "" || ecdhKey.Provider != azureProviderName {
		t.Fatalf("GenerateECDHCurveKeys() = %#v, %v", ecdhKey, err)
	}
	if _, err := utilities.ParseECDHPublicKeyFromBase64(ecdhKey.PublicKey); err != nil {
		t.Fatalf("GenerateECDHCurveKeys() public key parse error = %v", err)
	}
	azureEccCiphertext, err := repository.ECDH_Encode(context.Background(), models.ECDHEncodeRequest{PublicKey: ecdhKey.KeyRef, Text: "payload"})
	if err != nil {
		t.Fatalf("ECDH_Encode() azure error = %v", err)
	}
	if plaintext, err := repository.ECDH_Decode(context.Background(), models.ECDHDecodeRequest{PrivateKey: ecdhKey.KeyRef, CipherText: azureEccCiphertext}); err != nil || plaintext != "payload" {
		t.Fatalf("ECDH_Decode() azure = %q, %v", plaintext, err)
	}

	localRepository := local.NewRepository()
	localSymmetricKey, err := localRepository.GenerateSymetrycKeys(context.Background(), models.GenerateSymmetricKeyRequest{Size: common.Key256Bits})
	if err != nil {
		t.Fatalf("local GenerateSymetrycKeys() error = %v", err)
	}
	if _, err := repository.EncryptAES(context.Background(), models.EncryptAESRequest{SecretKey: localSymmetricKey.KeyID, Value: "hello", Additional: &additional}); err != nil {
		t.Fatalf("EncryptAES() local fallback error = %v", err)
	}
	localCiphertext, err := localRepository.EncryptAES(context.Background(), models.EncryptAESRequest{SecretKey: localSymmetricKey.KeyID, Value: "hello", Additional: &additional})
	if err != nil {
		t.Fatalf("local EncryptAES() error = %v", err)
	}
	if _, err := repository.DecryptAES(context.Background(), models.DecryptAESRequest{SecretKey: localSymmetricKey.KeyID, CipherValue: localCiphertext, Additional: &additional}); err != nil {
		t.Fatalf("DecryptAES() local fallback error = %v", err)
	}
	localMac := repository.HMAC(context.Background(), "secret", "message")
	if localMac == "" {
		t.Fatal("expected local HMAC fallback to succeed")
	}
	localRSAPrivate := mustAzureRSAPrivateBase64(t, privateKey)
	localRSAPublic := mustAzureRSAPublicBase64(t, &privateKey.PublicKey)
	localRSACiphertext, err := repository.RSA_OAEP_Encode(context.Background(), models.RSAOAEPEncodeRequest{PublicKey: localRSAPublic, Text: "payload"})
	if err != nil {
		t.Fatalf("RSA_OAEP_Encode() local fallback error = %v", err)
	}
	if _, err := repository.RSA_OAEP_Decode(context.Background(), models.RSAOAEPDecodeRequest{PrivateKey: localRSAPrivate, CipherText: localRSACiphertext}); err != nil {
		t.Fatalf("RSA_OAEP_Decode() local fallback error = %v", err)
	}
	localECCPrivate := mustAzureECCPrivateBase64(t, ecdh.P256())
	localECCPublic := mustAzureECCPublicBase64(t, localECCPrivate)
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

	if got, err := resolveAzureVaultURL(); err != nil || got != "https://vault.test" {
		t.Fatalf("resolveAzureVaultURL() = %q, %v", got, err)
	}
	if got := configuredAzureKeyID(); got == "" {
		t.Fatal("expected configuredAzureKeyID() value")
	}
	if !looksLikeAzureKeyReference(symmetricKey.KeyRef) || looksLikeAzureKeyReference("local") {
		t.Fatal("unexpected looksLikeAzureKeyReference() result")
	}
	if got := utilities.BytesFromOptionalString(nil); got != nil {
		t.Fatal("expected utilities.BytesFromOptionalString(nil) to return nil")
	}
	if boolValue(nil) || !boolValue(ptr(true)) {
		t.Fatal("unexpected boolValue() result")
	}
	if _, _, err := azureMetadataFromBundle(azkeys.KeyBundle{}, "", "name"); err == nil {
		t.Fatal("expected azureMetadataFromBundle() error")
	}
	if _, err := rsaPublicKeyFromAzureBundle(azkeys.KeyBundle{}); err == nil {
		t.Fatal("expected rsaPublicKeyFromAzureBundle() error")
	}
	if utilities.IsLocalAESKey("%%%") {
		t.Fatal("expected utilities.IsLocalAESKey() false for invalid base64")
	}

	_ = publicDER
}

func TestAzureRepositoryErrorBranches(t *testing.T) {
	t.Cleanup(viper.Reset)
	previousCredential := newAzureCredentialFn
	previousClient := newAzureClientFn
	t.Cleanup(func() {
		newAzureCredentialFn = previousCredential
		newAzureClientFn = previousClient
	})

	if _, err := NewSymmetricRepository().GenerateSymetrycKeys(context.Background(), models.GenerateSymmetricKeyRequest{Size: common.Key128Bits}); err == nil {
		t.Fatal("expected unsupported symmetric size error")
	}
	if _, err := NewAsymmetricRepository().GenerateRSAKeys(context.Background(), models.GenerateRSAKeyRequest{Size: 0}); err == nil {
		t.Fatal("expected unsupported rsa size error")
	}
	if _, err := resolveAzureKeyReference(""); err == nil {
		t.Fatal("expected resolveAzureKeyReference() error")
	}
	if _, err := resolveAzureKeyReference("not-a-url"); err == nil {
		t.Fatal("expected resolveAzureKeyReference() invalid URL error")
	}

	newAzureCredentialFn = func(*azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) {
		return nil, errors.New("credential boom")
	}
	if _, _, err := newAzureKeysClient(context.Background(), "https://vault.test"); err == nil {
		t.Fatal("expected newAzureKeysClient() credential error")
	}

	newAzureCredentialFn = func(*azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) {
		return fakeTokenCredential{}, nil
	}
	newAzureClientFn = func(string, azcore.TokenCredential) (azureKeysClient, error) {
		return fakeAzureKeysClient{
			createKeyFn: func(context.Context, string, azkeys.CreateKeyParameters, *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
				return azkeys.CreateKeyResponse{}, errors.New("create boom")
			},
			encryptFn: func(context.Context, string, string, azkeys.KeyOperationParameters, *azkeys.EncryptOptions) (azkeys.EncryptResponse, error) {
				return azkeys.EncryptResponse{}, errors.New("encrypt boom")
			},
			decryptFn: func(context.Context, string, string, azkeys.KeyOperationParameters, *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
				return azkeys.DecryptResponse{}, errors.New("decrypt boom")
			},
			signFn: func(context.Context, string, string, azkeys.SignParameters, *azkeys.SignOptions) (azkeys.SignResponse, error) {
				return azkeys.SignResponse{}, errors.New("sign boom")
			},
			verifyFn: func(context.Context, string, string, azkeys.VerifyParameters, *azkeys.VerifyOptions) (azkeys.VerifyResponse, error) {
				return azkeys.VerifyResponse{}, errors.New("verify boom")
			},
		}, nil
	}

	viper.Set(defaultAzureVaultURLKey, "https://vault.test")
	viper.Set(defaultAzureKeyIDKey, "https://vault.test/keys/default-key/v1")
	symmetricRepository := NewSymmetricRepository()
	hashRepository := NewHashRepository()
	keyRepository := NewKeyRepository()
	asymmetricRepository := NewAsymmetricRepository()
	signatureRepository := NewSignatureRepository()

	if _, err := symmetricRepository.GenerateSymetrycKeys(context.Background(), models.GenerateSymmetricKeyRequest{Size: common.Key256Bits}); err == nil {
		t.Fatal("expected GenerateSymetrycKeys() provider error")
	}
	if _, err := symmetricRepository.EncryptAES(context.Background(), models.EncryptAESRequest{SecretKey: "", Value: "payload", Additional: nil}); err == nil {
		t.Fatal("expected EncryptAES() key reference error")
	}
	if _, err := symmetricRepository.EncryptAES(context.Background(), models.EncryptAESRequest{SecretKey: "https://vault.test/keys/default-key/v1", Value: "payload", Additional: nil}); err == nil {
		t.Fatal("expected EncryptAES() provider error")
	}
	if _, err := symmetricRepository.DecryptAES(context.Background(), models.DecryptAESRequest{SecretKey: "https://vault.test/keys/default-key/v1", CipherValue: "%%%", Additional: nil}); err == nil {
		t.Fatal("expected DecryptAES() payload decode error")
	}
	invalidJSON := base64.StdEncoding.EncodeToString([]byte("{"))
	if _, err := symmetricRepository.DecryptAES(context.Background(), models.DecryptAESRequest{SecretKey: "https://vault.test/keys/default-key/v1", CipherValue: invalidJSON, Additional: nil}); err == nil {
		t.Fatal("expected DecryptAES() json decode error")
	}
	payloadBytes, err := json.Marshal(azureAEADPayload{Result: "%%%", IV: base64.StdEncoding.EncodeToString([]byte("iv")), Tag: base64.StdEncoding.EncodeToString([]byte("tag"))})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if _, err := symmetricRepository.DecryptAES(context.Background(), models.DecryptAESRequest{SecretKey: "https://vault.test/keys/default-key/v1", CipherValue: base64.StdEncoding.EncodeToString(payloadBytes), Additional: nil}); err == nil {
		t.Fatal("expected DecryptAES() ciphertext decode error")
	}
	if got := hashRepository.HMAC(context.Background(), "https://vault.test/keys/default-key/v1", "message"); got != "" {
		t.Fatalf("HMAC() = %q, want empty string on provider error", got)
	}
	if _, err := keyRepository.RotateKey(context.Background(), models.RotateKeyRequest{KeyID: "https://vault.test/keys/default-key/v1"}); err == nil {
		t.Fatal("expected RotateKey() provider error")
	}
	if _, err := keyRepository.GetKey(context.Background(), models.GetKeyRequest{KeyID: "https://vault.test/keys/default-key/v1"}); err == nil {
		t.Fatal("expected GetKey() provider error")
	}
	if err := keyRepository.DeactivateKey(context.Background(), models.DeactivateKeyRequest{KeyID: "https://vault.test/keys/default-key/v1"}); err == nil {
		t.Fatal("expected DeactivateKey() provider error")
	}
	if _, err := asymmetricRepository.RSA_OAEP_Encode(context.Background(), models.RSAOAEPEncodeRequest{PublicKey: "", Text: "payload"}); err == nil {
		t.Fatal("expected RSA_OAEP_Encode() key reference error")
	}
	if _, err := asymmetricRepository.RSA_OAEP_Encode(context.Background(), models.RSAOAEPEncodeRequest{PublicKey: "https://vault.test/keys/default-key/v1", Text: "payload"}); err == nil {
		t.Fatal("expected RSA_OAEP_Encode() provider error")
	}
	if _, err := asymmetricRepository.RSA_OAEP_Decode(context.Background(), models.RSAOAEPDecodeRequest{PrivateKey: "https://vault.test/keys/default-key/v1", CipherText: "%%%"}); err == nil {
		t.Fatal("expected RSA_OAEP_Decode() decode error")
	}
	if _, err := asymmetricRepository.RSA_OAEP_Decode(context.Background(), models.RSAOAEPDecodeRequest{PrivateKey: "https://vault.test/keys/default-key/v1", CipherText: base64.StdEncoding.EncodeToString([]byte("cipher"))}); err == nil {
		t.Fatal("expected RSA_OAEP_Decode() provider error")
	}
	if _, err := asymmetricRepository.GenerateECDHCurveKeys(context.Background(), models.GenerateECDHCurveKeyRequest{Curve: common.CurveAsymmetricKey(99)}); err == nil {
		t.Fatal("expected GenerateECDHCurveKeys() curve error")
	}
	if _, err := asymmetricRepository.GenerateECDHCurveKeys(context.Background(), models.GenerateECDHCurveKeyRequest{Curve: common.CurveP256}); err == nil {
		t.Fatal("expected GenerateECDHCurveKeys() provider error")
	}
	if _, err := asymmetricRepository.ECDH_Encode(context.Background(), models.ECDHEncodeRequest{PublicKey: "https://vault.test/keys/default-key/v1", Text: "payload"}); err == nil {
		t.Fatal("expected ECDH_Encode() provider error")
	}
	if _, err := asymmetricRepository.ECDH_Decode(context.Background(), models.ECDHDecodeRequest{PrivateKey: "https://vault.test/keys/default-key/v1", CipherText: "payload"}); err == nil {
		t.Fatal("expected ECDH_Decode() payload error")
	}
	if _, err := signatureRepository.SignEd25519(context.Background(), "https://vault.test/keys/default-key/v1", "payload"); !errors.Is(err, errAzureEd25519Unsupported) {
		t.Fatalf("SignEd25519() error = %v", err)
	}
	if err := signatureRepository.VerifyEd25519(context.Background(), "https://vault.test/keys/default-key/v1", "payload", "sig"); !errors.Is(err, errAzureEd25519Unsupported) {
		t.Fatalf("VerifyEd25519() error = %v", err)
	}
	if _, err := signatureRepository.SignRSAPSS(context.Background(), "", "payload"); err == nil {
		t.Fatal("expected SignRSAPSS() key reference error")
	}
	if _, err := signatureRepository.SignRSAPSS(context.Background(), "https://vault.test/keys/default-key/v1", "payload"); err == nil {
		t.Fatal("expected SignRSAPSS() provider error")
	}
	if err := signatureRepository.VerifyRSAPSS(context.Background(), "https://vault.test/keys/default-key/v1", "payload", "%%%"); err == nil {
		t.Fatal("expected VerifyRSAPSS() decode error")
	}
	if err := signatureRepository.VerifyRSAPSS(context.Background(), "https://vault.test/keys/default-key/v1", "payload", base64.StdEncoding.EncodeToString([]byte("sig"))); err == nil {
		t.Fatal("expected VerifyRSAPSS() provider error")
	}
	if _, err := signatureRepository.Sign_RSA_PKCS1v15_SHA256(context.Background(), "", "payload"); err == nil {
		t.Fatal("expected Sign_RSA_PKCS1v15_SHA256() provider error")
	}
	if err := signatureRepository.Verify_RSA_PKCS1v15_SHA256(context.Background(), "payload", "", "%%%"); err == nil {
		t.Fatal("expected Verify_RSA_PKCS1v15_SHA256() decode error")
	}
	if got, err := resolveAzureKeyReference("https://vault.test/keys/name/version"); err != nil || got.Name != "name" || got.Version != "version" {
		t.Fatalf("resolveAzureKeyReference() = %#v, %v", got, err)
	}
	viper.Reset()
	viper.Set(defaultAzureKeyIDKey, "https://vault.test/keys/from-config/v2")
	if got, err := resolveAzureVaultURL(); err != nil || got != "https://vault.test" {
		t.Fatalf("resolveAzureVaultURL() from key id = %q, %v", got, err)
	}
	viper.Reset()
	viper.Set(legacyAzureVaultURLKey, "https://legacy.vault")
	if got, err := resolveAzureVaultURL(); err != nil || got != "https://legacy.vault" {
		t.Fatalf("resolveAzureVaultURL() legacy = %q, %v", got, err)
	}
	viper.Reset()
	viper.Set(legacyAzureKeyIDKey, "https://vault.test/keys/legacy/v1")
	if got := configuredAzureKeyID(); got != "https://vault.test/keys/legacy/v1" {
		t.Fatalf("configuredAzureKeyID() = %q", got)
	}
	viper.Reset()
	if looksLikeAzureKeyReference("") {
		t.Fatal("expected looksLikeAzureKeyReference(\"\") to be false without config")
	}
	if _, err := azureRSAKeySize(common.Key3072Bits); err != nil {
		t.Fatalf("azureRSAKeySize(3072) error = %v", err)
	}
	if _, err := azureRSAKeySize(common.Key4096Bits); err != nil {
		t.Fatalf("azureRSAKeySize(4096) error = %v", err)
	}
	kid := azkeys.ID("https://vault.test/keys/name/version")
	if gotID, gotRef, err := azureMetadataFromBundle(azkeys.KeyBundle{Key: &azkeys.JSONWebKey{KID: &kid}}, "", "ignored"); err != nil || gotID != "name" || gotRef == "" {
		t.Fatalf("azureMetadataFromBundle() = %q, %q, %v", gotID, gotRef, err)
	}
	if gotID, gotRef, err := azureMetadataFromBundle(azkeys.KeyBundle{}, "https://vault.test", "name"); err != nil || gotID != "name" || gotRef != "https://vault.test/keys/name" {
		t.Fatalf("azureMetadataFromBundle() fallback = %q, %q, %v", gotID, gotRef, err)
	}
}

func TestAzureRepositoryAdditionalErrorBranches(t *testing.T) {
	t.Cleanup(viper.Reset)
	previousCredential := newAzureCredentialFn
	previousClient := newAzureClientFn
	t.Cleanup(func() {
		newAzureCredentialFn = previousCredential
		newAzureClientFn = previousClient
	})

	newAzureCredentialFn = func(*azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) {
		return fakeTokenCredential{}, nil
	}
	newAzureClientFn = func(string, azcore.TokenCredential) (azureKeysClient, error) {
		return nil, errors.New("client boom")
	}
	if _, _, err := newAzureKeysClient(context.Background(), "https://vault.test"); err == nil {
		t.Fatal("expected newAzureKeysClient() client error")
	}

	newAzureClientFn = func(string, azcore.TokenCredential) (azureKeysClient, error) {
		return fakeAzureKeysClient{
			createKeyFn: func(context.Context, string, azkeys.CreateKeyParameters, *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
				return azkeys.CreateKeyResponse{}, nil
			},
			encryptFn: func(context.Context, string, string, azkeys.KeyOperationParameters, *azkeys.EncryptOptions) (azkeys.EncryptResponse, error) {
				return azkeys.EncryptResponse{}, nil
			},
			decryptFn: func(context.Context, string, string, azkeys.KeyOperationParameters, *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
				return azkeys.DecryptResponse{}, errors.New("decrypt boom")
			},
			signFn: func(context.Context, string, string, azkeys.SignParameters, *azkeys.SignOptions) (azkeys.SignResponse, error) {
				return azkeys.SignResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: []byte("sig")}}, nil
			},
			verifyFn: func(context.Context, string, string, azkeys.VerifyParameters, *azkeys.VerifyOptions) (azkeys.VerifyResponse, error) {
				valid := false
				return azkeys.VerifyResponse{KeyVerifyResult: azkeys.KeyVerifyResult{Value: &valid}}, nil
			},
		}, nil
	}

	viper.Set(defaultAzureVaultURLKey, "https://vault.test")
	viper.Set(defaultAzureKeyIDKey, "https://vault.test/keys/default-key/v1")
	symmetricRepository := NewSymmetricRepository()
	signatureRepository := NewSignatureRepository()

	payload, err := json.Marshal(azureAEADPayload{
		Result: base64.StdEncoding.EncodeToString([]byte("cipher")),
		IV:     "%%%",
		Tag:    base64.StdEncoding.EncodeToString([]byte("tag")),
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if _, err := symmetricRepository.DecryptAES(context.Background(), models.DecryptAESRequest{SecretKey: "https://vault.test/keys/default-key/v1", CipherValue: base64.StdEncoding.EncodeToString(payload), Additional: nil}); err == nil {
		t.Fatal("expected DecryptAES() iv decode error")
	}
	payload, err = json.Marshal(azureAEADPayload{
		Result: base64.StdEncoding.EncodeToString([]byte("cipher")),
		IV:     base64.StdEncoding.EncodeToString([]byte("iv")),
		Tag:    "%%%",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if _, err := symmetricRepository.DecryptAES(context.Background(), models.DecryptAESRequest{SecretKey: "https://vault.test/keys/default-key/v1", CipherValue: base64.StdEncoding.EncodeToString(payload), Additional: nil}); err == nil {
		t.Fatal("expected DecryptAES() tag decode error")
	}
	payload, err = json.Marshal(azureAEADPayload{
		Result: base64.StdEncoding.EncodeToString([]byte("cipher")),
		IV:     base64.StdEncoding.EncodeToString([]byte("iv")),
		Tag:    base64.StdEncoding.EncodeToString([]byte("tag")),
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if _, err := symmetricRepository.DecryptAES(context.Background(), models.DecryptAESRequest{SecretKey: "https://vault.test/keys/default-key/v1", CipherValue: base64.StdEncoding.EncodeToString(payload), Additional: nil}); err == nil {
		t.Fatal("expected DecryptAES() provider error")
	}
	if err := signatureRepository.VerifyRSAPSS(context.Background(), "https://vault.test/keys/default-key/v1", "payload", base64.StdEncoding.EncodeToString([]byte("sig"))); err == nil {
		t.Fatal("expected VerifyRSAPSS() invalid signature error")
	}
	if err := signatureRepository.Verify_RSA_PKCS1v15_SHA256(context.Background(), "payload", "", base64.StdEncoding.EncodeToString([]byte("sig"))); err == nil {
		t.Fatal("expected Verify_RSA_PKCS1v15_SHA256() invalid signature error")
	}
}

func TestAzureRepositoryMetadataFallbackPaths(t *testing.T) {
	t.Cleanup(viper.Reset)
	previousCredential := newAzureCredentialFn
	previousClient := newAzureClientFn
	t.Cleanup(func() {
		newAzureCredentialFn = previousCredential
		newAzureClientFn = previousClient
	})

	privateKey := mustAzureRSAKey(t)
	newAzureCredentialFn = func(*azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) {
		return fakeTokenCredential{}, nil
	}
	newAzureClientFn = func(string, azcore.TokenCredential) (azureKeysClient, error) {
		return fakeAzureKeysClient{
			createKeyFn: func(_ context.Context, _ string, parameters azkeys.CreateKeyParameters, _ *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
				key := &azkeys.JSONWebKey{}
				if parameters.Kty != nil && *parameters.Kty == azkeys.KeyTypeRSA {
					key.N = privateKey.PublicKey.N.Bytes()
					key.E = []byte{0x01, 0x00, 0x01}
				}
				return azkeys.CreateKeyResponse{KeyBundle: azkeys.KeyBundle{Key: key}}, nil
			},
			encryptFn: func(context.Context, string, string, azkeys.KeyOperationParameters, *azkeys.EncryptOptions) (azkeys.EncryptResponse, error) {
				return azkeys.EncryptResponse{}, nil
			},
			decryptFn: func(context.Context, string, string, azkeys.KeyOperationParameters, *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
				return azkeys.DecryptResponse{}, nil
			},
			signFn: func(context.Context, string, string, azkeys.SignParameters, *azkeys.SignOptions) (azkeys.SignResponse, error) {
				return azkeys.SignResponse{}, nil
			},
			verifyFn: func(context.Context, string, string, azkeys.VerifyParameters, *azkeys.VerifyOptions) (azkeys.VerifyResponse, error) {
				return azkeys.VerifyResponse{}, nil
			},
		}, nil
	}

	viper.Set(defaultAzureVaultURLKey, "https://vault.test")
	if key, err := NewSymmetricRepository().GenerateSymetrycKeys(context.Background(), models.GenerateSymmetricKeyRequest{Size: common.Key256Bits}); err != nil || key.KeyRef != "https://vault.test/keys/"+key.KeyID {
		t.Fatalf("GenerateSymetrycKeys() fallback metadata = %#v, %v", key, err)
	}
	if key, err := NewAsymmetricRepository().GenerateRSAKeys(context.Background(), models.GenerateRSAKeyRequest{Size: common.Key2048Bits}); err != nil || key.KeyRef != "https://vault.test/keys/"+key.KeyID {
		t.Fatalf("GenerateRSAKeys() fallback metadata = %#v, %v", key, err)
	}
}

func TestAzureECDHAndBundleHelpers(t *testing.T) {
	if got, err := azureECDHCurveName(common.CurveP384); err != nil || got != azkeys.CurveNameP384 {
		t.Fatalf("azureECDHCurveName(P384) = %q, %v", got, err)
	}
	if got, err := azureECDHCurveName(common.CurveP521); err != nil || got != azkeys.CurveNameP521 {
		t.Fatalf("azureECDHCurveName(P521) = %q, %v", got, err)
	}
	if _, err := azureECDHCurveName(common.CurveAsymmetricKey(99)); err == nil {
		t.Fatal("expected azureECDHCurveName() unsupported curve error")
	}

	if curve, size, err := ecdhCurveFromAzureName(azkeys.CurveNameP384); err != nil || curve != ecdh.P384() || size != 48 {
		t.Fatalf("ecdhCurveFromAzureName(P-384) = %#v, %d, %v", curve, size, err)
	}
	if curve, size, err := ecdhCurveFromAzureName(azkeys.CurveNameP521); err != nil || curve != ecdh.P521() || size != 66 {
		t.Fatalf("ecdhCurveFromAzureName(P-521) = %#v, %d, %v", curve, size, err)
	}
	if _, _, err := ecdhCurveFromAzureName("P-111"); err == nil {
		t.Fatal("expected ecdhCurveFromAzureName() unsupported curve error")
	}

	if name, size, err := azureCurveNameFromECDH(ecdh.P256()); err != nil || name != azkeys.CurveNameP256 || size != 32 {
		t.Fatalf("azureCurveNameFromECDH(P256) = %q, %d, %v", name, size, err)
	}
	if name, size, err := azureCurveNameFromECDH(ecdh.P384()); err != nil || name != azkeys.CurveNameP384 || size != 48 {
		t.Fatalf("azureCurveNameFromECDH(P384) = %q, %d, %v", name, size, err)
	}
	if name, size, err := azureCurveNameFromECDH(ecdh.P521()); err != nil || name != azkeys.CurveNameP521 || size != 66 {
		t.Fatalf("azureCurveNameFromECDH(P521) = %q, %d, %v", name, size, err)
	}
	if _, _, err := azureCurveNameFromECDH(nil); err == nil {
		t.Fatal("expected azureCurveNameFromECDH() unsupported curve error")
	}

	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh.GenerateKey() error = %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	jwk, err := azureECJWKFromPublicKeyDER(publicDER)
	if err != nil {
		t.Fatalf("azureECJWKFromPublicKeyDER() error = %v", err)
	}
	if jwk.KeyType != string(azkeys.KeyTypeEC) || jwk.Curve != string(azkeys.CurveNameP256) || jwk.X == "" || jwk.Y == "" {
		t.Fatalf("azureECJWKFromPublicKeyDER() = %#v", jwk)
	}
	if _, err := azureECJWKFromPublicKeyDER([]byte("bad der")); err == nil {
		t.Fatal("expected azureECJWKFromPublicKeyDER() parse error")
	}
	rsaPublicDER, err := x509.MarshalPKIXPublicKey(&mustAzureRSAKey(t).PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() RSA error = %v", err)
	}
	if _, err := azureECJWKFromPublicKeyDER(rsaPublicDER); err == nil {
		t.Fatal("expected azureECJWKFromPublicKeyDER() non-ECDH error")
	}

	publicBytes := privateKey.PublicKey().Bytes()
	ecBundle := azkeys.KeyBundle{Key: &azkeys.JSONWebKey{
		Kty: ptr(azkeys.KeyTypeECHSM),
		Crv: ptr(azkeys.CurveNameP256),
		X:   publicBytes[1:33],
		Y:   publicBytes[33:],
	}}
	if !azureBundleHasECKey(ecBundle) {
		t.Fatal("expected azureBundleHasECKey() true")
	}
	ecKeyData, err := azureKeyDataFromBundle(ecBundle, "https://vault.test", "ec-key")
	if err != nil || ecKeyData.PublicKey == "" {
		t.Fatalf("azureKeyDataFromBundle() EC = %#v, %v", ecKeyData, err)
	}
	if _, err := ecdhPublicKeyFromAzureBundle(azkeys.KeyBundle{Key: &azkeys.JSONWebKey{Kty: ptr(azkeys.KeyTypeEC)}}); err == nil {
		t.Fatal("expected ecdhPublicKeyFromAzureBundle() missing material error")
	}

	rsaBundle := azkeys.KeyBundle{Key: &azkeys.JSONWebKey{Kty: ptr(azkeys.KeyTypeRSAHSM)}}
	if !azureBundleHasRSAKey(rsaBundle) {
		t.Fatal("expected azureBundleHasRSAKey() true for RSA-HSM")
	}
	if azureBundleHasRSAKey(azkeys.KeyBundle{}) || azureBundleHasECKey(azkeys.KeyBundle{}) {
		t.Fatal("nil key bundles should not report key material")
	}
}

func TestHTTPAzureECDHDeriver(t *testing.T) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh.GenerateKey() error = %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}

	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s, want POST", r.Method)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer" {
				t.Fatalf("Authorization = %q, want empty bearer", got)
			}
			var request azureECDHDeriveRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			if request.Algorithm != "ECDH" || request.Public.X == "" || request.Public.Y == "" {
				t.Fatalf("request body = %#v", request)
			}
			_ = json.NewEncoder(w).Encode(azureECDHDeriveResponse{
				Value: base64.RawURLEncoding.EncodeToString([]byte("shared-secret")),
			})
		}))
		defer server.Close()

		deriver := httpAzureECDHDeriver{credential: fakeTokenCredential{}, httpClient: server.Client()}
		sharedSecret, err := deriver.DeriveSharedSecret(context.Background(), azureKeyReference{
			VaultURL: server.URL,
			Name:     "ec-key",
			Version:  "v1",
		}, publicDER)
		if err != nil {
			t.Fatalf("DeriveSharedSecret() error = %v", err)
		}
		if string(sharedSecret) != "shared-secret" {
			t.Fatalf("DeriveSharedSecret() = %q", sharedSecret)
		}
	})

	t.Run("token error", func(t *testing.T) {
		deriver := httpAzureECDHDeriver{credential: failingTokenCredential{}, httpClient: http.DefaultClient}
		if _, err := deriver.DeriveSharedSecret(context.Background(), azureKeyReference{VaultURL: "https://vault.test", Name: "ec-key", Version: "v1"}, publicDER); err == nil {
			t.Fatal("expected token error")
		}
	})

	for _, tt := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "status error", status: http.StatusInternalServerError, body: "boom"},
		{name: "decode error", status: http.StatusOK, body: "{"},
		{name: "missing value", status: http.StatusOK, body: `{}`},
		{name: "invalid value", status: http.StatusOK, body: `{"value":"%%%"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			deriver := httpAzureECDHDeriver{credential: fakeTokenCredential{}, httpClient: server.Client()}
			if _, err := deriver.DeriveSharedSecret(context.Background(), azureKeyReference{VaultURL: server.URL, Name: "ec-key", Version: "v1"}, publicDER); err == nil {
				t.Fatal("expected DeriveSharedSecret() error")
			}
		})
	}
}

func TestAzureBase64URLDecode(t *testing.T) {
	raw := base64.RawURLEncoding.EncodeToString([]byte("raw"))
	if got, err := decodeAzureBase64URL(raw); err != nil || string(got) != "raw" {
		t.Fatalf("decodeAzureBase64URL(raw) = %q, %v", got, err)
	}
	padded := base64.URLEncoding.EncodeToString([]byte("padded"))
	if got, err := decodeAzureBase64URL(padded); err != nil || string(got) != "padded" {
		t.Fatalf("decodeAzureBase64URL(padded) = %q, %v", got, err)
	}
	if _, err := decodeAzureBase64URL("%%%"); err == nil {
		t.Fatal("expected decodeAzureBase64URL() error")
	}
}

func mustAzureRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return privateKey
}

func mustAzureRSAPrivateBase64(t *testing.T, privateKey *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func mustAzureRSAPublicBase64(t *testing.T, publicKey *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func mustAzureECCPrivateBase64(t *testing.T, curve ecdh.Curve) string {
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

func mustAzureECCPublicBase64(t *testing.T, privateKeyBase64 string) string {
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
