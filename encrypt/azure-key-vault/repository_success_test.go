// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package azurekeyvault

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/models"
	"github.com/spf13/viper"
)

// azureECBundle builds a valid EC key bundle whose KID is a full key URL so
// azureKeyDataFromBundle and resolveAzureKeyReference succeed downstream.
func azureECBundle(t *testing.T) azkeys.KeyBundle {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh.GenerateKey() error = %v", err)
	}
	pub := priv.PublicKey().Bytes()
	kid := azkeys.ID("https://vault.test/keys/name/version")
	return azkeys.KeyBundle{Key: &azkeys.JSONWebKey{
		KID: &kid,
		Kty: ptr(azkeys.KeyTypeEC),
		Crv: ptr(azkeys.CurveNameP256),
		X:   pub[1:33],
		Y:   pub[33:],
	}}
}

// withFakeAzureClient installs a fake credential and client factory and restores
// them on cleanup.
func withFakeAzureClient(t *testing.T, client fakeAzureKeysClient) {
	t.Helper()
	prevCred := newAzureCredentialFn
	prevClient := newAzureClientFn
	t.Cleanup(func() {
		newAzureCredentialFn = prevCred
		newAzureClientFn = prevClient
		viper.Reset()
	})
	newAzureCredentialFn = func(*azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) {
		return fakeTokenCredential{}, nil
	}
	newAzureClientFn = func(string, azcore.TokenCredential) (azureKeysClient, error) {
		return client, nil
	}
	viper.Set(defaultAzureVaultURLKey, "https://vault.test")
}

// azureRSABundle builds a valid RSA key bundle with a full key URL KID.
func azureRSABundle(t *testing.T) azkeys.KeyBundle {
	t.Helper()
	rsaKey := mustAzureRSAKey(t)
	kid := azkeys.ID("https://vault.test/keys/name/version")
	eBytes := []byte{0x01, 0x00, 0x01}
	return azkeys.KeyBundle{Key: &azkeys.JSONWebKey{
		KID: &kid,
		Kty: ptr(azkeys.KeyTypeRSA),
		N:   rsaKey.PublicKey.N.Bytes(),
		E:   eBytes,
	}}
}

// TestAzureRemoteSuccessFlows covers the remote success paths of the symmetric,
// hash and asymmetric repositories using a fully functional fake client.
func TestAzureRemoteSuccessFlows(t *testing.T) {
	rsaBundle := azureRSABundle(t)
	withFakeAzureClient(t, fakeAzureKeysClient{
		createKeyFn: func(context.Context, string, azkeys.CreateKeyParameters, *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
			return azkeys.CreateKeyResponse{KeyBundle: rsaBundle}, nil
		},
		encryptFn: func(context.Context, string, string, azkeys.KeyOperationParameters, *azkeys.EncryptOptions) (azkeys.EncryptResponse, error) {
			return azkeys.EncryptResponse{KeyOperationResult: azkeys.KeyOperationResult{
				Result:            []byte("cipher"),
				IV:                []byte("iv"),
				AuthenticationTag: []byte("tag"),
			}}, nil
		},
		decryptFn: func(context.Context, string, string, azkeys.KeyOperationParameters, *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
			return azkeys.DecryptResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: []byte("plain")}}, nil
		},
		signFn: func(context.Context, string, string, azkeys.SignParameters, *azkeys.SignOptions) (azkeys.SignResponse, error) {
			return azkeys.SignResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: []byte("mac")}}, nil
		},
	})

	repo := NewRepository()
	ctx := context.Background()
	const keyRef = "https://vault.test/keys/name/version"

	cipher, err := repo.EncryptAES(ctx, models.EncryptAESRequest{SecretKey: keyRef, Value: "payload"})
	if err != nil {
		t.Fatalf("EncryptAES() error = %v", err)
	}
	if plain, err := repo.DecryptAES(ctx, models.DecryptAESRequest{SecretKey: keyRef, CipherValue: cipher}); err != nil || plain != "plain" {
		t.Fatalf("DecryptAES() = %q, %v", plain, err)
	}
	if got := repo.HMAC(ctx, keyRef, "message"); got == "" {
		t.Fatal("expected HMAC() to return a value")
	}
	if rsa, err := repo.GenerateRSAKeys(ctx, models.GenerateRSAKeyRequest{Size: common.Key2048Bits}); err != nil || rsa == nil || rsa.PublicKey == "" {
		t.Fatalf("GenerateRSAKeys() = %#v, %v", rsa, err)
	}
	if _, err := repo.RSA_OAEP_Encode(ctx, models.RSAOAEPEncodeRequest{PublicKey: keyRef, Text: "payload"}); err != nil {
		t.Fatalf("RSA_OAEP_Encode() error = %v", err)
	}
	cipherText := base64.StdEncoding.EncodeToString([]byte("cipher"))
	if plain, err := repo.RSA_OAEP_Decode(ctx, models.RSAOAEPDecodeRequest{PrivateKey: keyRef, CipherText: cipherText}); err != nil || plain != "plain" {
		t.Fatalf("RSA_OAEP_Decode() = %q, %v", plain, err)
	}
}

// TestAzureGenerateEd255KeysGuards covers the nil-context and cancelled-context
// guards of GenerateEd255Keys.
func TestAzureGenerateEd255KeysGuards(t *testing.T) {
	repo := NewSignatureRepository()

	var nilCtx context.Context
	if _, err := repo.GenerateEd255Keys(nilCtx); err == nil {
		t.Fatal("expected nil context error")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repo.GenerateEd255Keys(cancelled); err == nil {
		t.Fatal("expected cancelled context error")
	}
}

// TestAzureClientFactoryError covers the newAzureKeysClient error branch shared
// by the remote methods by making credential acquisition fail.
func TestAzureClientFactoryError(t *testing.T) {
	prevCred := newAzureCredentialFn
	prevClient := newAzureClientFn
	t.Cleanup(func() {
		newAzureCredentialFn = prevCred
		newAzureClientFn = prevClient
		viper.Reset()
	})
	newAzureCredentialFn = func(*azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) {
		return nil, errors.New("credential boom")
	}
	viper.Set(defaultAzureVaultURLKey, "https://vault.test")

	repo := NewRepository()
	ctx := context.Background()
	const keyRef = "https://vault.test/keys/name/version"

	errCalls := map[string]func() error{
		"GenerateSymetrycKeys": func() error {
			_, err := repo.GenerateSymetrycKeys(ctx, models.GenerateSymmetricKeyRequest{Size: common.Key256Bits})
			return err
		},
		"EncryptAES": func() error {
			_, err := repo.EncryptAES(ctx, models.EncryptAESRequest{SecretKey: keyRef, Value: "v"})
			return err
		},
		"RotateKey":     func() error { _, err := repo.RotateKey(ctx, models.RotateKeyRequest{KeyID: keyRef}); return err },
		"GetKey":        func() error { _, err := repo.GetKey(ctx, models.GetKeyRequest{KeyID: keyRef}); return err },
		"DeactivateKey": func() error { return repo.DeactivateKey(ctx, models.DeactivateKeyRequest{KeyID: keyRef}) },
		"GenerateRSAKeys": func() error {
			_, err := repo.GenerateRSAKeys(ctx, models.GenerateRSAKeyRequest{Size: common.Key2048Bits})
			return err
		},
		"GenerateECDHCurveKeys": func() error {
			_, err := repo.GenerateECDHCurveKeys(ctx, models.GenerateECDHCurveKeyRequest{Curve: common.CurveP256})
			return err
		},
		"RSA_OAEP_Encode": func() error {
			_, err := repo.RSA_OAEP_Encode(ctx, models.RSAOAEPEncodeRequest{PublicKey: keyRef, Text: "t"})
			return err
		},
		"ECDH_Encode": func() error {
			_, err := repo.ECDH_Encode(ctx, models.ECDHEncodeRequest{PublicKey: keyRef, Text: "t"})
			return err
		},
		"SignRSAPSS":   func() error { _, err := repo.SignRSAPSS(ctx, keyRef, "t"); return err },
		"VerifyRSAPSS": func() error { return repo.VerifyRSAPSS(ctx, keyRef, "t", "c2ln") },
	}

	for name, call := range errCalls {
		if err := call(); err == nil {
			t.Fatalf("%s() expected client factory error", name)
		}
	}

	if got := repo.HMAC(ctx, keyRef, "message"); got != "" {
		t.Fatalf("HMAC() = %q, want empty on client factory error", got)
	}
}

// TestAzureRotateKeyGetError covers the RotateKey branch where the post-rotation
// fetch of the rotated key fails.
func TestAzureRotateKeyGetError(t *testing.T) {
	bundle := azureECBundle(t)
	withFakeAzureClient(t, fakeAzureKeysClient{
		rotateKeyFn: func(context.Context, string, *azkeys.RotateKeyOptions) (azkeys.RotateKeyResponse, error) {
			return azkeys.RotateKeyResponse{KeyBundle: bundle}, nil
		},
		getKeyFn: func(context.Context, string, string, *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
			return azkeys.GetKeyResponse{}, errors.New("get boom")
		},
	})
	if _, err := NewKeyRepository().RotateKey(context.Background(), models.RotateKeyRequest{KeyID: "https://vault.test/keys/name/version"}); err == nil {
		t.Fatal("expected RotateKey() get error")
	}
}

// TestAzureDeactivateKeyGetBeforeDeactivate covers the version-less branch where
// DeactivateKey first fetches the key to resolve its current version.
func TestAzureDeactivateKeyGetBeforeDeactivate(t *testing.T) {
	bundle := azureECBundle(t)
	withFakeAzureClient(t, fakeAzureKeysClient{
		getKeyFn: func(context.Context, string, string, *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
			return azkeys.GetKeyResponse{KeyBundle: bundle}, nil
		},
		updateKeyFn: func(context.Context, string, string, azkeys.UpdateKeyParameters, *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error) {
			return azkeys.UpdateKeyResponse{KeyBundle: bundle}, nil
		},
	})
	if err := NewKeyRepository().DeactivateKey(context.Background(), models.DeactivateKeyRequest{KeyID: "https://vault.test/keys/name"}); err != nil {
		t.Fatalf("DeactivateKey() error = %v", err)
	}
}
