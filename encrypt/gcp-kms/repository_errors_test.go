// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package gcpkms

import (
	"context"
	"errors"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/models"
	"github.com/spf13/viper"
)

// erroringGCPClient returns a fake client whose every remote call fails, used to
// exercise the client-error branches of the repository methods.
func erroringGCPClient() fakeGCPClient {
	boom := errors.New("gcp boom")
	return fakeGCPClient{
		createCryptoKeyFn: func(context.Context, *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
			return nil, boom
		},
		createCryptoKeyVersionFn: func(context.Context, *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
			return nil, boom
		},
		getCryptoKeyFn: func(context.Context, *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
			return nil, boom
		},
		getPublicKeyFn: func(context.Context, *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
			return nil, boom
		},
		updateKeyVersionFn: func(context.Context, *kmspb.UpdateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
			return nil, boom
		},
		updatePrimaryFn: func(context.Context, *kmspb.UpdateCryptoKeyPrimaryVersionRequest) (*kmspb.CryptoKey, error) {
			return nil, boom
		},
		encryptFn: func(context.Context, *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
			return nil, boom
		},
		decryptFn: func(context.Context, *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
			return nil, boom
		},
		asymmetricSignFn: func(context.Context, *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
			return nil, boom
		},
		macSignFn: func(context.Context, *kmspb.MacSignRequest) (*kmspb.MacSignResponse, error) {
			return nil, boom
		},
		closeFn: func() error { return nil },
	}
}

// TestGCPRepositoryClientErrorBranches covers the remote-call error branches of
// the key, symmetric, hash and asymmetric repositories.
func TestGCPRepositoryClientErrorBranches(t *testing.T) {
	prev := newGCPClientFn
	t.Cleanup(func() {
		newGCPClientFn = prev
		viper.Reset()
	})
	newGCPClientFn = func(context.Context) (gcpKMSClient, error) {
		return erroringGCPClient(), nil
	}

	const versionRef = "projects/test/locations/global/keyRings/ring/cryptoKeys/k/cryptoKeyVersions/1"
	const keyRef = "projects/test/locations/global/keyRings/ring/cryptoKeys/k"
	viper.Set(defaultGCPKeyIDKey, versionRef)

	repo := NewRepository()
	ctx := context.Background()

	if _, err := repo.RotateKey(ctx, models.RotateKeyRequest{KeyID: versionRef}); err == nil {
		t.Fatal("expected RotateKey() error")
	}
	if _, err := repo.GetKey(ctx, models.GetKeyRequest{KeyID: versionRef}); err == nil {
		t.Fatal("expected GetKey() error")
	}
	if err := repo.DeactivateKey(ctx, models.DeactivateKeyRequest{KeyID: versionRef}); err == nil {
		t.Fatal("expected DeactivateKey() error")
	}
	if _, err := repo.EncryptAES(ctx, models.EncryptAESRequest{SecretKey: keyRef, Value: "payload"}); err == nil {
		t.Fatal("expected EncryptAES() error")
	}
	if got := repo.HMAC(ctx, versionRef, "message"); got != "" {
		t.Fatalf("HMAC() = %q, want empty on error", got)
	}
	if _, err := repo.GenerateRSAKeys(ctx, models.GenerateRSAKeyRequest{Size: common.Key2048Bits}); err == nil {
		t.Fatal("expected GenerateRSAKeys() error")
	}
	if _, err := repo.GenerateEd255Keys(ctx); err == nil {
		t.Fatal("expected GenerateEd255Keys() error")
	}
	if _, err := repo.GenerateECDHCurveKeys(ctx, models.GenerateECDHCurveKeyRequest{Curve: common.CurveP256}); err == nil {
		t.Fatal("expected GenerateECDHCurveKeys() error")
	}
}

// TestGCPClientFactoryError covers the newGCPClient error branch shared by every
// remote method by making the client factory fail.
func TestGCPClientFactoryError(t *testing.T) {
	prev := newGCPClientFn
	t.Cleanup(func() {
		newGCPClientFn = prev
		viper.Reset()
	})
	newGCPClientFn = func(context.Context) (gcpKMSClient, error) {
		return nil, errors.New("client factory boom")
	}

	const versionRef = "projects/test/locations/global/keyRings/ring/cryptoKeys/k/cryptoKeyVersions/1"
	const keyRef = "projects/test/locations/global/keyRings/ring/cryptoKeys/k"
	viper.Set(defaultGCPKeyIDKey, versionRef)

	repo := NewRepository()
	ctx := context.Background()

	errCalls := map[string]func() error{
		"GenerateSymetrycKeys": func() error {
			_, err := repo.GenerateSymetrycKeys(ctx, models.GenerateSymmetricKeyRequest{Size: common.Key256Bits})
			return err
		},
		"RotateKey":     func() error { _, err := repo.RotateKey(ctx, models.RotateKeyRequest{KeyID: versionRef}); return err },
		"GetKey":        func() error { _, err := repo.GetKey(ctx, models.GetKeyRequest{KeyID: versionRef}); return err },
		"DeactivateKey": func() error { return repo.DeactivateKey(ctx, models.DeactivateKeyRequest{KeyID: versionRef}) },
		"EncryptAES": func() error {
			_, err := repo.EncryptAES(ctx, models.EncryptAESRequest{SecretKey: keyRef, Value: "v"})
			return err
		},
		"GenerateRSAKeys": func() error {
			_, err := repo.GenerateRSAKeys(ctx, models.GenerateRSAKeyRequest{Size: common.Key2048Bits})
			return err
		},
		"GenerateEd255Keys": func() error { _, err := repo.GenerateEd255Keys(ctx); return err },
		"GenerateECDHCurveKeys": func() error {
			_, err := repo.GenerateECDHCurveKeys(ctx, models.GenerateECDHCurveKeyRequest{Curve: common.CurveP256})
			return err
		},
		"RSA_OAEP_Encode": func() error {
			_, err := repo.RSA_OAEP_Encode(ctx, models.RSAOAEPEncodeRequest{PublicKey: versionRef, Text: "t"})
			return err
		},
		"ECDH_Encode": func() error {
			_, err := repo.ECDH_Encode(ctx, models.ECDHEncodeRequest{PublicKey: versionRef, Text: "t"})
			return err
		},
		"SignEd25519":   func() error { _, err := repo.SignEd25519(ctx, versionRef, "t"); return err },
		"VerifyEd25519": func() error { return repo.VerifyEd25519(ctx, versionRef, "t", "s") },
		"SignRSAPSS":    func() error { _, err := repo.SignRSAPSS(ctx, versionRef, "t"); return err },
		"VerifyRSAPSS":  func() error { return repo.VerifyRSAPSS(ctx, versionRef, "t", "s") },
	}

	for name, call := range errCalls {
		if err := call(); err == nil {
			t.Fatalf("%s() expected client factory error", name)
		}
	}

	// HMAC swallows errors and returns an empty string.
	if got := repo.HMAC(ctx, versionRef, "message"); got != "" {
		t.Fatalf("HMAC() = %q, want empty on client factory error", got)
	}
}

// TestGCPHMACVersionError covers the HMAC branch where the key reference cannot
// be resolved to a crypto key version.
func TestGCPHMACVersionError(t *testing.T) {
	prev := newGCPClientFn
	t.Cleanup(func() {
		newGCPClientFn = prev
		viper.Reset()
	})
	newGCPClientFn = func(context.Context) (gcpKMSClient, error) {
		return erroringGCPClient(), nil
	}

	// A key reference without a version segment resolves the client but fails
	// version resolution, returning an empty MAC.
	const keyRef = "projects/test/locations/global/keyRings/ring/cryptoKeys/k"
	if got := NewRepository().HMAC(context.Background(), keyRef, "message"); got != "" {
		t.Fatalf("HMAC() = %q, want empty on version error", got)
	}
}
