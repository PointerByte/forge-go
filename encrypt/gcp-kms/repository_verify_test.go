// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package gcpkms

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/spf13/viper"
)

const gcpVerifyKeyRef = "projects/test/locations/global/keyRings/ring/cryptoKeys/k/cryptoKeyVersions/1"

// gcpPublicKeyClient installs a fake GCP client whose GetPublicKey returns the
// provided PEM, restoring the previous factory on cleanup.
func gcpPublicKeyClient(t *testing.T, pemKey string) {
	t.Helper()
	prev := newGCPClientFn
	t.Cleanup(func() {
		newGCPClientFn = prev
		viper.Reset()
	})
	newGCPClientFn = func(context.Context) (gcpKMSClient, error) {
		return fakeGCPClient{
			getPublicKeyFn: func(context.Context, *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
				return &kmspb.PublicKey{Pem: pemKey}, nil
			},
			closeFn: func() error { return nil },
		}, nil
	}
}

func pemFromDER(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestGCPVerifyErrorBranches covers the parse-error, wrong-key-type,
// signature-decode and invalid-signature branches of the remote verify methods.
func TestGCPVerifyErrorBranches(t *testing.T) {
	rsaKey := mustGCPRSAKey(t)
	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal rsa public: %v", err)
	}
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	edDER, err := x509.MarshalPKIXPublicKey(edPublic)
	if err != nil {
		t.Fatalf("marshal ed public: %v", err)
	}

	garbagePEM := pemFromDER([]byte("not-a-valid-der"))
	rsaPEM := pemFromDER(rsaDER)
	edPEM := pemFromDER(edDER)
	validSig := "YWJjZA==" // base64("abcd"), a syntactically valid but wrong signature

	repo := NewRepository()
	ctx := context.Background()

	t.Run("VerifyEd25519", func(t *testing.T) {
		cases := []struct {
			name   string
			pemKey string
			sig    string
		}{
			{name: "parse error", pemKey: garbagePEM, sig: validSig},
			{name: "wrong key type", pemKey: rsaPEM, sig: validSig},
			{name: "signature decode error", pemKey: edPEM, sig: "%%%"},
			{name: "invalid signature", pemKey: edPEM, sig: validSig},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				gcpPublicKeyClient(t, c.pemKey)
				if err := repo.VerifyEd25519(ctx, gcpVerifyKeyRef, "payload", c.sig); err == nil {
					t.Fatal("expected error")
				}
			})
		}
	})

	t.Run("VerifyRSAPSS", func(t *testing.T) {
		cases := []struct {
			name   string
			pemKey string
			sig    string
		}{
			{name: "parse error", pemKey: garbagePEM, sig: validSig},
			{name: "wrong key type", pemKey: edPEM, sig: validSig},
			{name: "signature decode error", pemKey: rsaPEM, sig: "%%%"},
			{name: "invalid signature", pemKey: rsaPEM, sig: validSig},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				gcpPublicKeyClient(t, c.pemKey)
				if err := repo.VerifyRSAPSS(ctx, gcpVerifyKeyRef, "payload", c.sig); err == nil {
					t.Fatal("expected error")
				}
			})
		}
	})

	t.Run("Verify_RSA_PKCS1v15_SHA256", func(t *testing.T) {
		cases := []struct {
			name   string
			pemKey string
			sig    string
		}{
			{name: "parse error", pemKey: garbagePEM, sig: validSig},
			{name: "wrong key type", pemKey: edPEM, sig: validSig},
			{name: "signature decode error", pemKey: rsaPEM, sig: "%%%"},
			{name: "invalid signature", pemKey: rsaPEM, sig: validSig},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				gcpPublicKeyClient(t, c.pemKey)
				if err := repo.Verify_RSA_PKCS1v15_SHA256(ctx, "payload", gcpVerifyKeyRef, c.sig); err == nil {
					t.Fatal("expected error")
				}
			})
		}
	})
}
