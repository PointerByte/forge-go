// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"context"
	"errors"
	"testing"

	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/models"
)

// TestRemainingMethodsRespectCanceledContext covers the canceled-context error
// branches of the hash, asymmetric and signature methods not exercised by
// TestRepositoriesRespectCanceledContext.
func TestRemainingMethodsRespectCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(testContext)
	cancel()

	hash := NewHashRepository()
	if got := hash.Sha256Hex(ctx, "message"); got != "" {
		t.Fatalf("Sha256Hex() = %q, want empty for canceled context", got)
	}
	if got := hash.Blake3(ctx, "message"); got != "" {
		t.Fatalf("Blake3() = %q, want empty for canceled context", got)
	}

	asym := NewAsymmetricRepository()
	asymCalls := map[string]func() error{
		"GenerateECDHCurveKeys": func() error {
			_, err := asym.GenerateECDHCurveKeys(ctx, models.GenerateECDHCurveKeyRequest{Curve: common.CurveP256})
			return err
		},
		"RSA_OAEP_Encode": func() error {
			_, err := asym.RSA_OAEP_Encode(ctx, models.RSAOAEPEncodeRequest{PublicKey: "k", Text: "t"})
			return err
		},
		"RSA_OAEP_Decode": func() error {
			_, err := asym.RSA_OAEP_Decode(ctx, models.RSAOAEPDecodeRequest{PrivateKey: "k", CipherText: "c"})
			return err
		},
		"ECDH_Encode": func() error {
			_, err := asym.ECDH_Encode(ctx, models.ECDHEncodeRequest{PublicKey: "k", Text: "t"})
			return err
		},
		"ECDH_Decode": func() error {
			_, err := asym.ECDH_Decode(ctx, models.ECDHDecodeRequest{PrivateKey: "k", CipherText: "c"})
			return err
		},
	}

	sig := NewSignatureRepository()
	sigCalls := map[string]func() error{
		"SignEd25519":              func() error { _, err := sig.SignEd25519(ctx, "k", "t"); return err },
		"VerifyEd25519":            func() error { return sig.VerifyEd25519(ctx, "k", "t", "s") },
		"SignRSAPSS":               func() error { _, err := sig.SignRSAPSS(ctx, "k", "t"); return err },
		"VerifyRSAPSS":             func() error { return sig.VerifyRSAPSS(ctx, "k", "t", "s") },
		"Sign_RSA_PKCS1v15_SHA256": func() error { _, err := sig.Sign_RSA_PKCS1v15_SHA256(ctx, "k", "d"); return err },
		"Verify_RSA_PKCS1v15_SHA256": func() error {
			return sig.Verify_RSA_PKCS1v15_SHA256(ctx, "d", "k", "s")
		},
	}

	for name, call := range asymCalls {
		if err := call(); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s() error = %v, want context.Canceled", name, err)
		}
	}
	for name, call := range sigCalls {
		if err := call(); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s() error = %v, want context.Canceled", name, err)
		}
	}
}

func TestContextErr(t *testing.T) {
	var nilCtx context.Context
	if err := contextErr(nilCtx); err == nil {
		t.Fatal("expected contextErr(nil) error")
	}
	if err := contextErr(context.Background()); err != nil {
		t.Fatalf("contextErr(background) = %v, want nil", err)
	}
}

func TestValidateSymmetricKeySize(t *testing.T) {
	for _, size := range []common.SizeSymetrycKey{common.Key128Bits, common.Key256Bits} {
		if err := validateSymmetricKeySize(size); err != nil {
			t.Fatalf("validateSymmetricKeySize(%d) = %v, want nil", size, err)
		}
	}
	if err := validateSymmetricKeySize(common.SizeSymetrycKey(7)); err == nil {
		t.Fatal("expected validateSymmetricKeySize() error for unsupported size")
	}
}
