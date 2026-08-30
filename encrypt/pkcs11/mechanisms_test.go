// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"
)

func slotWith(mechs ...mechanism) *slotState {
	supported := make(map[mechanism]bool, len(mechs))
	for _, mech := range mechs {
		supported[mech] = true
	}
	return &slotState{mechanisms: supported}
}

func TestPlanRSAPKCS1v15(t *testing.T) {
	combined, err := planRSAPKCS1v15(slotWith(ckmSHA256RSAPKCS))
	if err != nil {
		t.Fatalf("planRSAPKCS1v15() error = %v", err)
	}
	if combined.mechanism != ckmSHA256RSAPKCS {
		t.Fatalf("mechanism = %v, want CKM_SHA256_RSA_PKCS", combined.mechanism)
	}
	message := []byte("payload")
	if !bytes.Equal(combined.prepare(message), message) {
		t.Fatal("the combined mechanism must receive the message unchanged")
	}

	raw, err := planRSAPKCS1v15(slotWith(ckmRSAPKCS))
	if err != nil {
		t.Fatalf("planRSAPKCS1v15() error = %v", err)
	}
	if raw.mechanism != ckmRSAPKCS {
		t.Fatalf("mechanism = %v, want the raw fallback", raw.mechanism)
	}

	if _, err := planRSAPKCS1v15(slotWith()); err == nil {
		t.Fatal("planRSAPKCS1v15() must fail when neither mechanism exists")
	}
}

// TestRawPKCS1v15FallbackMatchesGo is the property that makes the degradation
// safe: a token that only implements CKM_RSA_PKCS must produce exactly the
// signature CKM_SHA256_RSA_PKCS would have produced.
func TestRawPKCS1v15FallbackMatchesGo(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	message := []byte("sign me")

	plan, err := planRSAPKCS1v15(slotWith(ckmRSAPKCS))
	if err != nil {
		t.Fatalf("planRSAPKCS1v15() error = %v", err)
	}
	// CKM_RSA_PKCS applies the PKCS#1 v1.5 padding to whatever it is given, so
	// feeding it DigestInfo||digest is equivalent to SignPKCS1v15.
	prepared := plan.prepare(message)
	fromRaw, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.Hash(0), prepared)
	if err != nil {
		t.Fatalf("SignPKCS1v15() error = %v", err)
	}

	digest := sha256.Sum256(message)
	fromCombined, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15() error = %v", err)
	}

	if !bytes.Equal(fromRaw, fromCombined) {
		t.Fatal("the raw-mechanism fallback does not reproduce the combined signature")
	}
}

func TestPlanRSAPSS(t *testing.T) {
	combined, err := planRSAPSS(slotWith(ckmSHA256RSAPKCSPSS))
	if err != nil {
		t.Fatalf("planRSAPSS() error = %v", err)
	}
	params, ok := combined.params.(pssParams)
	if !ok {
		t.Fatalf("params = %T, want pssParams", combined.params)
	}
	if params.SaltLen != sha256.Size || params.HashAlg != ckmSHA256 || params.MGF != ckgMGF1SHA256 {
		t.Fatalf("params = %+v, want SHA-256 with MGF1-SHA256 and a digest-sized salt", params)
	}

	raw, err := planRSAPSS(slotWith(ckmRSAPKCSPSS))
	if err != nil {
		t.Fatalf("planRSAPSS() error = %v", err)
	}
	if raw.mechanism != ckmRSAPKCSPSS {
		t.Fatalf("mechanism = %v, want the raw fallback", raw.mechanism)
	}
	digest := raw.prepare([]byte("x"))
	if len(digest) != sha256.Size {
		t.Fatalf("the raw mechanism must be fed a digest, got %d bytes", len(digest))
	}

	if _, err := planRSAPSS(slotWith()); err == nil {
		t.Fatal("planRSAPSS() must fail when neither mechanism exists")
	}
}

func TestPlanEd25519(t *testing.T) {
	plan, err := planEd25519(slotWith(ckmEdDSA))
	if err != nil {
		t.Fatalf("planEd25519() error = %v", err)
	}
	message := []byte("pure eddsa")
	// EdDSA is a pure scheme: the message must reach the token unhashed.
	if !bytes.Equal(plan.prepare(message), message) {
		t.Fatal("Ed25519 must not pre-hash the message")
	}

	err = planEd25519Err(t)
	var unsupported unsupportedMechanismError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error = %T, want unsupportedMechanismError", err)
	}
}

func planEd25519Err(t *testing.T) error {
	t.Helper()
	_, err := planEd25519(slotWith())
	if err == nil {
		t.Fatal("planEd25519() must fail on a token without CKM_EDDSA")
	}
	return err
}

func TestSha256DigestHelpers(t *testing.T) {
	message := []byte("abc")
	digest := sha256Digest(message)
	want := sha256.Sum256(message)
	if !bytes.Equal(digest, want[:]) {
		t.Fatal("sha256Digest() does not match crypto/sha256")
	}

	info := sha256DigestInfo(message)
	if !bytes.HasPrefix(info, sha256DigestInfoPrefix) {
		t.Fatal("sha256DigestInfo() must start with the DigestInfo header")
	}
	if !bytes.Equal(info[len(sha256DigestInfoPrefix):], want[:]) {
		t.Fatal("sha256DigestInfo() must end with the digest")
	}
}

// TestSupportsInHardwareECDH pins which mechanism set unlocks the path where
// no derived secret ever leaves the token.
func TestSupportsInHardwareECDH(t *testing.T) {
	tests := []struct {
		name string
		slot *slotState
		want bool
	}{
		{name: "all three", slot: slotWith(ckmECDH1Derive, ckmHKDFDerive, ckmAESGCM), want: true},
		{name: "no hkdf", slot: slotWith(ckmECDH1Derive, ckmAESGCM), want: false},
		{name: "no gcm", slot: slotWith(ckmECDH1Derive, ckmHKDFDerive), want: false},
		{name: "none", slot: slotWith(), want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := supportsInHardwareECDH(test.slot); got != test.want {
				t.Fatalf("supportsInHardwareECDH() = %v, want %v", got, test.want)
			}
		})
	}
}
