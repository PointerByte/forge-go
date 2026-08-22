// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package utilities

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/PointerByte/forge-go/encrypt/common"
)

// pemFixtures holds PEM files for each key type so the parsers can be exercised
// against both their happy and wrong-type branches.
type pemFixtures struct {
	dir         string
	garbage     string
	rsaPublic   string
	rsaPrivate  string
	edPublic    string
	edPrivate   string
	ecdhPublic  string
	ecdhPrivate string
}

func newPEMFixtures(t *testing.T) pemFixtures {
	t.Helper()
	dir := t.TempDir()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	rsaPrivDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal rsa private: %v", err)
	}
	rsaPubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal rsa public: %v", err)
	}

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	edPrivDER, err := x509.MarshalPKCS8PrivateKey(edPriv)
	if err != nil {
		t.Fatalf("marshal ed private: %v", err)
	}
	edPubDER, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatalf("marshal ed public: %v", err)
	}

	ecdhKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh.GenerateKey() error = %v", err)
	}
	ecdhPrivDER, err := x509.MarshalPKCS8PrivateKey(ecdhKey)
	if err != nil {
		t.Fatalf("marshal ecdh private: %v", err)
	}
	ecdhPubDER, err := x509.MarshalPKIXPublicKey(ecdhKey.PublicKey())
	if err != nil {
		t.Fatalf("marshal ecdh public: %v", err)
	}

	return pemFixtures{
		dir:         dir,
		garbage:     writePEMFile(t, dir, "garbage.pem", "PUBLIC KEY", []byte("not-a-valid-der")),
		rsaPublic:   writePEMFile(t, dir, "rsa-pub.pem", "PUBLIC KEY", rsaPubDER),
		rsaPrivate:  writePEMFile(t, dir, "rsa-priv.pem", "PRIVATE KEY", rsaPrivDER),
		edPublic:    writePEMFile(t, dir, "ed-pub.pem", "PUBLIC KEY", edPubDER),
		edPrivate:   writePEMFile(t, dir, "ed-priv.pem", "PRIVATE KEY", edPrivDER),
		ecdhPublic:  writePEMFile(t, dir, "ecdh-pub.pem", "PUBLIC KEY", ecdhPubDER),
		ecdhPrivate: writePEMFile(t, dir, "ecdh-priv.pem", "PRIVATE KEY", ecdhPrivDER),
	}
}

// TestPEMParsersErrorBranches exercises, for every PEM parser, the missing-file,
// invalid-DER (parse error) and wrong-key-type branches.
func TestPEMParsersErrorBranches(t *testing.T) {
	f := newPEMFixtures(t)
	missing := filepath.Join(f.dir, "missing.pem")

	parsers := map[string]func(string) error{
		"rsa-public":   func(s string) error { _, err := ParseRSAPublicKeyFromPEMFile(s); return err },
		"rsa-private":  func(s string) error { _, err := ParseRSAPrivateKeyFromPEMFile(s); return err },
		"ed-public":    func(s string) error { _, err := ParseEd25519PublicKeyFromPEMFile(s); return err },
		"ed-private":   func(s string) error { _, err := ParseEd25519PrivateKeyFromPEMFile(s); return err },
		"ecdh-public":  func(s string) error { _, err := ParseECDHPublicKeyFromPEMFile(s); return err },
		"ecdh-private": func(s string) error { _, err := ParseECDHPrivateKeyFromPEMFile(s); return err },
	}

	// wrongType maps each parser to a PEM file holding a key of a different type.
	wrongType := map[string]string{
		"rsa-public":   f.edPublic,
		"rsa-private":  f.edPrivate,
		"ed-public":    f.rsaPublic,
		"ed-private":   f.rsaPrivate,
		"ecdh-public":  f.edPublic,
		"ecdh-private": f.edPrivate,
	}

	for name, parse := range parsers {
		t.Run(name+"/missing file", func(t *testing.T) {
			if err := parse(missing); err == nil {
				t.Fatal("expected error for missing file")
			}
		})
		t.Run(name+"/invalid der", func(t *testing.T) {
			if err := parse(f.garbage); err == nil {
				t.Fatal("expected parse error for invalid DER")
			}
		})
		t.Run(name+"/wrong type", func(t *testing.T) {
			if err := parse(wrongType[name]); err == nil {
				t.Fatal("expected error for wrong key type")
			}
		})
	}
}

// TestParseECDHFromBase64WrongType covers the default branch of the type switch
// in the Base64 ECDH parsers (an Ed25519 key is neither ECDH nor ECDSA).
func TestParseECDHFromBase64WrongType(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	edPubDER, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatalf("marshal ed public: %v", err)
	}
	edPrivDER, err := x509.MarshalPKCS8PrivateKey(edPriv)
	if err != nil {
		t.Fatalf("marshal ed private: %v", err)
	}

	if _, err := ParseECDHPublicKeyFromBase64(base64.StdEncoding.EncodeToString(edPubDER)); err == nil {
		t.Fatal("expected error for non-ECC public key")
	}
	if _, err := ParseECDHPrivateKeyFromBase64(base64.StdEncoding.EncodeToString(edPrivDER)); err == nil {
		t.Fatal("expected error for non-ECC private key")
	}
}

// TestParseECDHFromECDSAUnsupportedCurve covers the ECDSA->ECDH conversion
// error branch: a P-224 ECDSA key parses as *ecdsa key but has no ECDH form.
func TestParseECDHFromECDSAUnsupportedCurve(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal ecdsa public: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatalf("marshal ecdsa private: %v", err)
	}

	if _, err := ParseECDHPublicKeyFromBase64(base64.StdEncoding.EncodeToString(pubDER)); err == nil {
		t.Fatal("expected ECDH conversion error for public key")
	}
	if _, err := ParseECDHPrivateKeyFromBase64(base64.StdEncoding.EncodeToString(privDER)); err == nil {
		t.Fatal("expected ECDH conversion error for private key")
	}

	dir := t.TempDir()
	pubPath := writePEMFile(t, dir, "ecdsa-pub.pem", "PUBLIC KEY", pubDER)
	privPath := writePEMFile(t, dir, "ecdsa-priv.pem", "PRIVATE KEY", privDER)

	if _, err := ParseECDHPublicKeyFromPEMFile(pubPath); err == nil {
		t.Fatal("expected ECDH conversion error for public PEM key")
	}
	if _, err := ParseECDHPrivateKeyFromPEMFile(privPath); err == nil {
		t.Fatal("expected ECDH conversion error for private PEM key")
	}
}

// TestResolveECDHCurveAllCases covers every supported curve plus the default.
func TestResolveECDHCurveAllCases(t *testing.T) {
	tests := []struct {
		name    string
		in      common.CurveAsymmetricKey
		want    ecdh.Curve
		wantErr bool
	}{
		{name: "P256", in: common.CurveP256, want: ecdh.P256()},
		{name: "P384", in: common.CurveP384, want: ecdh.P384()},
		{name: "P521", in: common.CurveP521, want: ecdh.P521()},
		{name: "unsupported", in: common.CurveAsymmetricKey(99), wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ResolveECDHCurve(test.in)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveECDHCurve() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("ResolveECDHCurve() = %v, want %v", got, test.want)
			}
		})
	}
}

// TestCurveNameFromECDHAllCases covers each named curve.
func TestCurveNameFromECDHAllCases(t *testing.T) {
	tests := []struct {
		name string
		in   ecdh.Curve
		want string
	}{
		{name: "P256", in: ecdh.P256(), want: common.CurveP256.String()},
		{name: "P384", in: ecdh.P384(), want: common.CurveP384.String()},
		{name: "P521", in: ecdh.P521(), want: common.CurveP521.String()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := CurveNameFromECDH(test.in)
			if err != nil {
				t.Fatalf("CurveNameFromECDH() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("CurveNameFromECDH() = %q, want %q", got, test.want)
			}
		})
	}
}

// TestDecodeECCCipherPayloadErrors covers the decode and unmarshal error
// branches that the happy-path test does not reach.
func TestDecodeECCCipherPayloadErrors(t *testing.T) {
	if _, err := DecodeECCCipherPayload("%%%not-base64%%%"); err == nil {
		t.Fatal("expected base64 decode error")
	}
	if _, err := DecodeECCCipherPayload(base64.StdEncoding.EncodeToString([]byte("not json"))); err == nil {
		t.Fatal("expected json unmarshal error")
	}
}
