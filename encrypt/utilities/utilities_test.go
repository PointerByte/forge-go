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
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/PointerByte/forge-go/encrypt/common"
)

func TestParseRSAKeysFromBase64(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}

	gotPublic, err := ParseRSAPublicKeyFromBase64(base64.StdEncoding.EncodeToString(publicDER))
	if err != nil {
		t.Fatalf("ParseRSAPublicKeyFromBase64() error = %v", err)
	}
	if gotPublic.N.Cmp(privateKey.PublicKey.N) != 0 || gotPublic.E != privateKey.PublicKey.E {
		t.Fatal("ParseRSAPublicKeyFromBase64() returned unexpected key")
	}

	gotPrivate, err := ParseRSAPrivateKeyFromBase64(base64.StdEncoding.EncodeToString(privateDER))
	if err != nil {
		t.Fatalf("ParseRSAPrivateKeyFromBase64() error = %v", err)
	}
	if gotPrivate.N.Cmp(privateKey.N) != 0 || gotPrivate.E != privateKey.E {
		t.Fatal("ParseRSAPrivateKeyFromBase64() returned unexpected key")
	}
}

func TestParseRSAKeysFromBase64Errors(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
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

	pkcs1Private := x509.MarshalPKCS1PrivateKey(privateKey)
	pkcs1Public := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)

	tests := []struct {
		name string
		fn   func(string) error
		in   string
	}{
		{name: "public bad base64", fn: func(s string) error { _, err := ParseRSAPublicKeyFromBase64(s); return err }, in: "%%%"},
		{name: "public parse failure", fn: func(s string) error { _, err := ParseRSAPublicKeyFromBase64(s); return err }, in: base64.StdEncoding.EncodeToString(pkcs1Public)},
		{name: "public wrong type", fn: func(s string) error { _, err := ParseRSAPublicKeyFromBase64(s); return err }, in: base64.StdEncoding.EncodeToString(edPublicDER)},
		{name: "private bad base64", fn: func(s string) error { _, err := ParseRSAPrivateKeyFromBase64(s); return err }, in: "%%%"},
		{name: "private parse failure", fn: func(s string) error { _, err := ParseRSAPrivateKeyFromBase64(s); return err }, in: base64.StdEncoding.EncodeToString(pkcs1Private)},
		{name: "private wrong type", fn: func(s string) error { _, err := ParseRSAPrivateKeyFromBase64(s); return err }, in: base64.StdEncoding.EncodeToString(edPrivateDER)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.fn(test.in); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseEd25519KeysFromBase64(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}

	gotPublic, err := ParseEd25519PublicKeyFromBase64(base64.StdEncoding.EncodeToString(publicDER))
	if err != nil {
		t.Fatalf("ParseEd25519PublicKeyFromBase64() error = %v", err)
	}
	if string(gotPublic) != string(publicKey) {
		t.Fatal("ParseEd25519PublicKeyFromBase64() returned unexpected key")
	}

	gotPrivate, err := ParseEd25519PrivateKeyFromBase64(base64.StdEncoding.EncodeToString(privateDER))
	if err != nil {
		t.Fatalf("ParseEd25519PrivateKeyFromBase64() error = %v", err)
	}
	if string(gotPrivate) != string(privateKey) {
		t.Fatal("ParseEd25519PrivateKeyFromBase64() returned unexpected key")
	}
}

func TestParseEd25519KeysFromBase64Errors(t *testing.T) {
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	rsaPublicDER, err := x509.MarshalPKIXPublicKey(&rsaPrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	rsaPrivateDER, err := x509.MarshalPKCS8PrivateKey(rsaPrivateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}

	tests := []struct {
		name string
		fn   func(string) error
		in   string
	}{
		{name: "public bad base64", fn: func(s string) error { _, err := ParseEd25519PublicKeyFromBase64(s); return err }, in: "%%%"},
		{name: "public parse failure", fn: func(s string) error { _, err := ParseEd25519PublicKeyFromBase64(s); return err }, in: base64.StdEncoding.EncodeToString([]byte("bad"))},
		{name: "public wrong type", fn: func(s string) error { _, err := ParseEd25519PublicKeyFromBase64(s); return err }, in: base64.StdEncoding.EncodeToString(rsaPublicDER)},
		{name: "private bad base64", fn: func(s string) error { _, err := ParseEd25519PrivateKeyFromBase64(s); return err }, in: "%%%"},
		{name: "private parse failure", fn: func(s string) error { _, err := ParseEd25519PrivateKeyFromBase64(s); return err }, in: base64.StdEncoding.EncodeToString([]byte("bad"))},
		{name: "private wrong type", fn: func(s string) error { _, err := ParseEd25519PrivateKeyFromBase64(s); return err }, in: base64.StdEncoding.EncodeToString(rsaPrivateDER)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.fn(test.in); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseECDHKeysFromBase64(t *testing.T) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh.GenerateKey() error = %v", err)
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}

	gotPublic, err := ParseECDHPublicKeyFromBase64(base64.StdEncoding.EncodeToString(publicDER))
	if err != nil {
		t.Fatalf("ParseECDHPublicKeyFromBase64() error = %v", err)
	}
	if !gotPublic.Equal(privateKey.PublicKey()) {
		t.Fatal("ParseECDHPublicKeyFromBase64() returned unexpected key")
	}

	gotPrivate, err := ParseECDHPrivateKeyFromBase64(base64.StdEncoding.EncodeToString(privateDER))
	if err != nil {
		t.Fatalf("ParseECDHPrivateKeyFromBase64() error = %v", err)
	}
	if !gotPrivate.Equal(privateKey) {
		t.Fatal("ParseECDHPrivateKeyFromBase64() returned unexpected key")
	}
}

func TestParseECDHKeysFromBase64AcceptsECDSAEncoding(t *testing.T) {
	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(ecdsaPrivateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&ecdsaPrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}

	if _, err := ParseECDHPrivateKeyFromBase64(base64.StdEncoding.EncodeToString(privateDER)); err != nil {
		t.Fatalf("ParseECDHPrivateKeyFromBase64() ecdsa error = %v", err)
	}
	if _, err := ParseECDHPublicKeyFromBase64(base64.StdEncoding.EncodeToString(publicDER)); err != nil {
		t.Fatalf("ParseECDHPublicKeyFromBase64() ecdsa error = %v", err)
	}
}

func TestParseECDHKeysFromBase64Errors(t *testing.T) {
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	rsaPublicDER, err := x509.MarshalPKIXPublicKey(&rsaPrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	rsaPrivateDER, err := x509.MarshalPKCS8PrivateKey(rsaPrivateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}

	tests := []struct {
		name string
		fn   func(string) error
		in   string
	}{
		{name: "public bad base64", fn: func(s string) error { _, err := ParseECDHPublicKeyFromBase64(s); return err }, in: "%%%"},
		{name: "public parse failure", fn: func(s string) error { _, err := ParseECDHPublicKeyFromBase64(s); return err }, in: base64.StdEncoding.EncodeToString([]byte("bad"))},
		{name: "public wrong type", fn: func(s string) error { _, err := ParseECDHPublicKeyFromBase64(s); return err }, in: base64.StdEncoding.EncodeToString(rsaPublicDER)},
		{name: "private bad base64", fn: func(s string) error { _, err := ParseECDHPrivateKeyFromBase64(s); return err }, in: "%%%"},
		{name: "private parse failure", fn: func(s string) error { _, err := ParseECDHPrivateKeyFromBase64(s); return err }, in: base64.StdEncoding.EncodeToString([]byte("bad"))},
		{name: "private wrong type", fn: func(s string) error { _, err := ParseECDHPrivateKeyFromBase64(s); return err }, in: base64.StdEncoding.EncodeToString(rsaPrivateDER)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.fn(test.in); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseKeysFromPEMFiles(t *testing.T) {
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	rsaPrivateDER, err := x509.MarshalPKCS8PrivateKey(rsaPrivateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	rsaPublicDER, err := x509.MarshalPKIXPublicKey(&rsaPrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}

	edPublicKey, edPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	edPrivateDER, err := x509.MarshalPKCS8PrivateKey(edPrivateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	edPublicDER, err := x509.MarshalPKIXPublicKey(edPublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}

	ecdhPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh.GenerateKey() error = %v", err)
	}
	ecdhPrivateDER, err := x509.MarshalPKCS8PrivateKey(ecdhPrivateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	ecdhPublicDER, err := x509.MarshalPKIXPublicKey(ecdhPrivateKey.PublicKey())
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}

	tempDir := t.TempDir()
	rsaPrivatePath := writePEMFile(t, tempDir, "rsa-private.pem", "PRIVATE KEY", rsaPrivateDER)
	rsaPublicPath := writePEMFile(t, tempDir, "rsa-public.pem", "PUBLIC KEY", rsaPublicDER)
	edPrivatePath := writePEMFile(t, tempDir, "ed-private.pem", "PRIVATE KEY", edPrivateDER)
	edPublicPath := writePEMFile(t, tempDir, "ed-public.pem", "PUBLIC KEY", edPublicDER)
	ecdhPrivatePath := writePEMFile(t, tempDir, "ecdh-private.pem", "PRIVATE KEY", ecdhPrivateDER)
	ecdhPublicPath := writePEMFile(t, tempDir, "ecdh-public.pem", "PUBLIC KEY", ecdhPublicDER)

	gotRSAPublic, err := ParseRSAPublicKeyFromPEMFile(rsaPublicPath)
	if err != nil {
		t.Fatalf("ParseRSAPublicKeyFromPEMFile() error = %v", err)
	}
	if gotRSAPublic.N.Cmp(rsaPrivateKey.PublicKey.N) != 0 || gotRSAPublic.E != rsaPrivateKey.PublicKey.E {
		t.Fatal("ParseRSAPublicKeyFromPEMFile() returned unexpected key")
	}

	gotRSAPrivate, err := ParseRSAPrivateKeyFromPEMFile(rsaPrivatePath)
	if err != nil {
		t.Fatalf("ParseRSAPrivateKeyFromPEMFile() error = %v", err)
	}
	if gotRSAPrivate.N.Cmp(rsaPrivateKey.N) != 0 || gotRSAPrivate.E != rsaPrivateKey.E {
		t.Fatal("ParseRSAPrivateKeyFromPEMFile() returned unexpected key")
	}

	gotEdPublic, err := ParseEd25519PublicKeyFromPEMFile(edPublicPath)
	if err != nil {
		t.Fatalf("ParseEd25519PublicKeyFromPEMFile() error = %v", err)
	}
	if string(gotEdPublic) != string(edPublicKey) {
		t.Fatal("ParseEd25519PublicKeyFromPEMFile() returned unexpected key")
	}

	gotEdPrivate, err := ParseEd25519PrivateKeyFromPEMFile(edPrivatePath)
	if err != nil {
		t.Fatalf("ParseEd25519PrivateKeyFromPEMFile() error = %v", err)
	}
	if string(gotEdPrivate) != string(edPrivateKey) {
		t.Fatal("ParseEd25519PrivateKeyFromPEMFile() returned unexpected key")
	}

	gotECDHPublic, err := ParseECDHPublicKeyFromPEMFile(ecdhPublicPath)
	if err != nil {
		t.Fatalf("ParseECDHPublicKeyFromPEMFile() error = %v", err)
	}
	if !gotECDHPublic.Equal(ecdhPrivateKey.PublicKey()) {
		t.Fatal("ParseECDHPublicKeyFromPEMFile() returned unexpected key")
	}

	gotECDHPrivate, err := ParseECDHPrivateKeyFromPEMFile(ecdhPrivatePath)
	if err != nil {
		t.Fatalf("ParseECDHPrivateKeyFromPEMFile() error = %v", err)
	}
	if !gotECDHPrivate.Equal(ecdhPrivateKey) {
		t.Fatal("ParseECDHPrivateKeyFromPEMFile() returned unexpected key")
	}
}

func TestParseKeysFromPEMFilesErrors(t *testing.T) {
	tempDir := t.TempDir()
	invalidPath := filepath.Join(tempDir, "invalid.pem")
	if err := os.WriteFile(invalidPath, []byte("not pem"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	rsaPublicDER, err := x509.MarshalPKIXPublicKey(&rsaPrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	rsaPublicPath := writePEMFile(t, tempDir, "rsa-public.pem", "PUBLIC KEY", rsaPublicDER)

	tests := []struct {
		name string
		fn   func(string) error
		in   string
	}{
		{name: "rsa public missing file", fn: func(s string) error { _, err := ParseRSAPublicKeyFromPEMFile(s); return err }, in: filepath.Join(tempDir, "missing.pem")},
		{name: "rsa public invalid pem", fn: func(s string) error { _, err := ParseRSAPublicKeyFromPEMFile(s); return err }, in: invalidPath},
		{name: "ed private wrong type", fn: func(s string) error { _, err := ParseEd25519PrivateKeyFromPEMFile(s); return err }, in: rsaPublicPath},
		{name: "ecdh public wrong type", fn: func(s string) error { _, err := ParseECDHPublicKeyFromPEMFile(s); return err }, in: rsaPublicPath},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.fn(test.in); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSharedHelpers(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if !IsLocalAESKey(key) {
		t.Fatal("expected IsLocalAESKey() to recognize a valid AES key")
	}
	if IsLocalAESKey("%%%") {
		t.Fatal("expected IsLocalAESKey() to reject invalid base64")
	}
	if got := BytesFromOptionalString(nil); got != nil {
		t.Fatal("expected BytesFromOptionalString(nil) to return nil")
	}
	value := "aad"
	if got := string(BytesFromOptionalString(&value)); got != value {
		t.Fatalf("BytesFromOptionalString() = %q, want %q", got, value)
	}

	curve, err := ResolveECDHCurve(common.CurveP256)
	if err != nil || curve != ecdh.P256() {
		t.Fatalf("ResolveECDHCurve() = %v, %v", curve, err)
	}
	if _, err := ResolveECDHCurve(common.CurveAsymmetricKey(99)); err == nil {
		t.Fatal("expected ResolveECDHCurve() error")
	}
	if name, err := CurveNameFromECDH(ecdh.P521()); err != nil || name != common.CurveP521.String() {
		t.Fatalf("CurveNameFromECDH() = %q, %v", name, err)
	}

	derivedKey, err := DeriveECCAESKey([]byte("shared-secret"), common.CurveP256.String())
	if err != nil {
		t.Fatalf("DeriveECCAESKey() error = %v", err)
	}
	if len(derivedKey) != 32 {
		t.Fatalf("DeriveECCAESKey() length = %d, want 32", len(derivedKey))
	}

	payload := ECCCipherPayload{
		Curve:              common.CurveP256.String(),
		EphemeralPublicKey: "ephemeral",
		Ciphertext:         "ciphertext",
	}
	encoded, err := EncodeECCCipherPayload(payload)
	if err != nil {
		t.Fatalf("EncodeECCCipherPayload() error = %v", err)
	}
	decoded, err := DecodeECCCipherPayload(encoded)
	if err != nil {
		t.Fatalf("DecodeECCCipherPayload() error = %v", err)
	}
	if *decoded != payload {
		t.Fatalf("DecodeECCCipherPayload() = %#v, want %#v", decoded, payload)
	}
	if _, err := DecodeECCCipherPayload(base64.StdEncoding.EncodeToString([]byte("{}"))); err == nil {
		t.Fatal("expected DecodeECCCipherPayload() error")
	}
}

func writePEMFile(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	block := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	return path
}
