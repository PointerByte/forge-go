// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testEncryptionSecret    = "12345678901234567890123456789012"
	testEncryptionSecretNew = "abcdefghijklmnopqrstuvwxyz123456"
)

func TestGenerateCertificatesByAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		curve     string
		assertKey func(t *testing.T, privateKey any)
	}{
		{
			name:      "rsa",
			algorithm: algorithmRSA,
			assertKey: func(t *testing.T, privateKey any) {
				t.Helper()
				if _, ok := privateKey.(*rsa.PrivateKey); !ok {
					t.Fatalf("expected rsa private key, got %T", privateKey)
				}
			},
		},
		{
			name:      "ecc",
			algorithm: algorithmECC,
			curve:     curveP384,
			assertKey: func(t *testing.T, privateKey any) {
				t.Helper()
				key, ok := privateKey.(*ecdsa.PrivateKey)
				if !ok {
					t.Fatalf("expected ecdsa private key, got %T", privateKey)
				}
				if key.Curve.Params().Name != "P-384" {
					t.Fatalf("expected P-384 curve, got %s", key.Curve.Params().Name)
				}
			},
		},
		{
			name:      "ed25519",
			algorithm: algorithmEd25519,
			assertKey: func(t *testing.T, privateKey any) {
				t.Helper()
				if _, ok := privateKey.(ed25519.PrivateKey); !ok {
					t.Fatalf("expected ed25519 private key, got %T", privateKey)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outputDir := filepath.Join(t.TempDir(), test.name)
			result, err := GenerateCertificates(Options{
				Algorithm:    test.algorithm,
				ECCCurve:     test.curve,
				OutputDir:    outputDir,
				CommonName:   "localhost",
				ValidForDays: 10,
				Salt:         "salt-value",
			})
			if err != nil {
				t.Fatalf("GenerateCertificates returned error: %v", err)
			}

			certificate := parseCertificateFile(t, result.CertificatePath)
			if certificate.Subject.CommonName != "localhost" {
				t.Fatalf("expected common name localhost, got %q", certificate.Subject.CommonName)
			}

			privateKey := parsePrivateKeyFile(t, result.PrivateKeyPath)
			test.assertKey(t, privateKey)

			if _, err := os.Stat(result.PublicKeyPath); err != nil {
				t.Fatalf("expected public key file to exist, got %v", err)
			}
		})
	}
}

func TestGenerateCertificatesSignedByCA(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "certs")
	caResult, err := GenerateCertificates(Options{
		Algorithm:         algorithmECC,
		ECCCurve:          curveP521,
		OutputDir:         outputDir,
		CommonName:        "dragon-cmk-ca.chest-max.svc.cluster.local",
		Organization:      "PointerByte",
		ValidForDays:      365,
		IsCA:              true,
		CertFileName:      "ca.pem",
		KeyFileName:       "ca-key.pem",
		PublicKeyFileName: "ca-public.pem",
	})
	if err != nil {
		t.Fatalf("GenerateCertificates CA returned error: %v", err)
	}

	result, err := GenerateCertificates(Options{
		Algorithm:         algorithmECC,
		ECCCurve:          curveP521,
		OutputDir:         outputDir,
		CommonName:        "dragon-cmk.chest-max.svc.cluster.local",
		DNSNames:          []string{"dragon-cmk.chest-max.svc.cluster.local"},
		Organization:      "PointerByte",
		ValidForDays:      365,
		CertFileName:      "cert.pem",
		KeyFileName:       "key.pem",
		PublicKeyFileName: "public.pem",
		SignedBy:          caResult.CertificatePath,
		CAKeyFile:         caResult.PrivateKeyPath,
	})
	if err != nil {
		t.Fatalf("GenerateCertificates signed certificate returned error: %v", err)
	}

	caCertificate := parseCertificateFile(t, caResult.CertificatePath)
	certificate := parseCertificateFile(t, result.CertificatePath)
	if !caCertificate.IsCA {
		t.Fatal("expected generated CA certificate to be marked as CA")
	}
	if certificate.Issuer.CommonName != caCertificate.Subject.CommonName {
		t.Fatalf("expected issuer %q, got %q", caCertificate.Subject.CommonName, certificate.Issuer.CommonName)
	}
	if err := certificate.CheckSignatureFrom(caCertificate); err != nil {
		t.Fatalf("expected certificate to verify against generated CA, got %v", err)
	}

	if _, err := os.Stat(result.PrivateKeyPath); err != nil {
		t.Fatalf("expected private key file to exist, got %v", err)
	}
	if _, err := os.Stat(result.PublicKeyPath); err != nil {
		t.Fatalf("expected public key file to exist, got %v", err)
	}
}

func TestGenerateEncryptedCertificates(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "certs")
	result, err := GenerateCertificates(Options{
		Algorithm:     algorithmRSA,
		OutputDir:     outputDir,
		CommonName:    "localhost",
		ValidForDays:  10,
		EncryptSecret: testEncryptionSecret,
	})
	if err != nil {
		t.Fatalf("GenerateCertificates encrypted returned error: %v", err)
	}
	if !result.Encrypted {
		t.Fatal("expected encrypted result")
	}

	rawContent, err := os.ReadFile(result.CertificatePath)
	if err != nil {
		t.Fatalf("expected encrypted certificate file, got %v", err)
	}
	block, _ := pem.Decode(rawContent)
	if block == nil || block.Type != encryptedPEMBlockType {
		t.Fatalf("expected encrypted PEM block, got %#v", block)
	}
	var payload encryptedPEMPayload
	if err := json.Unmarshal(block.Bytes, &payload); err != nil {
		t.Fatalf("expected encrypted payload JSON, got %v", err)
	}
	if payload.Version != encryptedPEMVersion || payload.KDF != encryptedPEMKDF {
		t.Fatalf("expected current encrypted PEM format, got %#v", payload)
	}

	certificatePEM, err := ReadPEMFile(result.CertificatePath, testEncryptionSecret)
	if err != nil {
		t.Fatalf("ReadPEMFile certificate returned error: %v", err)
	}
	certificate := parseCertificateContent(t, certificatePEM)
	if certificate.Subject.CommonName != "localhost" {
		t.Fatalf("expected common name localhost, got %q", certificate.Subject.CommonName)
	}
	if certificate, err := ReadCertificateFile(result.CertificatePath, testEncryptionSecret); err != nil || certificate.Subject.CommonName != "localhost" {
		t.Fatalf("expected ReadCertificateFile to return localhost certificate, cert=%v err=%v", certificate, err)
	}

	privateKeyPEM, err := ReadPEMFile(result.PrivateKeyPath, testEncryptionSecret)
	if err != nil {
		t.Fatalf("ReadPEMFile private key returned error: %v", err)
	}
	if _, ok := parsePrivateKeyContent(t, privateKeyPEM).(*rsa.PrivateKey); !ok {
		t.Fatal("expected decrypted RSA private key")
	}
	if _, err := ReadPrivateKeyFile(result.PrivateKeyPath, testEncryptionSecret); err != nil {
		t.Fatalf("ReadPrivateKeyFile returned error: %v", err)
	}
	if _, err := ReadPublicKeyFile(result.PublicKeyPath, testEncryptionSecret); err != nil {
		t.Fatalf("ReadPublicKeyFile returned error: %v", err)
	}

	if _, err := ReadPEMFile(result.CertificatePath, "short"); err == nil {
		t.Fatal("expected short secret error")
	}
	if _, err := ReadPEMFile(result.CertificatePath, strings.Repeat("x", 32)); err == nil {
		t.Fatal("expected wrong secret error")
	}
}

func TestUpdateEncryptionSecret(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "certs")
	result, err := GenerateCertificates(Options{
		Algorithm:     algorithmRSA,
		OutputDir:     outputDir,
		CommonName:    "localhost",
		ValidForDays:  10,
		EncryptSecret: testEncryptionSecret,
	})
	if err != nil {
		t.Fatalf("GenerateCertificates encrypted returned error: %v", err)
	}

	updateResult, err := UpdateEncryptionSecret(UpdateEncryptionSecretOptions{
		CertificatePath:  result.CertificatePath,
		PrivateKeyPath:   result.PrivateKeyPath,
		PublicKeyPath:    result.PublicKeyPath,
		EncryptSecretOld: testEncryptionSecret,
		EncryptSecretNew: testEncryptionSecretNew,
	})
	if err != nil {
		t.Fatalf("UpdateEncryptionSecret returned error: %v", err)
	}
	if updateResult.CertificatePath != result.CertificatePath ||
		updateResult.PrivateKeyPath != result.PrivateKeyPath ||
		updateResult.PublicKeyPath != result.PublicKeyPath {
		t.Fatalf("unexpected update result: %#v", updateResult)
	}

	if _, err := ReadPEMFile(result.CertificatePath, testEncryptionSecret); err == nil {
		t.Fatal("expected old secret to fail after update")
	}

	certificate, err := ReadCertificateFile(result.CertificatePath, testEncryptionSecretNew)
	if err != nil {
		t.Fatalf("ReadCertificateFile with new secret returned error: %v", err)
	}
	if certificate.Subject.CommonName != "localhost" {
		t.Fatalf("expected common name localhost, got %q", certificate.Subject.CommonName)
	}
	if _, err := ReadPrivateKeyFile(result.PrivateKeyPath, testEncryptionSecretNew); err != nil {
		t.Fatalf("ReadPrivateKeyFile with new secret returned error: %v", err)
	}
	if _, err := ReadPublicKeyFile(result.PublicKeyPath, testEncryptionSecretNew); err != nil {
		t.Fatalf("ReadPublicKeyFile with new secret returned error: %v", err)
	}
}

func TestGenerateCertificatesSignedByEncryptedCA(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "certs")
	caResult, err := GenerateCertificates(Options{
		Algorithm:         algorithmECC,
		ECCCurve:          curveP384,
		OutputDir:         outputDir,
		CommonName:        "encrypted-ca.local",
		ValidForDays:      365,
		IsCA:              true,
		CertFileName:      "ca.pem",
		KeyFileName:       "ca-key.pem",
		PublicKeyFileName: "ca-public.pem",
		EncryptSecret:     testEncryptionSecret,
	})
	if err != nil {
		t.Fatalf("GenerateCertificates encrypted CA returned error: %v", err)
	}

	result, err := GenerateCertificates(Options{
		Algorithm:         algorithmECC,
		ECCCurve:          curveP384,
		OutputDir:         outputDir,
		CommonName:        "service.local",
		ValidForDays:      365,
		CertFileName:      "cert.pem",
		KeyFileName:       "key.pem",
		PublicKeyFileName: "public.pem",
		SignedBy:          caResult.CertificatePath,
		CAKeyFile:         caResult.PrivateKeyPath,
		SignedBySecret:    testEncryptionSecret,
		CAKeySecret:       testEncryptionSecret,
	})
	if err != nil {
		t.Fatalf("GenerateCertificates signed by encrypted CA returned error: %v", err)
	}

	caPEM, err := ReadPEMFile(caResult.CertificatePath, testEncryptionSecret)
	if err != nil {
		t.Fatalf("ReadPEMFile CA returned error: %v", err)
	}
	caCertificate := parseCertificateContent(t, caPEM)
	certificate := parseCertificateFile(t, result.CertificatePath)
	if err := certificate.CheckSignatureFrom(caCertificate); err != nil {
		t.Fatalf("expected certificate to verify against encrypted CA, got %v", err)
	}
}

func TestGenerateCertificatesErrors(t *testing.T) {
	if _, err := GenerateCertificates(Options{Algorithm: "dsa", OutputDir: t.TempDir(), CommonName: "localhost"}); err == nil {
		t.Fatal("expected unsupported algorithm error")
	}

	if _, err := GenerateCertificates(Options{
		Algorithm:  algorithmECC,
		ECCCurve:   "p111",
		OutputDir:  t.TempDir(),
		CommonName: "localhost",
	}); err == nil {
		t.Fatal("expected unsupported ecc curve error")
	}

	if _, err := GenerateCertificates(Options{
		Algorithm:  algorithmRSA,
		RSAKeySize: 1024,
		OutputDir:  t.TempDir(),
		CommonName: "localhost",
	}); err == nil {
		t.Fatal("expected rsa key size error")
	}

	if _, err := GenerateCertificates(Options{
		OutputDir:  t.TempDir(),
		CommonName: "localhost",
		SignedBy:   "ca.pem",
	}); err == nil {
		t.Fatal("expected signed-by without ca-key error")
	}

	if _, err := GenerateCertificates(Options{
		OutputDir:     t.TempDir(),
		CommonName:    "localhost",
		EncryptSecret: "short",
	}); err == nil {
		t.Fatal("expected short encryption secret error")
	}

	if _, err := GenerateCertificates(Options{
		OutputDir:         t.TempDir(),
		CommonName:        "localhost",
		CertFileName:      "same.pem",
		KeyFileName:       "same.pem",
		PublicKeyFileName: "public.pem",
	}); err == nil {
		t.Fatal("expected duplicate output path error")
	}

	if _, err := UpdateEncryptionSecret(UpdateEncryptionSecretOptions{
		CertificatePath:  "cert.pem",
		PrivateKeyPath:   "key.pem",
		PublicKeyPath:    "public.pem",
		EncryptSecretOld: testEncryptionSecret,
		EncryptSecretNew: testEncryptionSecret,
	}); err == nil {
		t.Fatal("expected same encryption secret error")
	}

	if _, err := UpdateEncryptionSecret(UpdateEncryptionSecretOptions{
		CertificatePath:  "cert.pem",
		PrivateKeyPath:   "key.pem",
		PublicKeyPath:    "public.pem",
		EncryptSecretOld: "",
		EncryptSecretNew: testEncryptionSecretNew,
	}); err == nil {
		t.Fatal("expected missing old encryption secret error")
	}
}

func TestReadPrivateKeyPEMFileSupportsLegacyFormats(t *testing.T) {
	tempDir := t.TempDir()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("expected rsa key without error, got %v", err)
	}
	rsaPath := writePEMFile(t, tempDir, "rsa-key.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey))
	gotRSAKey, err := ReadPrivateKeyFile(rsaPath, "")
	if err != nil {
		t.Fatalf("expected PKCS#1 rsa key without error, got %v", err)
	}
	if _, ok := gotRSAKey.(*rsa.PrivateKey); !ok {
		t.Fatalf("expected rsa private key, got %T", gotRSAKey)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("expected ecdsa key without error, got %v", err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("expected ecdsa key marshal without error, got %v", err)
	}
	ecPath := writePEMFile(t, tempDir, "ec-key.pem", "EC PRIVATE KEY", ecDER)
	gotECKey, err := ReadPrivateKeyFile(ecPath, "")
	if err != nil {
		t.Fatalf("expected EC private key without error, got %v", err)
	}
	if _, ok := gotECKey.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected ecdsa private key, got %T", gotECKey)
	}
}

func TestPEMReadAndDecryptErrors(t *testing.T) {
	tempDir := t.TempDir()
	noPEMPath := filepath.Join(tempDir, "not-pem.txt")
	if err := os.WriteFile(noPEMPath, []byte("not pem"), 0o600); err != nil {
		t.Fatalf("expected write without error, got %v", err)
	}

	if _, err := ReadCertificateFile(noPEMPath, ""); err == nil || !strings.Contains(err.Error(), "decode certificate PEM") {
		t.Fatalf("expected certificate PEM decode error, got %v", err)
	}
	if _, err := ReadPrivateKeyFile(noPEMPath, ""); err == nil || !strings.Contains(err.Error(), "decode private key PEM") {
		t.Fatalf("expected private key PEM decode error, got %v", err)
	}
	if _, err := ReadPublicKeyFile(noPEMPath, ""); err == nil || !strings.Contains(err.Error(), "decode public key PEM") {
		t.Fatalf("expected public key PEM decode error, got %v", err)
	}

	badPublicPath := writePEMFile(t, tempDir, "bad-public.pem", "PUBLIC KEY", []byte("not der"))
	if _, err := ReadPublicKeyFile(badPublicPath, ""); err == nil || !strings.Contains(err.Error(), "parse public key") {
		t.Fatalf("expected public key parse error, got %v", err)
	}

	plain, err := DecryptPEM([]byte("not pem"), "")
	if err != nil {
		t.Fatalf("expected plain content without error, got %v", err)
	}
	if string(plain) != "not pem" {
		t.Fatalf("expected plain content back, got %q", plain)
	}

	tests := []struct {
		name    string
		content []byte
		want    string
	}{
		{
			name:    "invalid json",
			content: encryptedTestPEM(t, encryptedKindCertificate, []byte("{")),
			want:    "decode encrypted PEM payload",
		},
		{
			name: "unsupported version",
			content: encryptedPayloadPEM(t, encryptedKindCertificate, encryptedPEMPayload{
				Version:    encryptedPEMVersion + 1,
				Algorithm:  encryptedPEMAlgorithm,
				Nonce:      base64.StdEncoding.EncodeToString(make([]byte, 12)),
				Ciphertext: base64.StdEncoding.EncodeToString([]byte("cipher")),
			}),
			want: "unsupported encrypted PEM version",
		},
		{
			name: "unsupported algorithm",
			content: encryptedPayloadPEM(t, encryptedKindCertificate, encryptedPEMPayload{
				Version:    encryptedPEMVersion,
				Algorithm:  "AES-128-GCM",
				Nonce:      base64.StdEncoding.EncodeToString(make([]byte, 12)),
				Ciphertext: base64.StdEncoding.EncodeToString([]byte("cipher")),
			}),
			want: "unsupported encrypted PEM algorithm",
		},
		{
			name: "invalid nonce",
			content: encryptedPayloadPEM(t, encryptedKindCertificate, encryptedPEMPayload{
				Version:    legacyEncryptedPEMVersion,
				Algorithm:  encryptedPEMAlgorithm,
				Nonce:      "%%%",
				Ciphertext: base64.StdEncoding.EncodeToString([]byte("cipher")),
			}),
			want: "decode encrypted PEM nonce",
		},
		{
			name: "invalid ciphertext",
			content: encryptedPayloadPEM(t, encryptedKindCertificate, encryptedPEMPayload{
				Version:    legacyEncryptedPEMVersion,
				Algorithm:  encryptedPEMAlgorithm,
				Nonce:      base64.StdEncoding.EncodeToString(make([]byte, 12)),
				Ciphertext: "%%%",
			}),
			want: "decode encrypted PEM ciphertext",
		},
		{
			name: "invalid nonce size",
			content: encryptedPayloadPEM(t, encryptedKindCertificate, encryptedPEMPayload{
				Version:    legacyEncryptedPEMVersion,
				Algorithm:  encryptedPEMAlgorithm,
				Nonce:      base64.StdEncoding.EncodeToString([]byte("short")),
				Ciphertext: base64.StdEncoding.EncodeToString([]byte("cipher")),
			}),
			want: "invalid encrypted PEM nonce size",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecryptPEM(test.content, testEncryptionSecret)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q error, got %v", test.want, err)
			}
		})
	}

	if err := requireEncryptedPEM([]byte("not pem"), encryptedKindCertificate); err == nil || !strings.Contains(err.Error(), "no PEM data") {
		t.Fatalf("expected no PEM data error, got %v", err)
	}
	plainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("cert")})
	if err := requireEncryptedPEM(plainPEM, encryptedKindCertificate); err == nil || !strings.Contains(err.Error(), "not encrypted") {
		t.Fatalf("expected not encrypted error, got %v", err)
	}
	if err := requireEncryptedPEM(encryptedTestPEM(t, encryptedKindPrivateKey, []byte("{}")), encryptedKindCertificate); err == nil || !strings.Contains(err.Error(), "want") {
		t.Fatalf("expected encrypted kind error, got %v", err)
	}
}

func TestParseIPAddresses(t *testing.T) {
	got := parseIPAddresses([]string{" 127.0.0.1 ", "not-ip", "::1"})
	if len(got) != 2 {
		t.Fatalf("expected two parsed IPs, got %v", got)
	}
	if got[0].String() != "127.0.0.1" || got[1].String() != "::1" {
		t.Fatalf("unexpected parsed IPs: %v", got)
	}
}

func parseCertificateFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected certificate file, got %v", err)
	}

	block, _ := pem.Decode(content)
	return parseCertificateBlock(t, block)
}

func parseCertificateContent(t *testing.T, content []byte) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode(content)
	return parseCertificateBlock(t, block)
}

func parseCertificateBlock(t *testing.T, block *pem.Block) *x509.Certificate {
	t.Helper()

	if block == nil {
		t.Fatal("expected certificate PEM block")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("expected certificate parsing without error, got %v", err)
	}
	return certificate
}

func parsePrivateKeyFile(t *testing.T, path string) any {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected private key file, got %v", err)
	}

	block, _ := pem.Decode(content)
	return parsePrivateKeyBlock(t, block)
}

func parsePrivateKeyContent(t *testing.T, content []byte) any {
	t.Helper()

	block, _ := pem.Decode(content)
	return parsePrivateKeyBlock(t, block)
}

func parsePrivateKeyBlock(t *testing.T, block *pem.Block) any {
	t.Helper()

	if block == nil {
		t.Fatal("expected private key PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("expected private key parsing without error, got %v", err)
	}
	return privateKey
}

func writePEMFile(t *testing.T, dir string, name string, blockType string, der []byte) string {
	t.Helper()

	path := filepath.Join(dir, name)
	content := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("expected write PEM file without error, got %v", err)
	}
	return path
}

func encryptedPayloadPEM(t *testing.T, kind string, payload encryptedPEMPayload) []byte {
	t.Helper()

	content, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("expected encrypted payload marshal without error, got %v", err)
	}
	return encryptedTestPEM(t, kind, content)
}

func encryptedTestPEM(t *testing.T, kind string, content []byte) []byte {
	t.Helper()

	return pem.EncodeToMemory(&pem.Block{
		Type:    encryptedPEMBlockType,
		Headers: map[string]string{"Kind": kind},
		Bytes:   content,
	})
}
