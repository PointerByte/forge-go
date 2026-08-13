// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"bytes"
	mathrand "math/rand"
	"os"
	"testing"
	"time"
)

var (
	benchmarkCertificateResult Result
	benchmarkPEMBytes          int
	benchmarkEncryptedPEM      []byte
)

func BenchmarkGeneratorGenerateEd25519(b *testing.B) {
	writtenBytes := 0
	generator := &Generator{
		mkdirAllFn: func(string, os.FileMode) error {
			return nil
		},
		writeFilesFn: func(updates []pemFileUpdate) error {
			for _, update := range updates {
				writtenBytes += len(update.content)
			}
			return nil
		},
		nowFn: func() time.Time {
			return time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
		},
		// The generated material is discarded. A seeded reader keeps benchmark
		// work reproducible and must never be used by production code.
		randReader: mathrand.New(mathrand.NewSource(1)), // #nosec G404 -- deterministic benchmark input
	}
	options := Options{
		Algorithm:         algorithmEd25519,
		OutputDir:         "benchmark-output",
		CommonName:        "benchmark.example.invalid",
		DNSNames:          []string{"benchmark.example.invalid"},
		Organization:      "GoForge Benchmark",
		ValidForDays:      30,
		CertFileName:      "cert.pem",
		KeyFileName:       "key.pem",
		PublicKeyFileName: "public.pem",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := generator.Generate(options)
		if err != nil {
			b.Fatalf("Generate() error = %v", err)
		}
		benchmarkCertificateResult = result
	}
	benchmarkPEMBytes = writtenBytes
}

func BenchmarkEncryptPEMArgon2id(b *testing.B) {
	content := bytes.Repeat([]byte("benchmark PEM content\n"), 64)
	randomness := make([]byte, encryptedPEMSaltBytes+12)
	secret := "benchmark-only-secret-1234567890"

	b.ReportAllocs()
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := encryptPEM(
			content,
			secret,
			encryptedKindPrivateKey,
			bytes.NewReader(randomness),
		)
		if err != nil {
			b.Fatalf("encryptPEM() error = %v", err)
		}
		benchmarkEncryptedPEM = encrypted
	}
}
