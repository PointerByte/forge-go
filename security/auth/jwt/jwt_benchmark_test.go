// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"testing"
)

type benchmarkClaims struct {
	Subject string   `json:"sub"`
	Roles   []string `json:"roles"`
	Active  bool     `json:"active"`
}

var (
	benchmarkJWTToken  string
	benchmarkJWTClaims benchmarkClaims
)

func BenchmarkJWTService(b *testing.B) {
	sign := func(_ context.Context, signingInput []byte) ([]byte, error) {
		digest := sha256.Sum256(signingInput)
		return digest[:], nil
	}
	verify := func(_ context.Context, signingInput []byte, signature []byte) error {
		digest := sha256.Sum256(signingInput)
		if subtle.ConstantTimeCompare(signature, digest[:]) != 1 {
			return ErrInvalidSignature
		}
		return nil
	}

	service, err := New(WithCustomStrategy("BENCH-SHA256", sign, verify))
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}
	claims := benchmarkClaims{
		Subject: "benchmark-user",
		Roles:   []string{"reader", "writer"},
		Active:  true,
	}
	token, err := service.Create(claims)
	if err != nil {
		b.Fatalf("Create() setup error = %v", err)
	}

	b.Run("Create", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchmarkJWTToken, err = service.Create(claims)
			if err != nil {
				b.Fatalf("Create() error = %v", err)
			}
		}
	})

	b.Run("Decode", func(b *testing.B) {
		ctx := context.Background()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var decoded benchmarkClaims
			if _, err := service.Decode(ctx, token, &decoded); err != nil {
				b.Fatalf("Decode() error = %v", err)
			}
			benchmarkJWTClaims = decoded
		}
	})
}
