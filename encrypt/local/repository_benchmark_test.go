// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"context"
	"strings"
	"testing"
)

var benchmarkDigest string

func BenchmarkHashRepository(b *testing.B) {
	repository := NewHashRepository()
	ctx := context.Background()
	message := strings.Repeat("GoForgeBenchData", 64)

	b.Run("SHA256_1KiB", func(b *testing.B) {
		b.SetBytes(int64(len(message)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchmarkDigest = repository.Sha256Hex(ctx, message)
		}
	})

	b.Run("BLAKE3_1KiB", func(b *testing.B) {
		b.SetBytes(int64(len(message)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchmarkDigest = repository.Blake3(ctx, message)
		}
	})
}
