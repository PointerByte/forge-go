// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package sanitizer

import (
	"net/http"
	"testing"

	"github.com/PointerByte/forge-go/logger/formatter"
)

var benchmarkSanitizedLog formatter.LogFormat

func BenchmarkSanitizerLogFormat(b *testing.B) {
	sanitizer := New([]string{"authorization", "password", "email"})
	log := formatter.LogFormat{
		Message: "request completed",
		Details: formatter.Details{
			System:   "benchmark-api",
			Client:   "benchmark-client",
			Protocol: "HTTP/2",
			Method:   http.MethodPost,
			Path:     "/sessions",
			Headers: http.Header{
				"Authorization": {"benchmark-value"},
				"Content-Type":  {"application/json"},
			},
			Request: map[string]any{
				"email":    "benchmark@example.invalid",
				"password": "benchmark-value",
				"profile": map[string]any{
					"display_name": "Benchmark User",
					"enabled":      true,
				},
			},
			Response: `{"status":"accepted","email":"benchmark@example.invalid"}`,
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkSanitizedLog = sanitizer.LogFormat(log)
	}
}
