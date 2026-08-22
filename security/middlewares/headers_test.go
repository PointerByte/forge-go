// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	nextCalled := false

	router.Use(SecurityHeaders())
	router.GET("/health", func(c *gin.Context) {
		nextCalled = true
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected middleware to continue the handler chain")
	}

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, rec.Code)
	}

	tests := map[string]string{
		"X-Frame-Options":           "DENY",
		"Content-Security-Policy":   "default-src 'self'; connect-src *; font-src *; script-src-elem * 'unsafe-inline'; img-src * data:; style-src * 'unsafe-inline';",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Referrer-Policy":           "strict-origin",
		"X-Content-Type-Options":    "nosniff",
		"Permissions-Policy":        "geolocation=(),midi=(),sync-xhr=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()",
	}

	for header, want := range tests {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("header %q: expected %q, got %q", header, want, got)
		}
	}
}
