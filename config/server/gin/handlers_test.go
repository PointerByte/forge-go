// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package gin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNotFound(t *testing.T) {
	router := gin.New()
	router.NoRoute(notFound())

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/missing", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if body["message"] != "Path not found" {
		t.Fatalf("unexpected message: %q", body["message"])
	}
}

func TestNoMethod(t *testing.T) {
	router := gin.New()
	router.HandleMethodNotAllowed = true
	router.NoMethod(noMethod())
	router.GET("/resource", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/resource", nil))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if body["message"] != "Method not allowed" {
		t.Fatalf("unexpected message: %q", body["message"])
	}
}
