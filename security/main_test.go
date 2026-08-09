// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	jwtservice "github.com/PointerByte/forge-go/security/auth/jwt"
	"github.com/PointerByte/forge-go/security/middlewares"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

func TestNewRouterHealthEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := newTestRouter(t)

	tests := []struct {
		name string
		path string
	}{
		{name: "root health", path: "/health"},
		{name: "hmac health", path: "/hmac/health"},
		{name: "rsa health", path: "/rsa/health"},
		{name: "custom health", path: "/custom/health"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, test.path, nil)
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
			}
		})
	}
}

func TestHMACLoginAndProtectedMe(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := newTestRouter(t)
	token := loginAndGetToken(t, router, "/hmac/login", `{"user_id":"42","role":"admin"}`)

	req := httptest.NewRequest(http.MethodGet, "/hmac/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected json response, got %v", err)
	}

	if body["user_id"] != "42" {
		t.Fatalf("expected user_id 42, got %q", body["user_id"])
	}

	if body["role"] != "admin" {
		t.Fatalf("expected role admin, got %q", body["role"])
	}
}

func TestHMACAdminRejectsNonAdminRole(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := newTestRouter(t)
	token := loginAndGetToken(t, router, "/hmac/login", `{"user_id":"42","role":"reader"}`)

	req := httptest.NewRequest(http.MethodGet, "/hmac/api/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
}

func TestProtectedRouteRejectsBlockedUser(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := newTestRouter(t)
	token := loginAndGetToken(t, router, "/hmac/login", `{"user_id":"blocked-user","role":"admin"}`)

	req := httptest.NewRequest(http.MethodGet, "/hmac/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "user session is blocked") {
		t.Fatalf("expected blocked session error, got %q", rec.Body.String())
	}
}

func TestRSALoginAndProtectedMe(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := newTestRouter(t)
	token := loginAndGetToken(t, router, "/rsa/login", `{"user_id":"84","role":"admin"}`)

	req := httptest.NewRequest(http.MethodGet, "/rsa/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected json response, got %v", err)
	}

	if body["user_id"] != "84" {
		t.Fatalf("expected user_id 84, got %q", body["user_id"])
	}
}

func TestCustomJWTLoginAndProtectedMe(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := newTestRouter(t)
	token := loginAndGetToken(t, router, "/custom/login", `{"user_id":"126","role":"admin"}`)

	req := httptest.NewRequest(http.MethodGet, "/custom/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected json response, got %v", err)
	}

	if body["user_id"] != "126" {
		t.Fatalf("expected user_id 126, got %q", body["user_id"])
	}

	if body["example"] != "Custom / CUSTOM" {
		t.Fatalf("expected custom example, got %q", body["example"])
	}
}

func TestValidateActiveSessionRejectsBlockedUser(t *testing.T) {
	token := jwtservice.Token{
		Claims: json.RawMessage(`{"user_id":"blocked-user","role":"admin"}`),
	}

	err := validateActiveSession(context.Background(), token)
	if err == nil || err.Error() != "user session is blocked" {
		t.Fatalf("expected blocked user error, got %v", err)
	}
}

func TestNewServices(t *testing.T) {
	configureViper()

	if err := ensureDefaultHMACSecret(); err != nil {
		t.Fatalf("expected hmac config without error, got %v", err)
	}

	viper.Set(jwtservice.DefaultAlgorithmKey, "HS256")
	validator := jwtservice.Validator(validateActiveSession)
	hmacService, err := jwtservice.NewConfiguredService(&validator)
	if err != nil {
		t.Fatalf("expected hmac service without error, got %v", err)
	}

	if err := ensureDefaultRSAKeys(); err != nil {
		t.Fatalf("expected rsa config without error, got %v", err)
	}

	viper.Set(jwtservice.DefaultAlgorithmKey, "RS256")
	rsaService, err := jwtservice.NewConfiguredService(&validator)
	if err != nil {
		t.Fatalf("expected rsa service without error, got %v", err)
	}

	if hmacService == nil || rsaService == nil {
		t.Fatal("expected non-nil services")
	}
}

func TestEnsureDefaultRSAKeysReplacesMissingPEMPlaceholders(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	viper.Set(rsaPrivateKeyKey, "./certs/jwt/key.pem")
	viper.Set(rsaPublicKeyKey, "./certs/jwt/public.pem")

	if err := ensureDefaultRSAKeys(); err != nil {
		t.Fatalf("expected rsa config without error, got %v", err)
	}

	if strings.HasSuffix(viper.GetString(rsaPrivateKeyKey), ".pem") {
		t.Fatalf("expected generated private key, got %q", viper.GetString(rsaPrivateKeyKey))
	}
	if strings.HasSuffix(viper.GetString(rsaPublicKeyKey), ".pem") {
		t.Fatalf("expected generated public key, got %q", viper.GetString(rsaPublicKeyKey))
	}

	viper.Set(jwtservice.DefaultAlgorithmKey, "RS256")
	service, err := jwtservice.NewConfiguredService(nil)
	if err != nil {
		t.Fatalf("expected rsa service without error, got %v", err)
	}

	token, err := service.Create(sessionClaims{UserID: "42", Role: "admin"})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}
	if err := service.ValidateSignature(token); err != nil {
		t.Fatalf("expected valid signature, got %v", err)
	}
}

func TestHealthHandlerIncludesExampleWhenPresent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	ctx.Request = req

	healthHandler("demo")(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "demo") {
		t.Fatalf("expected example in response, got %s", rec.Body.String())
	}
}

func TestLoginHandlerErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("invalid payload", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{`))
		req.Header.Set("Content-Type", "application/json")
		ctx.Request = req

		loginHandler(&jwtservice.Service{})(ctx)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
		}
	})

	t.Run("token creation failure", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"user_id":"42","role":"admin"}`))
		req.Header.Set("Content-Type", "application/json")
		ctx.Request = req

		loginHandler(&jwtservice.Service{})(ctx)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
		}
	})
}

func TestMeHandlerAndClaimsFromContextErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	ctx.Request = req

	meHandler("demo")(ctx)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
	}
}

func TestAdminHandlerSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	ctx.Request = req
	ctx.Set(middlewares.JWTClaimsContextKey.String(), &sessionClaims{UserID: "42", Role: "admin"})

	adminHandler("demo")(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestValidateActiveSessionInvalidJSON(t *testing.T) {
	token := jwtservice.Token{
		Claims: json.RawMessage(`{`),
	}

	if err := validateActiveSession(context.Background(), token); err == nil {
		t.Fatal("expected json unmarshal error")
	}
}

func TestRunApp(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		restore := stubAppBootstrap(t)
		defer restore()

		if err := runApp(); err != nil {
			t.Fatalf("expected runApp without error, got %v", err)
		}
	})

	t.Run("run router error", func(t *testing.T) {
		restore := stubAppBootstrap(t)
		defer restore()

		runRouterFn = func(router *gin.Engine) error {
			return errors.New("listen boom")
		}

		err := runApp()
		if err == nil || !strings.Contains(err.Error(), "run gin server") {
			t.Fatalf("expected router startup error, got %v", err)
		}
	})
}

func TestMainCallsFatalOnStartupError(t *testing.T) {
	restore := stubAppBootstrap(t)
	defer restore()

	runRouterFn = func(router *gin.Engine) error {
		return errors.New("boom")
	}

	called := false
	logFatalfFn = func(format string, args ...any) {
		called = true
		panic("fatal called")
	}

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic from fatal stub")
		}
		if !called {
			t.Fatal("expected fatal logger to be called")
		}
	}()

	main()
}

func newTestRouter(t *testing.T) *gin.Engine {
	t.Helper()

	configureViper()

	if err := ensureDefaultHMACSecret(); err != nil {
		t.Fatalf("expected hmac config without error, got %v", err)
	}

	if err := ensureDefaultRSAKeys(); err != nil {
		t.Fatalf("expected rsa config without error, got %v", err)
	}

	return newRouter()
}

func loginAndGetToken(t *testing.T, router *gin.Engine, path string, body string) string {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("expected login response json, got %v", err)
	}

	if response.Token == "" {
		t.Fatal("expected non-empty token")
	}

	return response.Token
}

func stubAppBootstrap(t *testing.T) func() {
	t.Helper()

	originalRunRouterFn := runRouterFn
	originalLogFatalfFn := logFatalfFn

	runRouterFn = func(router *gin.Engine) error {
		return nil
	}
	logFatalfFn = func(format string, args ...any) {}

	return func() {
		runRouterFn = originalRunRouterFn
		logFatalfFn = originalLogFatalfFn
	}
}
