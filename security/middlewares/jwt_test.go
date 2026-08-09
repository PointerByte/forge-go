// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package middlewares

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	jwtservice "github.com/PointerByte/forge-go/security/auth/jwt"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

type jwtClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

func TestRequireJWTAllowsRequestWithValidBearerToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	configureMiddlewareJWT()
	defer viper.Reset()

	validator := jwtservice.Validator(func(ctx context.Context, token jwtservice.Token) error {
		var claims jwtClaims
		if err := json.Unmarshal(token.Claims, &claims); err != nil {
			return err
		}
		if claims.Role != "admin" {
			return errors.New("role not allowed")
		}
		return nil
	})
	service, err := jwtservice.NewConfiguredService(&validator)
	if err != nil {
		t.Fatalf("expected jwt service without error, got %v", err)
	}

	token, err := service.Create(jwtClaims{UserID: "42", Role: "admin"})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	router := gin.New()
	nextCalled := false
	router.Use(RequireJWT(
		WithJWTClaimsFactory(func() any { return &jwtClaims{} }),
		WithJWTValidator(func(ctx context.Context, token jwtservice.Token) error {
			var claims jwtClaims
			if err := json.Unmarshal(token.Claims, &claims); err != nil {
				return err
			}
			if claims.Role != "admin" {
				return errors.New("role not allowed")
			}
			return nil
		}),
	))
	router.GET("/private", func(c *gin.Context) {
		nextCalled = true

		claimsValue, exists := c.Get(JWTClaimsContextKey.String())
		if !exists {
			t.Fatal("expected claims in context")
		}

		claims, ok := claimsValue.(*jwtClaims)
		if !ok {
			t.Fatalf("expected *jwtClaims in context, got %T", claimsValue)
		}

		if claims.UserID != "42" {
			t.Fatalf("expected user id 42, got %s", claims.UserID)
		}

		if _, exists := c.Get(JWTTokenContextKey.String()); !exists {
			t.Fatal("expected parsed token in context")
		}

		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected middleware to continue the handler chain")
	}

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, rec.Code)
	}
}

func TestRequireJWTRejectsMissingAuthorizationHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	configureMiddlewareJWT()
	defer viper.Reset()

	router := gin.New()
	handlerCalled := false
	router.Use(RequireJWT())
	router.GET("/private", func(c *gin.Context) {
		handlerCalled = true
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if handlerCalled {
		t.Fatal("expected middleware to abort the handler chain")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestRequireJWTRejectsInvalidSignature(t *testing.T) {
	gin.SetMode(gin.TestMode)
	configureMiddlewareJWT()
	defer viper.Reset()

	service, err := jwtservice.NewConfiguredService(nil)
	if err != nil {
		t.Fatalf("expected jwt service without error, got %v", err)
	}

	token, err := service.Create(jwtClaims{UserID: "42", Role: "admin"})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	parts := strings.Split(token, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"42","role":"guest"}`)) + "." + parts[2]

	router := gin.New()
	handlerCalled := false
	router.Use(RequireJWT())
	router.GET("/private", func(c *gin.Context) {
		handlerCalled = true
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set("Authorization", "Bearer "+tampered)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if handlerCalled {
		t.Fatal("expected middleware to abort the handler chain")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestRequireJWTWithDefaultClaimsMapAndCustomContextKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	configureMiddlewareJWT()
	defer viper.Reset()

	service, err := jwtservice.NewConfiguredService(nil)
	if err != nil {
		t.Fatalf("expected jwt service without error, got %v", err)
	}

	token, err := service.Create(jwtClaims{UserID: "42", Role: "admin"})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	router := gin.New()
	router.Use(RequireJWT(WithJWTContextKeys(GinContextKey("tokenKey"), GinContextKey("claimsKey"))))
	router.GET("/private", func(c *gin.Context) {
		claimsValue, exists := c.Get(GinContextKey("claimsKey").String())
		if !exists {
			t.Fatal("expected claims under custom key")
		}

		claimsMap, ok := claimsValue.(map[string]any)
		if !ok {
			t.Fatalf("expected map claims, got %T", claimsValue)
		}

		if claimsMap["user_id"] != "42" {
			t.Fatalf("expected user_id 42, got %v", claimsMap["user_id"])
		}

		if _, exists := c.Get(GinContextKey("tokenKey").String()); !exists {
			t.Fatal("expected token under custom key")
		}

		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, rec.Code)
	}
}

func TestRequireJWTRejectsInvalidServiceConfiguration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	viper.Reset()
	defer viper.Reset()
	viper.Set(jwtservice.DefaultAlgorithmKey, "HS256")

	router := gin.New()
	var captured error

	router.Use(RequireJWT(WithJWTUnauthorizedHandler(func(c *gin.Context, err error) {
		captured = err
		c.AbortWithStatus(http.StatusTeapot)
	})))
	router.GET("/private", func(c *gin.Context) {
		t.Fatal("handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if !errors.Is(captured, jwtservice.ErrMissingSecret) {
		t.Fatalf("expected ErrMissingSecret, got %v", captured)
	}

	if rec.Code != http.StatusTeapot {
		t.Fatalf("expected status %d, got %d", http.StatusTeapot, rec.Code)
	}
}

func TestRequireJWTCanBeExplicitlyDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	original := viper.Get("jwt.enable")
	wasSet := viper.IsSet("jwt.enable")
	viper.Set("jwt.enable", false)
	defer func() {
		if wasSet {
			viper.Set("jwt.enable", original)
			return
		}
		viper.Reset()
	}()

	router := gin.New()
	handlerCalled := false
	router.Use(RequireJWT())
	router.GET("/private", func(c *gin.Context) {
		handlerCalled = true
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if !handlerCalled {
		t.Fatal("expected middleware to skip validation when explicitly disabled")
	}

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, rec.Code)
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		prefix    string
		wantToken string
		wantErr   error
	}{
		{name: "missing", header: "", prefix: "Bearer ", wantErr: ErrMissingAuthorization},
		{name: "wrong prefix", header: "Basic abc", prefix: "Bearer ", wantErr: ErrInvalidAuthorizationType},
		{name: "empty token", header: "Bearer   ", prefix: "Bearer ", wantErr: ErrMissingAuthorization},
		{name: "success", header: "Bearer abc.def.ghi", prefix: "Bearer ", wantToken: "abc.def.ghi"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, err := extractBearerToken(test.header, test.prefix)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("expected error %v, got %v", test.wantErr, err)
			}

			if token != test.wantToken {
				t.Fatalf("expected token %q, got %q", test.wantToken, token)
			}
		})
	}
}

func TestJWTMiddlewareOptionNilHandlersDoNotOverrideDefaults(t *testing.T) {
	config := jwtMiddlewareConfig{
		tokenContextKey:     JWTTokenContextKey,
		claimsContextKey:    JWTClaimsContextKey,
		unauthorizedHandler: func(*gin.Context, error) {},
	}

	WithJWTClaimsFactory(nil)(&config)
	if config.claimsFactory != nil {
		t.Fatal("expected nil claims factory to remain nil")
	}

	WithJWTContextKeys(GinContextKey(""), GinContextKey(""))(&config)
	if config.tokenContextKey != JWTTokenContextKey || config.claimsContextKey != JWTClaimsContextKey {
		t.Fatal("expected default keys to remain unchanged")
	}

	currentHandler := config.unauthorizedHandler
	WithJWTUnauthorizedHandler(nil)(&config)
	if fmt.Sprintf("%p", currentHandler) != fmt.Sprintf("%p", config.unauthorizedHandler) {
		t.Fatal("expected unauthorized handler to remain unchanged")
	}

	service := &jwtservice.Service{}
	WithJWTService(service)(&config)
	if config.service != service {
		t.Fatal("expected service to be updated")
	}

	WithJWTService(nil)(&config)
	if config.service != service {
		t.Fatal("expected nil service not to override existing service")
	}
}

func configureMiddlewareJWT() {
	viper.Reset()
	viper.Set(jwtservice.DefaultAlgorithmKey, "HS256")
	viper.Set(jwtservice.DefaultHMACSecretKey, "middleware-secret")
}
