// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package middlewares

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	cookiesauth "github.com/PointerByte/forge-go/security/auth/cookies"
	jwtservice "github.com/PointerByte/forge-go/security/auth/jwt"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

type cookieClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

func TestRequireJWTCookieAllowsRequestWithValidCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	configureMiddlewareJWTCookie()
	defer viper.Reset()

	service, err := jwtservice.NewConfiguredService(nil)
	if err != nil {
		t.Fatalf("expected jwt service without error, got %v", err)
	}

	token, err := service.Create(cookieClaims{UserID: "42", Role: "admin"})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	router := gin.New()
	nextCalled := false
	router.Use(RequireJWTCookie(
		WithJWTCookieClaimsFactory(func() any { return &cookieClaims{} }),
		WithJWTCookieServiceConfig(cookiesauth.ConfigServiceInput{
			CookieNameKey: "COOKIE_MIDDLEWARE_NAME",
			JWT: cookiesauth.JWTConfigServiceInput{
				Algorithm:     "HS256",
				HMACSecretKey: stringPtr("COOKIE_MIDDLEWARE_SECRET"),
				Validator: func(ctx context.Context, token jwtservice.Token) error {
					var claims cookieClaims
					if err := json.Unmarshal(token.Claims, &claims); err != nil {
						return err
					}
					if claims.Role != "admin" {
						return errors.New("role not allowed")
					}
					return nil
				},
			},
		}),
	))
	router.GET("/private", func(c *gin.Context) {
		nextCalled = true

		claimsValue, exists := c.Get(JWTClaimsContextKey.String())
		if !exists {
			t.Fatal("expected claims in context")
		}

		claims, ok := claimsValue.(*cookieClaims)
		if !ok {
			t.Fatalf("expected *cookieClaims in context, got %T", claimsValue)
		}

		if claims.UserID != "42" {
			t.Fatalf("expected user id 42, got %s", claims.UserID)
		}

		if _, exists := c.Get(JWTTokenContextKey.String()); !exists {
			t.Fatal("expected token in context")
		}

		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: token})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected middleware to continue the handler chain")
	}

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, rec.Code)
	}
}

func TestRequireJWTCookieRejectsMissingCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	configureMiddlewareJWTCookie()
	defer viper.Reset()

	router := gin.New()
	handlerCalled := false
	router.Use(RequireJWTCookie(WithJWTCookieServiceConfig(middlewareJWTCookieServiceConfig())))
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

func TestRequireJWTCookieRejectsInvalidServiceConfiguration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	viper.Reset()
	viper.Set(jwtservice.DefaultAlgorithmKey, "HS256")
	defer viper.Reset()

	viper.Set(cookiesauth.DefaultCookieNameKey, "session_token")

	router := gin.New()
	var captured error

	router.Use(RequireJWTCookie(WithJWTCookieUnauthorizedHandler(func(c *gin.Context, err error) {
		captured = err
		c.AbortWithStatus(http.StatusTeapot)
	}), WithJWTCookieServiceConfig(cookiesauth.ConfigServiceInput{
		CookieName: "session_token",
		JWT: cookiesauth.JWTConfigServiceInput{
			Algorithm:     "HS256",
			HMACSecretKey: stringPtr(jwtservice.DefaultHMACSecretKey),
		},
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

func TestRequireJWTCookieWithCustomContextKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	configureMiddlewareJWTCookie()
	defer viper.Reset()

	service, err := jwtservice.NewConfiguredService(nil)
	if err != nil {
		t.Fatalf("expected jwt service without error, got %v", err)
	}

	token, err := service.Create(cookieClaims{UserID: "84", Role: "reader"})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	router := gin.New()
	router.Use(RequireJWTCookie(
		WithJWTCookieContextKeys(GinContextKey("tokenKey"), GinContextKey("claimsKey")),
		WithJWTCookieServiceConfig(middlewareJWTCookieServiceConfig()),
	))
	router.GET("/private", func(c *gin.Context) {
		claimsValue, exists := c.Get(GinContextKey("claimsKey").String())
		if !exists {
			t.Fatal("expected claims under custom key")
		}

		claimsMap, ok := claimsValue.(map[string]any)
		if !ok {
			t.Fatalf("expected map claims, got %T", claimsValue)
		}

		if claimsMap["user_id"] != "84" {
			t.Fatalf("expected user_id 84, got %v", claimsMap["user_id"])
		}

		if _, exists := c.Get(GinContextKey("tokenKey").String()); !exists {
			t.Fatal("expected token under custom key")
		}

		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: token})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, rec.Code)
	}
}

func TestJWTCookieMiddlewareOptionNilHandlersDoNotOverrideDefaults(t *testing.T) {
	config := cookieMiddlewareConfig{
		tokenContextKey:     JWTTokenContextKey,
		claimsContextKey:    JWTClaimsContextKey,
		serviceFactory:      cookiesauth.NewConfiguredService,
		unauthorizedHandler: func(*gin.Context, error) {},
	}

	WithJWTCookieClaimsFactory(nil)(&config)
	if config.claimsFactory != nil {
		t.Fatal("expected nil claims factory to remain nil")
	}

	WithJWTCookieContextKeys(GinContextKey(""), GinContextKey(""))(&config)
	if config.tokenContextKey != JWTTokenContextKey || config.claimsContextKey != JWTClaimsContextKey {
		t.Fatal("expected default keys to remain unchanged")
	}

	currentHandler := config.unauthorizedHandler
	WithJWTCookieUnauthorizedHandler(nil)(&config)
	if fmt.Sprintf("%p", currentHandler) != fmt.Sprintf("%p", config.unauthorizedHandler) {
		t.Fatal("expected unauthorized handler to remain unchanged")
	}

	WithJWTCookieServiceConfig(cookiesauth.ConfigServiceInput{CookieName: "session_token"})(&config)
	if config.serviceConfig.CookieName != "session_token" {
		t.Fatal("expected service config to be updated")
	}
}

func configureMiddlewareJWTCookie() {
	viper.Reset()
	viper.Set(jwtservice.DefaultAlgorithmKey, "HS256")
	viper.Set(jwtservice.DefaultHMACSecretKey, "middleware-secret")
	viper.Set("COOKIE_MIDDLEWARE_SECRET", "middleware-secret")
	viper.Set(cookiesauth.DefaultCookieNameKey, "session_token")
	viper.Set("COOKIE_MIDDLEWARE_NAME", "session_token")
}

func middlewareJWTCookieServiceConfig() cookiesauth.ConfigServiceInput {
	return cookiesauth.ConfigServiceInput{
		CookieNameKey: "COOKIE_MIDDLEWARE_NAME",
		JWT: cookiesauth.JWTConfigServiceInput{
			Algorithm:     "HS256",
			HMACSecretKey: stringPtr("COOKIE_MIDDLEWARE_SECRET"),
		},
	}
}

func stringPtr(value string) *string {
	return &value
}
