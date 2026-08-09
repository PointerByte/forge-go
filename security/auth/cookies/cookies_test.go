// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package cookies

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	jwtservice "github.com/PointerByte/forge-go/security/auth/jwt"
	"github.com/spf13/viper"
)

type testClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

func TestReadAndDecodeCookieJWT(t *testing.T) {
	jwtSvc, err := jwtservice.New(jwtservice.WithHMACSHA256("cookie-secret"))
	if err != nil {
		t.Fatalf("expected jwt service without error, got %v", err)
	}

	service, err := New(
		WithJWTService(jwtSvc),
		WithCookieName("auth_token"),
	)
	if err != nil {
		t.Fatalf("expected cookie service without error, got %v", err)
	}

	token, err := jwtSvc.Create(testClaims{UserID: "42", Role: "admin"})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/private", nil)
	request.AddCookie(&http.Cookie{Name: "auth_token", Value: token})

	var claims testClaims
	if err := service.Read(request, &claims); err != nil {
		t.Fatalf("expected read without error, got %v", err)
	}

	if claims.UserID != "42" {
		t.Fatalf("expected user id 42, got %s", claims.UserID)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.ReadWithContext(ctx, request, &claims); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadWithContext() error = %v, want context.Canceled", err)
	}

	visitedValidator := false
	parsed, err := service.Decode(context.Background(), request, &claims, func(ctx context.Context, token jwtservice.Token) error {
		visitedValidator = true
		return nil
	})
	if err != nil {
		t.Fatalf("expected decode without error, got %v", err)
	}

	if !visitedValidator {
		t.Fatal("expected validator to run")
	}

	if parsed.Header.Algorithm != "HS256" {
		t.Fatalf("expected HS256 algorithm, got %s", parsed.Header.Algorithm)
	}
}

func TestValidateRequest(t *testing.T) {
	jwtSvc, err := jwtservice.New(jwtservice.WithHMACSHA256("cookie-secret"))
	if err != nil {
		t.Fatalf("expected jwt service without error, got %v", err)
	}

	service, err := New(
		WithJWTService(jwtSvc),
		WithCookieName("access_token"),
	)
	if err != nil {
		t.Fatalf("expected cookie service without error, got %v", err)
	}

	token, err := jwtSvc.Create(testClaims{UserID: "7", Role: "reader"})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/private", nil)
	request.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	if err := service.ValidateRequest(request); err != nil {
		t.Fatalf("expected validate without error, got %v", err)
	}
}

func TestTokenFromRequestErrors(t *testing.T) {
	jwtSvc, err := jwtservice.New(jwtservice.WithHMACSHA256("cookie-secret"))
	if err != nil {
		t.Fatalf("expected jwt service without error, got %v", err)
	}

	service, err := New(
		WithJWTService(jwtSvc),
		WithCookieName("access_token"),
	)
	if err != nil {
		t.Fatalf("expected cookie service without error, got %v", err)
	}

	if _, err := service.TokenFromRequest(nil); !errors.Is(err, ErrNilRequest) {
		t.Fatalf("expected ErrNilRequest, got %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/private", nil)
	if _, err := service.TokenFromRequest(request); !errors.Is(err, ErrMissingCookie) {
		t.Fatalf("expected ErrMissingCookie, got %v", err)
	}

	request.AddCookie(&http.Cookie{Name: "access_token", Value: "   "})
	if _, err := service.TokenFromRequest(request); !errors.Is(err, ErrMissingCookie) {
		t.Fatalf("expected ErrMissingCookie for blank value, got %v", err)
	}
}

func TestNewAndOptionsErrors(t *testing.T) {
	if _, err := New(); !errors.Is(err, ErrNilJWTService) {
		t.Fatalf("expected ErrNilJWTService, got %v", err)
	}

	if _, err := New(nil); !errors.Is(err, ErrNilJWTService) {
		t.Fatalf("expected ErrNilJWTService with nil option, got %v", err)
	}

	if _, err := New(WithCookieName("access_token")); !errors.Is(err, ErrNilJWTService) {
		t.Fatalf("expected ErrNilJWTService, got %v", err)
	}

	jwtSvc, err := jwtservice.New(jwtservice.WithHMACSHA256("cookie-secret"))
	if err != nil {
		t.Fatalf("expected jwt service without error, got %v", err)
	}

	if _, err := New(WithJWTService(jwtSvc)); !errors.Is(err, ErrMissingCookieKey) {
		t.Fatalf("expected ErrMissingCookieKey, got %v", err)
	}

	if _, err := New(WithJWTService(nil)); !errors.Is(err, ErrNilJWTService) {
		t.Fatalf("expected ErrNilJWTService from option, got %v", err)
	}

	if _, err := New(WithJWTService(jwtSvc), WithCookieName("")); !errors.Is(err, ErrMissingCookieKey) {
		t.Fatalf("expected ErrMissingCookieKey from option, got %v", err)
	}
}

func TestNilServiceAndCookieName(t *testing.T) {
	var service *Service
	request := httptest.NewRequest(http.MethodGet, "/private", nil)

	if service.CookieName() != "" {
		t.Fatalf("nil service CookieName() = %q, want empty", service.CookieName())
	}
	if _, err := service.TokenFromRequest(request); !errors.Is(err, ErrNilJWTService) {
		t.Fatalf("nil service TokenFromRequest() error = %v, want ErrNilJWTService", err)
	}
	if err := service.ValidateRequest(request); !errors.Is(err, ErrNilJWTService) {
		t.Fatalf("nil service ValidateRequest() error = %v, want ErrNilJWTService", err)
	}
	if _, err := service.Decode(context.Background(), request, &testClaims{}); !errors.Is(err, ErrNilJWTService) {
		t.Fatalf("nil service Decode() error = %v, want ErrNilJWTService", err)
	}
}

func TestValidateRequestAndDecodeErrors(t *testing.T) {
	jwtSvc, err := jwtservice.New(jwtservice.WithHMACSHA256("cookie-secret"))
	if err != nil {
		t.Fatalf("expected jwt service without error, got %v", err)
	}

	service, err := New(
		WithJWTService(jwtSvc),
		WithCookieName("access_token"),
	)
	if err != nil {
		t.Fatalf("expected cookie service without error, got %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/private", nil)
	if err := service.ValidateRequest(request); !errors.Is(err, ErrMissingCookie) {
		t.Fatalf("ValidateRequest() error = %v, want ErrMissingCookie", err)
	}
	if _, err := service.Decode(context.Background(), request, &testClaims{}); !errors.Is(err, ErrMissingCookie) {
		t.Fatalf("Decode() error = %v, want ErrMissingCookie", err)
	}

	request.AddCookie(&http.Cookie{Name: "access_token", Value: "not-a-token"})
	if err := service.ValidateRequest(request); err == nil {
		t.Fatal("ValidateRequest() succeeded with invalid token")
	}
}

func TestJWTValidatorPtr(t *testing.T) {
	validator := jwtservice.Validator(func(context.Context, jwtservice.Token) error {
		return nil
	})
	if got := jwtValidatorPtr(nil); got != nil {
		t.Fatalf("jwtValidatorPtr(nil) = %#v, want nil", got)
	}
	got := jwtValidatorPtr(validator)
	if got == nil {
		t.Fatal("jwtValidatorPtr(non-nil) = nil")
	}
}

func TestApplyJWTConfig(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	hmacKey := "COOKIE_HMAC_SECRET"
	rsaPrivateKey := "COOKIE_RSA_PRIVATE"
	rsaPublicKey := "COOKIE_RSA_PUBLIC"
	eddsaPrivateKey := "COOKIE_EDDSA_PRIVATE"
	eddsaPublicKey := "COOKIE_EDDSA_PUBLIC"

	viper.Set(hmacKey, "hmac-from-key")
	viper.Set(rsaPrivateKey, "rsa-private-from-key")
	viper.Set(rsaPublicKey, "rsa-public-from-key")
	viper.Set(eddsaPrivateKey, "eddsa-private-from-key")
	viper.Set(eddsaPublicKey, "eddsa-public-from-key")

	applyJWTConfig(JWTConfigServiceInput{
		Algorithm:          "EdDSA",
		HMACSecret:         "hmac-direct",
		HMACSecretKey:      &hmacKey,
		RSAPrivateKey:      "rsa-private-direct",
		RSAPublicKey:       "rsa-public-direct",
		RSAPrivateKeyKey:   &rsaPrivateKey,
		RSAPublicKeyKey:    &rsaPublicKey,
		EdDSAPrivateKey:    "eddsa-private-direct",
		EdDSAPublicKey:     "eddsa-public-direct",
		EdDSAPrivateKeyKey: &eddsaPrivateKey,
		EdDSAPublicKeyKey:  &eddsaPublicKey,
	})

	if got := viper.GetString(jwtservice.DefaultAlgorithmKey); got != "EdDSA" {
		t.Fatalf("algorithm = %q, want EdDSA", got)
	}
	if got := viper.GetString(jwtservice.DefaultHMACSecretKey); got != "hmac-from-key" {
		t.Fatalf("hmac secret = %q, want hmac-from-key", got)
	}
	if got := viper.GetString(jwtservice.DefaultJWTPrivateKeyKey); got != "eddsa-private-from-key" {
		t.Fatalf("private key = %q, want eddsa-private-from-key", got)
	}
	if got := viper.GetString(jwtservice.DefaultJWTPublicKeyKey); got != "eddsa-public-from-key" {
		t.Fatalf("public key = %q, want eddsa-public-from-key", got)
	}
}

func TestNewConfiguredServiceSupportsDirectAndViperCookieNames(t *testing.T) {
	t.Run("direct cookie name", func(t *testing.T) {
		key := "COOKIE_TEST_SECRET_DIRECT"
		_, err := NewConfiguredService(ConfigServiceInput{
			CookieName: "session_token",
			JWT: JWTConfigServiceInput{
				Algorithm:     "HS256",
				HMACSecretKey: &key,
			},
		})
		if err == nil {
			t.Fatal("expected missing secret error for absent viper value")
		}
	})

	t.Run("viper config", func(t *testing.T) {
		viper.Reset()
		defer viper.Reset()

		key := "COOKIE_TEST_SECRET"
		viper.Set(key, "configured-secret")
		viper.Set("COOKIE_TEST_NAME", "session_token")
		service, err := NewConfiguredService(ConfigServiceInput{
			CookieNameKey: "COOKIE_TEST_NAME",
			JWT: JWTConfigServiceInput{
				Algorithm:     "HS256",
				HMACSecretKey: &key,
			},
		})
		if err != nil {
			t.Fatalf("expected service without error, got %v", err)
		}

		if service.CookieName() != "session_token" {
			t.Fatalf("expected cookie name session_token, got %s", service.CookieName())
		}
	})

	t.Run("default cookie name", func(t *testing.T) {
		viper.Reset()
		defer viper.Reset()

		key := "COOKIE_TEST_SECRET_DEFAULT"
		viper.Set(key, "configured-secret")
		service, err := NewConfiguredService(ConfigServiceInput{
			JWT: JWTConfigServiceInput{
				Algorithm:     "HS256",
				HMACSecretKey: &key,
			},
		})
		if err != nil {
			t.Fatalf("expected service without error, got %v", err)
		}

		if service.CookieName() != DefaultCookieName {
			t.Fatalf("expected default cookie name %s, got %s", DefaultCookieName, service.CookieName())
		}
	})
}
