// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

type testClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	Active bool   `json:"active"`
}

type simpleStrategy struct {
	algorithm string
	signature []byte
	signErr   error
	verifyErr error
}

func (strategy simpleStrategy) Algorithm() string {
	return strategy.algorithm
}

func (strategy simpleStrategy) Sign([]byte) ([]byte, error) {
	if strategy.signErr != nil {
		return nil, strategy.signErr
	}
	return strategy.signature, nil
}

func (strategy simpleStrategy) Verify([]byte, []byte) error {
	return strategy.verifyErr
}

func TestSetJWTAsymmetricKeys(t *testing.T) {
	t.Run("rsa uses defaults when keys are unset", func(t *testing.T) {
		viper.Reset()
		t.Cleanup(viper.Reset)

		if err := SetJWTAsymmetricKeys("rsa-private", "rsa-public", "rsa"); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if got := viper.GetString(DefaultJWTPrivateKeyKey); got != "rsa-private" {
			t.Fatalf("expected private key %q, got %q", "rsa-private", got)
		}
		if got := viper.GetString(DefaultJWTPublicKeyKey); got != "rsa-public" {
			t.Fatalf("expected public key %q, got %q", "rsa-public", got)
		}
	})

	t.Run("rsa overwrites existing values", func(t *testing.T) {
		viper.Reset()
		t.Cleanup(viper.Reset)
		viper.Set(DefaultJWTPrivateKeyKey, "old-private")
		viper.Set(DefaultJWTPublicKeyKey, "old-public")

		if err := SetJWTAsymmetricKeys("new-private", "new-public", "RSA"); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if got := viper.GetString(DefaultJWTPrivateKeyKey); got != "new-private" {
			t.Fatalf("expected private key %q, got %q", "new-private", got)
		}
		if got := viper.GetString(DefaultJWTPublicKeyKey); got != "new-public" {
			t.Fatalf("expected public key %q, got %q", "new-public", got)
		}
	})

	t.Run("eddsa uses defaults when keys are unset", func(t *testing.T) {
		viper.Reset()
		t.Cleanup(viper.Reset)

		if err := SetJWTAsymmetricKeys("eddsa-private", "eddsa-public", " eddsa "); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if got := viper.GetString(DefaultJWTPrivateKeyKey); got != "eddsa-private" {
			t.Fatalf("expected private key %q, got %q", "eddsa-private", got)
		}
		if got := viper.GetString(DefaultJWTPublicKeyKey); got != "eddsa-public" {
			t.Fatalf("expected public key %q, got %q", "eddsa-public", got)
		}
	})

	t.Run("eddsa overwrites existing values", func(t *testing.T) {
		viper.Reset()
		t.Cleanup(viper.Reset)
		viper.Set(DefaultJWTPrivateKeyKey, "old-private")
		viper.Set(DefaultJWTPublicKeyKey, "old-public")

		if err := SetJWTAsymmetricKeys("new-private", "new-public", "EdDSA"); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if got := viper.GetString(DefaultJWTPrivateKeyKey); got != "new-private" {
			t.Fatalf("expected private key %q, got %q", "new-private", got)
		}
		if got := viper.GetString(DefaultJWTPublicKeyKey); got != "new-public" {
			t.Fatalf("expected public key %q, got %q", "new-public", got)
		}
	})

	t.Run("unsupported algorithm returns error", func(t *testing.T) {
		viper.Reset()
		t.Cleanup(viper.Reset)

		err := SetJWTAsymmetricKeys("private", "public", "ecdsa")
		if !errors.Is(err, ErrUnsupportedAlg) {
			t.Fatalf("expected ErrUnsupportedAlg, got %v", err)
		}
	})
}

func TestCreateValidateAndReadJWT(t *testing.T) {
	service, err := New(WithHMACSHA256("super-secret"))
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}

	wantClaims := testClaims{
		UserID: "42",
		Role:   "admin",
		Active: true,
	}

	token, err := service.Create(wantClaims)
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	if err := service.ValidateSignature(token); err != nil {
		t.Fatalf("expected valid signature, got %v", err)
	}

	var gotClaims testClaims
	if err := service.Read(token, &gotClaims); err != nil {
		t.Fatalf("expected read without error, got %v", err)
	}

	if gotClaims != wantClaims {
		t.Fatalf("expected claims %+v, got %+v", wantClaims, gotClaims)
	}
}

func TestRegisteredTimeClaimValidation(t *testing.T) {
	fixedNow := time.Unix(1_700_000_000, 500_000_000)

	tests := []struct {
		name      string
		claims    map[string]any
		leeway    time.Duration
		wantError error
	}{
		{
			name: "valid registered times and custom claims",
			claims: map[string]any{
				"exp":     float64(fixedNow.Unix()) + 60,
				"nbf":     float64(fixedNow.Unix()) - 60,
				"iss":     "caller-owned",
				"aud":     []string{"api", "worker"},
				"profile": map[string]any{"role": "admin"},
			},
		},
		{
			name:      "expiration at current time is expired",
			claims:    map[string]any{"exp": float64(fixedNow.Unix()) + 0.5},
			wantError: ErrTokenExpired,
		},
		{
			name:      "expired token",
			claims:    map[string]any{"exp": fixedNow.Unix() - 1},
			wantError: ErrTokenExpired,
		},
		{
			name:      "token not valid yet",
			claims:    map[string]any{"nbf": fixedNow.Unix() + 1},
			wantError: ErrTokenNotYetValid,
		},
		{
			name:      "string expiration is invalid",
			claims:    map[string]any{"exp": "1700000000"},
			wantError: ErrInvalidExpirationClaim,
		},
		{
			name:      "null expiration is invalid",
			claims:    map[string]any{"exp": nil},
			wantError: ErrInvalidExpirationClaim,
		},
		{
			name:      "boolean not-before is invalid",
			claims:    map[string]any{"nbf": true},
			wantError: ErrInvalidNotBeforeClaim,
		},
		{
			name: "leeway accepts bounded clock skew",
			claims: map[string]any{
				"exp": float64(fixedNow.Unix()),
				"nbf": float64(fixedNow.Unix()) + 1,
			},
			leeway: time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := []Option{
				WithHMACSHA256("time-claim-secret"),
				WithClock(func() time.Time { return fixedNow }),
			}
			if test.leeway != 0 {
				options = append(options, WithLeeway(test.leeway))
			}
			service, err := New(options...)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			token, err := service.Create(test.claims)
			if err != nil {
				t.Fatalf("Create() error = %v", err)
			}

			var got map[string]any
			parsed, err := service.Decode(context.Background(), token, &got)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("Decode() error = %v, want %v", err, test.wantError)
			}
			if test.wantError != nil {
				return
			}
			if parsed == nil {
				t.Fatal("Decode() returned a nil parsed token")
			}
			if got["iss"] != test.claims["iss"] {
				t.Fatalf("custom issuer claim = %#v, want %#v", got["iss"], test.claims["iss"])
			}
			if _, hasProfile := test.claims["profile"]; hasProfile &&
				!strings.Contains(string(parsed.Claims), `"profile"`) {
				t.Fatalf("parsed claims lost custom payload: %s", parsed.Claims)
			}
		})
	}
}

func TestRegisteredTimeClaimsRunAfterSignatureVerification(t *testing.T) {
	fixedNow := time.Unix(1_700_000_000, 0)
	issuer, err := New(WithHMACSHA256("issuer-secret"))
	if err != nil {
		t.Fatalf("New(issuer) error = %v", err)
	}
	token, err := issuer.Create(map[string]any{"exp": fixedNow.Unix() - 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	verifier, err := New(
		WithHMACSHA256("different-secret"),
		WithClock(func() time.Time { return fixedNow }),
	)
	if err != nil {
		t.Fatalf("New(verifier) error = %v", err)
	}
	if err := verifier.ValidateSignature(token); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("ValidateSignature() error = %v, want ErrInvalidSignature", err)
	}
}

func TestRegisteredTimeValidationPreservesNonObjectClaims(t *testing.T) {
	clockCalls := 0
	service, err := New(
		WithHMACSHA256("arbitrary-claims-secret"),
		WithClock(func() time.Time {
			clockCalls++
			return time.Unix(1_700_000_000, 0)
		}),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	token, err := service.Create([]string{"custom", "claims"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	var claims []string
	if _, err := service.Decode(context.Background(), token, &claims); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(claims) != 2 || claims[0] != "custom" || claims[1] != "claims" {
		t.Fatalf("decoded arbitrary claims = %#v", claims)
	}
	if clockCalls != 0 {
		t.Fatalf("clock called %d times for claims without exp or nbf", clockCalls)
	}
}

func TestRegisteredTimeClaimsPrecedeCallerValidators(t *testing.T) {
	fixedNow := time.Unix(1_700_000_000, 0)
	validatorCalled := false
	service, err := New(
		WithHMACSHA256("validator-order-secret"),
		WithClock(func() time.Time { return fixedNow }),
		WithValidator(func(context.Context, Token) error {
			validatorCalled = true
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	token, err := service.Create(map[string]any{
		"exp": fixedNow.Unix() - 1,
		"iss": "untrusted",
		"aud": "untrusted",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	var claims map[string]any
	if _, err := service.Decode(context.Background(), token, &claims); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("Decode() error = %v, want ErrTokenExpired", err)
	}
	if validatorCalled {
		t.Fatal("caller validator ran before registered-time validation")
	}
}

func TestClockAndLeewayOptionValidation(t *testing.T) {
	if _, err := New(WithHMACSHA256("secret"), WithClock(nil)); !errors.Is(err, ErrNilClock) {
		t.Fatalf("New() error = %v, want ErrNilClock", err)
	}
	if _, err := New(WithHMACSHA256("secret"), WithLeeway(-time.Nanosecond)); !errors.Is(err, ErrInvalidLeeway) {
		t.Fatalf("New() error = %v, want ErrInvalidLeeway", err)
	}
}

func TestServiceContextTimeout(t *testing.T) {
	issuer, err := New(WithHMACSHA256("super-secret"))
	if err != nil {
		t.Fatalf("expected issuer without error, got %v", err)
	}
	token, err := issuer.Create(testClaims{UserID: "42"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	service, err := New(
		WithHMACSHA256("super-secret"),
		WithContextTimeout(time.Nanosecond),
		WithValidator(func(ctx context.Context, token Token) error {
			<-ctx.Done()
			return ctx.Err()
		}),
	)
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}

	var claims testClaims
	if _, err := service.Decode(context.Background(), token, &claims); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Decode() error = %v, want context.DeadlineExceeded", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.CreateWithContext(ctx, testClaims{UserID: "42"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("CreateWithContext() error = %v, want context.Canceled", err)
	}

	if err := service.ReadWithContext(ctx, token, &claims); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadWithContext() error = %v, want context.Canceled", err)
	}
}

func TestDecodeRunsServiceAndInlineValidators(t *testing.T) {
	const tokenUserID = "db-user"

	service, err := New(
		WithHMACSHA256("another-secret"),
		WithValidator(func(ctx context.Context, token Token) error {
			if token.Header.Type != "JWT" {
				return errors.New("unexpected token type")
			}
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}

	token, err := service.Create(testClaims{
		UserID: tokenUserID,
		Role:   "reader",
		Active: true,
	})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	var gotClaims testClaims
	visitedDB := false

	parsedToken, err := service.Decode(context.Background(), token, &gotClaims, func(ctx context.Context, token Token) error {
		visitedDB = true

		var claims testClaims
		if err := unmarshalClaims(token.Claims, &claims); err != nil {
			return err
		}

		if claims.UserID != tokenUserID {
			return errors.New("user not found in db")
		}

		return nil
	})
	if err != nil {
		t.Fatalf("expected decode without error, got %v", err)
	}

	if !visitedDB {
		t.Fatal("expected inline validator to run")
	}

	if parsedToken.Header.Algorithm != "HS256" {
		t.Fatalf("expected algorithm HS256, got %s", parsedToken.Header.Algorithm)
	}

	if gotClaims.UserID != tokenUserID {
		t.Fatalf("expected user id %q, got %q", tokenUserID, gotClaims.UserID)
	}
}

func TestValidateSignatureFailsWithTamperedToken(t *testing.T) {
	service, err := New(WithHMACSHA256("super-secret"))
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}

	token, err := service.Create(testClaims{
		UserID: "42",
		Role:   "admin",
		Active: true,
	})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	parts := strings.Split(token, ".")
	tampered := parts[0] + "." + encodeSegment([]byte(`{"user_id":"999","role":"admin","active":true}`)) + "." + parts[2]

	if err := service.ValidateSignature(tampered); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected invalid signature error, got %v", err)
	}
}

func TestDecodeFailsWhenInlineValidatorRejectsToken(t *testing.T) {
	service, err := New(WithHMACSHA256("super-secret"))
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}

	token, err := service.Create(testClaims{
		UserID: "inactive-user",
		Role:   "reader",
		Active: false,
	})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	var gotClaims testClaims
	err = service.Read(token, &gotClaims)
	if err != nil {
		t.Fatalf("expected read without error, got %v", err)
	}

	_, err = service.Decode(context.Background(), token, &gotClaims, func(ctx context.Context, token Token) error {
		if !gotClaims.Active {
			return errors.New("user inactive in db")
		}
		return nil
	})
	if err == nil || err.Error() != "user inactive in db" {
		t.Fatalf("expected db validation error, got %v", err)
	}
}

func TestCreateValidateAndReadJWTWithRS256(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("expected rsa key without error, got %v", err)
	}

	service, err := New(WithRSASHA256(privateKey, &privateKey.PublicKey))
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}

	wantClaims := testClaims{
		UserID: "rsa-user",
		Role:   "operator",
		Active: true,
	}

	token, err := service.Create(wantClaims)
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	if err := service.ValidateSignature(token); err != nil {
		t.Fatalf("expected valid rsa signature, got %v", err)
	}

	var gotClaims testClaims
	parsedToken, err := service.Decode(context.Background(), token, &gotClaims)
	if err != nil {
		t.Fatalf("expected decode without error, got %v", err)
	}

	if parsedToken.Header.Algorithm != "RS256" {
		t.Fatalf("expected algorithm RS256, got %s", parsedToken.Header.Algorithm)
	}

	if gotClaims != wantClaims {
		t.Fatalf("expected claims %+v, got %+v", wantClaims, gotClaims)
	}
}

func TestCreateValidateAndReadJWTWithPS256(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("expected rsa key without error, got %v", err)
	}

	service, err := New(WithRSAPSSSHA256(privateKey, &privateKey.PublicKey))
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}

	wantClaims := testClaims{UserID: "pss-user", Role: "operator", Active: true}

	token, err := service.Create(wantClaims)
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	if err := service.ValidateSignature(token); err != nil {
		t.Fatalf("expected valid pss signature, got %v", err)
	}

	var gotClaims testClaims
	parsedToken, err := service.Decode(context.Background(), token, &gotClaims)
	if err != nil {
		t.Fatalf("expected decode without error, got %v", err)
	}

	if parsedToken.Header.Algorithm != "PS256" {
		t.Fatalf("expected algorithm PS256, got %s", parsedToken.Header.Algorithm)
	}

	if gotClaims != wantClaims {
		t.Fatalf("expected claims %+v, got %+v", wantClaims, gotClaims)
	}
}

func TestCreateValidateAndReadJWTWithEdDSA(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("expected ed25519 key without error, got %v", err)
	}

	service, err := New(WithEd25519(privateKey, publicKey))
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}

	wantClaims := testClaims{UserID: "eddsa-user", Role: "operator", Active: true}

	token, err := service.Create(wantClaims)
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	if err := service.ValidateSignature(token); err != nil {
		t.Fatalf("expected valid eddsa signature, got %v", err)
	}

	var gotClaims testClaims
	parsedToken, err := service.Decode(context.Background(), token, &gotClaims)
	if err != nil {
		t.Fatalf("expected decode without error, got %v", err)
	}

	if parsedToken.Header.Algorithm != "EdDSA" {
		t.Fatalf("expected algorithm EdDSA, got %s", parsedToken.Header.Algorithm)
	}

	if gotClaims != wantClaims {
		t.Fatalf("expected claims %+v, got %+v", wantClaims, gotClaims)
	}
}

func TestCreateValidateAndReadJWTWithCustomStrategy(t *testing.T) {
	sign := func(ctx context.Context, signingInput []byte) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []byte("custom:" + string(signingInput)), nil
	}
	verify := func(ctx context.Context, signingInput []byte, signature []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		want := "custom:" + string(signingInput)
		if string(signature) != want {
			return ErrInvalidSignature
		}
		return nil
	}

	service, err := New(WithCustomStrategy("CUSTOM", sign, verify))
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}

	wantClaims := testClaims{UserID: "custom-user", Role: "operator", Active: true}
	token, err := service.Create(wantClaims)
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	var gotClaims testClaims
	parsedToken, err := service.Decode(context.Background(), token, &gotClaims)
	if err != nil {
		t.Fatalf("expected decode without error, got %v", err)
	}
	if parsedToken.Header.Algorithm != "CUSTOM" {
		t.Fatalf("expected algorithm CUSTOM, got %s", parsedToken.Header.Algorithm)
	}
	if gotClaims != wantClaims {
		t.Fatalf("expected claims %+v, got %+v", wantClaims, gotClaims)
	}

	parts := strings.Split(token, ".")
	parts[2] = encodeSegment([]byte("bad-signature"))
	if err := service.ValidateSignature(strings.Join(parts, ".")); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestNewAndOptionsErrors(t *testing.T) {
	if _, err := New(); !errors.Is(err, ErrNilStrategy) {
		t.Fatalf("expected ErrNilStrategy, got %v", err)
	}

	if _, err := New(WithHMACSHA256("")); !errors.Is(err, ErrMissingSecret) {
		t.Fatalf("expected ErrMissingSecret, got %v", err)
	}

	if _, err := New(WithStrategy(nil)); !errors.Is(err, ErrNilStrategy) {
		t.Fatalf("expected ErrNilStrategy from WithStrategy, got %v", err)
	}

	if _, err := New(WithValidator(nil), WithHMACSHA256("secret")); !errors.Is(err, ErrNilValidator) {
		t.Fatalf("expected ErrNilValidator, got %v", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("expected rsa key without error, got %v", err)
	}

	if _, err := New(WithRSASHA256(nil, &privateKey.PublicKey)); !errors.Is(err, ErrMissingPrivateKey) {
		t.Fatalf("expected ErrMissingPrivateKey, got %v", err)
	}

	if _, err := New(WithRSASHA256(privateKey, nil)); !errors.Is(err, ErrMissingPublicKey) {
		t.Fatalf("expected ErrMissingPublicKey, got %v", err)
	}

	if _, err := New(WithRSAPSSSHA256(nil, &privateKey.PublicKey)); !errors.Is(err, ErrMissingPrivateKey) {
		t.Fatalf("expected ErrMissingPrivateKey, got %v", err)
	}

	if _, err := New(WithRSAPSSSHA256(privateKey, nil)); !errors.Is(err, ErrMissingPublicKey) {
		t.Fatalf("expected ErrMissingPublicKey, got %v", err)
	}

	if _, err := New(WithEd25519(nil, nil)); !errors.Is(err, ErrMissingEdDSAPrivateKey) {
		t.Fatalf("expected ErrMissingEdDSAPrivateKey, got %v", err)
	}

	if _, err := New(WithCustomStrategy("", func(context.Context, []byte) ([]byte, error) { return nil, nil }, func(context.Context, []byte, []byte) error { return nil })); !errors.Is(err, ErrMissingAlgorithm) {
		t.Fatalf("expected ErrMissingAlgorithm, got %v", err)
	}

	if _, err := New(WithCustomStrategy("CUSTOM", nil, func(context.Context, []byte, []byte) error { return nil })); !errors.Is(err, ErrMissingSignFunc) {
		t.Fatalf("expected ErrMissingSignFunc, got %v", err)
	}

	if _, err := New(WithCustomStrategy("CUSTOM", func(context.Context, []byte) ([]byte, error) { return nil, nil }, nil)); !errors.Is(err, ErrMissingVerifyFunc) {
		t.Fatalf("expected ErrMissingVerifyFunc, got %v", err)
	}
}

func TestNewHMACServiceUsesViperSecretAndOptionalValidator(t *testing.T) {
	viper.Set(DefaultHMACSecretKey, "service-secret")
	defer viper.Reset()

	validatorCalled := false
	validator := Validator(func(ctx context.Context, token Token) error {
		validatorCalled = true
		return nil
	})
	service, err := NewHMACService(&validator)
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}

	token, err := service.Create(testClaims{UserID: "42", Role: "reader", Active: true})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	var claims testClaims
	if _, err := service.Decode(context.Background(), token, &claims); err != nil {
		t.Fatalf("expected decode without error, got %v", err)
	}
	if !validatorCalled {
		t.Fatal("expected validator to run")
	}
}

func TestNewRSAServiceUsesViperKeysAndOptionalValidator(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("expected rsa key without error, got %v", err)
	}
	setRSAConfig(t, privateKey)

	validatorCalled := false
	validator := Validator(func(ctx context.Context, token Token) error {
		validatorCalled = true
		return nil
	})
	service, err := NewRSAService(&validator)
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}

	token, err := service.Create(testClaims{UserID: "99", Role: "operator", Active: true})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	var claims testClaims
	if _, err := service.Decode(context.Background(), token, &claims); err != nil {
		t.Fatalf("expected decode without error, got %v", err)
	}
	if !validatorCalled {
		t.Fatal("expected validator to run")
	}
}

func TestNewRSAPSSServiceUsesViperKeysAndOptionalValidator(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("expected rsa key without error, got %v", err)
	}
	setRSAConfig(t, privateKey)

	validatorCalled := false
	validator := Validator(func(ctx context.Context, token Token) error {
		validatorCalled = true
		return nil
	})
	service, err := NewRSAPSSService(&validator)
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}

	token, err := service.Create(testClaims{UserID: "99", Role: "operator", Active: true})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	var claims testClaims
	if _, err := service.Decode(context.Background(), token, &claims); err != nil {
		t.Fatalf("expected decode without error, got %v", err)
	}
	if !validatorCalled {
		t.Fatal("expected validator to run")
	}
}

func TestNewEd25519ServiceUsesViperKeysAndOptionalValidator(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("expected ed25519 key without error, got %v", err)
	}
	setEd25519Config(t, privateKey, publicKey)

	validatorCalled := false
	validator := Validator(func(ctx context.Context, token Token) error {
		validatorCalled = true
		return nil
	})
	service, err := NewEd25519Service(&validator)
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}

	token, err := service.Create(testClaims{UserID: "99", Role: "operator", Active: true})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	var claims testClaims
	if _, err := service.Decode(context.Background(), token, &claims); err != nil {
		t.Fatalf("expected decode without error, got %v", err)
	}
	if !validatorCalled {
		t.Fatal("expected validator to run")
	}
}

func TestAsymmetricServicesFallBackToLegacyViperKeys(t *testing.T) {
	t.Run("rsa and rsa pss", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}
		setRSALegacyConfig(t, privateKey)

		for _, newService := range []struct {
			name string
			new  func(*Validator) (*Service, error)
		}{
			{name: "RS256", new: NewRSAService},
			{name: "PS256", new: NewRSAPSSService},
		} {
			t.Run(newService.name, func(t *testing.T) {
				service, err := newService.new(nil)
				if err != nil {
					t.Fatalf("configured service error = %v", err)
				}
				token, err := service.Create(map[string]any{"subject": "legacy-rsa"})
				if err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if err := service.ValidateSignature(token); err != nil {
					t.Fatalf("ValidateSignature() error = %v", err)
				}
			})
		}
	})

	t.Run("ed25519", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey() error = %v", err)
		}
		setEd25519LegacyConfig(t, privateKey, publicKey)

		service, err := NewEd25519Service(nil)
		if err != nil {
			t.Fatalf("NewEd25519Service() error = %v", err)
		}
		token, err := service.Create(map[string]any{"subject": "legacy-ed25519"})
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		if err := service.ValidateSignature(token); err != nil {
			t.Fatalf("ValidateSignature() error = %v", err)
		}
	})
}

func TestNewRSAServiceSupportsPEMFiles(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("expected rsa key without error, got %v", err)
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("expected private key marshal without error, got %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("expected public key marshal without error, got %v", err)
	}

	tempDir := t.TempDir()
	viper.Set(DefaultJWTPrivateKeyKey, writeTestPEMFile(t, tempDir, "private_key.pem", "PRIVATE KEY", privateDER))
	viper.Set(DefaultJWTPublicKeyKey, writeTestPEMFile(t, tempDir, "public_key.pem", "PUBLIC KEY", publicDER))
	defer viper.Reset()

	service, err := NewRSAService(nil)
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}

	token, err := service.Create(testClaims{UserID: "88", Role: "admin", Active: true})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}
	if err := service.ValidateSignature(token); err != nil {
		t.Fatalf("expected valid signature, got %v", err)
	}
}

func TestNewServicesFromViperErrors(t *testing.T) {
	t.Run("missing hmac secret", func(t *testing.T) {
		defer viper.Reset()
		if _, err := NewHMACService(nil); !errors.Is(err, ErrMissingSecret) {
			t.Fatalf("expected ErrMissingSecret, got %v", err)
		}
	})

	t.Run("invalid rsa private key", func(t *testing.T) {
		viper.Set(DefaultJWTPrivateKeyKey, "%%%")
		viper.Set(DefaultJWTPublicKeyKey, "")
		defer viper.Reset()

		err := error(nil)
		_, err = NewRSAService(nil)
		if err == nil || !strings.Contains(err.Error(), DefaultJWTPrivateKeyKey) {
			t.Fatalf("expected private key parse error, got %v", err)
		}
	})
}

func TestNewConfiguredServiceUsesViperAlgorithm(t *testing.T) {
	t.Run("hs256", func(t *testing.T) {
		viper.Set(DefaultAlgorithmKey, "HS256")
		viper.Set(DefaultHMACSecretKey, "configured-secret")
		defer viper.Reset()

		validator := Validator(func(ctx context.Context, token Token) error { return nil })
		service, err := NewConfiguredService(&validator)
		if err != nil {
			t.Fatalf("expected service without error, got %v", err)
		}

		token, err := service.Create(testClaims{UserID: "1", Role: "admin", Active: true})
		if err != nil {
			t.Fatalf("expected token without error, got %v", err)
		}
		if err := service.ValidateSignature(token); err != nil {
			t.Fatalf("expected valid signature, got %v", err)
		}
	})

	t.Run("rs256", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("expected rsa key without error, got %v", err)
		}
		viper.Set(DefaultAlgorithmKey, "RS256")
		setRSAConfig(t, privateKey)

		service, err := NewConfiguredService(nil)
		if err != nil {
			t.Fatalf("expected service without error, got %v", err)
		}

		token, err := service.Create(testClaims{UserID: "2", Role: "admin", Active: true})
		if err != nil {
			t.Fatalf("expected token without error, got %v", err)
		}
		if err := service.ValidateSignature(token); err != nil {
			t.Fatalf("expected valid signature, got %v", err)
		}
	})

	t.Run("ps256", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("expected rsa key without error, got %v", err)
		}
		viper.Set(DefaultAlgorithmKey, "PS256")
		setRSAConfig(t, privateKey)

		service, err := NewConfiguredService(nil)
		if err != nil {
			t.Fatalf("expected service without error, got %v", err)
		}

		token, err := service.Create(testClaims{UserID: "3", Role: "admin", Active: true})
		if err != nil {
			t.Fatalf("expected token without error, got %v", err)
		}
		if err := service.ValidateSignature(token); err != nil {
			t.Fatalf("expected valid signature, got %v", err)
		}
	})

	t.Run("eddsa", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("expected ed25519 key without error, got %v", err)
		}
		setEd25519Config(t, privateKey, publicKey)
		viper.Set(DefaultAlgorithmKey, "EDDSA")

		service, err := NewConfiguredService(nil)
		if err != nil {
			t.Fatalf("expected service without error, got %v", err)
		}

		token, err := service.Create(testClaims{UserID: "4", Role: "admin", Active: true})
		if err != nil {
			t.Fatalf("expected token without error, got %v", err)
		}
		if err := service.ValidateSignature(token); err != nil {
			t.Fatalf("expected valid signature, got %v", err)
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		viper.Set(DefaultAlgorithmKey, "ES256")
		defer viper.Reset()

		_, err := NewConfiguredService(nil)
		if !errors.Is(err, ErrUnsupportedAlg) {
			t.Fatalf("expected ErrUnsupportedAlg, got %v", err)
		}
	})

	t.Run("missing algorithm", func(t *testing.T) {
		defer viper.Reset()

		_, err := NewConfiguredService(nil)
		if !errors.Is(err, ErrMissingAlgorithm) {
			t.Fatalf("expected ErrMissingAlgorithm, got %v", err)
		}
	})
}

func setRSAConfig(t *testing.T, privateKey *rsa.PrivateKey) {
	t.Helper()

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("expected private key marshal without error, got %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("expected public key marshal without error, got %v", err)
	}

	viper.Set(DefaultJWTPrivateKeyKey, base64.StdEncoding.EncodeToString(privateDER))
	viper.Set(DefaultJWTPublicKeyKey, base64.StdEncoding.EncodeToString(publicDER))
	t.Cleanup(viper.Reset)
}

func setEd25519Config(t *testing.T, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) {
	t.Helper()

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("expected private key marshal without error, got %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("expected public key marshal without error, got %v", err)
	}

	viper.Set(DefaultJWTPrivateKeyKey, base64.StdEncoding.EncodeToString(privateDER))
	viper.Set(DefaultJWTPublicKeyKey, base64.StdEncoding.EncodeToString(publicDER))
	t.Cleanup(viper.Reset)
}

func setRSALegacyConfig(t *testing.T, privateKey *rsa.PrivateKey) {
	t.Helper()

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}

	viper.Set(DefaultRSAPrivateKeyKey, base64.StdEncoding.EncodeToString(privateDER))
	viper.Set(DefaultRSAPublicKeyKey, base64.StdEncoding.EncodeToString(publicDER))
	t.Cleanup(viper.Reset)
}

func setEd25519LegacyConfig(t *testing.T, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) {
	t.Helper()

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}

	viper.Set(DefaultEdDSAPrivateKeyKey, base64.StdEncoding.EncodeToString(privateDER))
	viper.Set(DefaultEdDSAPublicKeyKey, base64.StdEncoding.EncodeToString(publicDER))
	t.Cleanup(viper.Reset)
}

func writeTestPEMFile(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()

	path := filepath.Join(dir, name)
	block := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("expected write PEM file without error, got %v", err)
	}
	return path
}

func TestCreateAndDecodeErrors(t *testing.T) {
	service, err := New(WithHMACSHA256("secret"))
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}

	if _, err := (*Service)(nil).Create(testClaims{}); !errors.Is(err, ErrNilStrategy) {
		t.Fatalf("expected ErrNilStrategy for nil service create, got %v", err)
	}

	badClaims := map[string]any{"bad": make(chan int)}
	if _, err := service.Create(badClaims); err == nil || !strings.Contains(err.Error(), "jwt: encode claims") {
		t.Fatalf("expected claims encode error, got %v", err)
	}

	if _, err := service.Decode(context.Background(), "token", nil); !errors.Is(err, ErrNilDestination) {
		t.Fatalf("expected ErrNilDestination, got %v", err)
	}

	token, err := service.Create(testClaims{UserID: "42", Role: "admin", Active: true})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	var claims testClaims
	if _, err := service.Decode(context.Background(), token, &claims, nil); !errors.Is(err, ErrMissingValidation) {
		t.Fatalf("expected ErrMissingValidation, got %v", err)
	}

	if _, err := service.Decode(context.Background(), token, claims); err == nil || !strings.Contains(err.Error(), "jwt: decode claims") {
		t.Fatalf("expected decode claims error, got %v", err)
	}
}

func TestValidateSignatureAndParseErrors(t *testing.T) {
	service, err := New(WithHMACSHA256("secret"))
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}

	tests := []struct {
		name  string
		token string
		check func(error) bool
	}{
		{
			name:  "invalid parts",
			token: "only-two.parts",
			check: func(err error) bool { return errors.Is(err, ErrInvalidToken) },
		},
		{
			name:  "invalid header base64",
			token: "%%%." + encodeSegment([]byte(`{"user_id":"42"}`)) + "." + encodeSegment([]byte("sig")),
			check: func(err error) bool { return err != nil && strings.Contains(err.Error(), "jwt: decode header") },
		},
		{
			name:  "invalid header json",
			token: encodeSegment([]byte("{")) + "." + encodeSegment([]byte(`{"user_id":"42"}`)) + "." + encodeSegment([]byte("sig")),
			check: func(err error) bool { return err != nil && strings.Contains(err.Error(), "jwt: parse header") },
		},
		{
			name:  "unexpected alg",
			token: buildRawToken(t, Header{Type: "JWT", Algorithm: "RS256"}, map[string]any{"user_id": "42"}, []byte("sig")),
			check: func(err error) bool { return err != nil && errors.Is(err, ErrUnexpectedAlg) },
		},
		{
			name:  "invalid claims base64",
			token: buildRawTokenFromParts(t, Header{Type: "JWT", Algorithm: "HS256"}, "%%%", encodeSegment([]byte("sig"))),
			check: func(err error) bool { return err != nil && strings.Contains(err.Error(), "jwt: decode claims") },
		},
		{
			name:  "invalid signature base64",
			token: buildRawTokenFromParts(t, Header{Type: "JWT", Algorithm: "HS256"}, encodeSegment([]byte(`{"user_id":"42"}`)), "%%%"),
			check: func(err error) bool { return err != nil && strings.Contains(err.Error(), "jwt: decode signature") },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := service.ValidateSignature(test.token)
			if !test.check(err) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}

	if err := (*Service)(nil).ValidateSignature("any"); !errors.Is(err, ErrNilStrategy) {
		t.Fatalf("expected ErrNilStrategy for nil service validate, got %v", err)
	}
}

func TestStrategySpecificErrorsAndHelpers(t *testing.T) {
	hmacStrategy := NewHMACSHA256("").(*hmacSHA256Strategy)
	if _, err := hmacStrategy.Sign([]byte("input")); !errors.Is(err, ErrMissingSecret) {
		t.Fatalf("expected ErrMissingSecret, got %v", err)
	}

	rsaStrategy := &rsaSHA256Strategy{}
	if _, err := rsaStrategy.Sign([]byte("input")); !errors.Is(err, ErrMissingPrivateKey) {
		t.Fatalf("expected ErrMissingPrivateKey, got %v", err)
	}

	if err := rsaStrategy.Verify([]byte("input"), []byte("sig")); !errors.Is(err, ErrMissingPublicKey) {
		t.Fatalf("expected ErrMissingPublicKey, got %v", err)
	}

	rsaPSSStrategy := &rsaPSSSHA256Strategy{}
	if _, err := rsaPSSStrategy.Sign([]byte("input")); !errors.Is(err, ErrMissingPrivateKey) {
		t.Fatalf("expected ErrMissingPrivateKey, got %v", err)
	}

	if err := rsaPSSStrategy.Verify([]byte("input"), []byte("sig")); !errors.Is(err, ErrMissingPublicKey) {
		t.Fatalf("expected ErrMissingPublicKey, got %v", err)
	}

	eddsaStrategy := &ed25519Strategy{}
	if _, err := eddsaStrategy.Sign([]byte("input")); !errors.Is(err, ErrMissingEdDSAPrivateKey) {
		t.Fatalf("expected ErrMissingEdDSAPrivateKey, got %v", err)
	}

	if err := eddsaStrategy.Verify([]byte("input"), []byte("sig")); !errors.Is(err, ErrMissingEdDSAPublicKey) {
		t.Fatalf("expected ErrMissingEdDSAPublicKey, got %v", err)
	}

	encoded := encodeSegment([]byte("hello"))
	decoded, err := decodeSegment(encoded)
	if err != nil {
		t.Fatalf("expected decodeSegment without error, got %v", err)
	}
	if string(decoded) != "hello" {
		t.Fatalf("expected %q, got %q", "hello", string(decoded))
	}

	if _, err := decodeSegment("%%%"); err == nil {
		t.Fatal("expected decodeSegment error")
	}
}

func TestStrategyWrappersAndContextFallbacks(t *testing.T) {
	strategy, err := NewCustomStrategy(
		"CUSTOM",
		func(ctx context.Context, signingInput []byte) ([]byte, error) {
			return append([]byte("signed:"), signingInput...), ctx.Err()
		},
		func(ctx context.Context, signingInput []byte, signature []byte) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if string(signature) != "signed:"+string(signingInput) {
				return ErrInvalidSignature
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("expected custom strategy without error, got %v", err)
	}

	signature, err := strategy.Sign([]byte("input"))
	if err != nil {
		t.Fatalf("expected custom sign without error, got %v", err)
	}
	if string(signature) != "signed:input" {
		t.Fatalf("expected custom signature, got %q", signature)
	}
	if err := strategy.Verify([]byte("input"), signature); err != nil {
		t.Fatalf("expected custom verify without error, got %v", err)
	}

	if _, err := (&customStrategy{algorithm: "CUSTOM"}).Sign([]byte("input")); !errors.Is(err, ErrMissingSignFunc) {
		t.Fatalf("expected ErrMissingSignFunc, got %v", err)
	}
	if err := (&customStrategy{algorithm: "CUSTOM"}).Verify([]byte("input"), []byte("signature")); !errors.Is(err, ErrMissingVerifyFunc) {
		t.Fatalf("expected ErrMissingVerifyFunc, got %v", err)
	}

	service, err := New(
		WithStrategy(simpleStrategy{algorithm: "SIMPLE", signature: []byte("signature")}),
		WithContextTimeout(0),
	)
	if err != nil {
		t.Fatalf("expected service without error, got %v", err)
	}
	if service.contextTimeoutOn {
		t.Fatal("expected context timeout to be disabled")
	}

	gotSignature, err := signStrategy(context.Background(), service.strategy, []byte("input"))
	if err != nil {
		t.Fatalf("expected fallback sign without error, got %v", err)
	}
	if string(gotSignature) != "signature" {
		t.Fatalf("expected fallback signature, got %q", gotSignature)
	}
	if err := verifyStrategy(context.Background(), service.strategy, []byte("input"), gotSignature); err != nil {
		t.Fatalf("expected fallback verify without error, got %v", err)
	}

	signErr := errors.New("sign failed")
	if _, err := signStrategy(context.Background(), simpleStrategy{algorithm: "SIMPLE", signErr: signErr}, []byte("input")); !errors.Is(err, signErr) {
		t.Fatalf("expected sign error, got %v", err)
	}

	verifyErr := errors.New("verify failed")
	if err := verifyStrategy(context.Background(), simpleStrategy{algorithm: "SIMPLE", verifyErr: verifyErr}, []byte("input"), []byte("signature")); !errors.Is(err, verifyErr) {
		t.Fatalf("expected verify error, got %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := signStrategy(ctx, simpleStrategy{algorithm: "SIMPLE"}, []byte("input")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled sign, got %v", err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	waitCtx, waitCancel := context.WithCancel(context.Background())
	go func() {
		<-started
		waitCancel()
	}()
	_, err = runStrategyWithContext(waitCtx, func() (string, error) {
		close(started)
		<-release
		return "late", nil
	})
	close(release)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled from waiting operation, got %v", err)
	}
}

func TestSignatureErrorPreservesContextErrors(t *testing.T) {
	if err := signatureError(context.Canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if err := signatureError(context.DeadlineExceeded); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
	if err := signatureError(errors.New("crypto")); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

func buildRawToken(t *testing.T, header Header, claims any, signature []byte) string {
	t.Helper()

	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("expected header json without error, got %v", err)
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("expected claims json without error, got %v", err)
	}

	return fmt.Sprintf("%s.%s.%s", encodeSegment(headerBytes), encodeSegment(claimsBytes), encodeSegment(signature))
}

func buildRawTokenFromParts(t *testing.T, header Header, claimsPart string, signaturePart string) string {
	t.Helper()

	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("expected header json without error, got %v", err)
	}

	return fmt.Sprintf("%s.%s.%s", encodeSegment(headerBytes), claimsPart, signaturePart)
}

func unmarshalClaims(raw []byte, destination any) error {
	return json.Unmarshal(raw, destination)
}
