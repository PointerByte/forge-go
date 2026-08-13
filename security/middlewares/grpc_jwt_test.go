// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package middlewares

import (
	"context"
	"encoding/json"
	"testing"

	jwtservice "github.com/PointerByte/forge-go/security/auth/jwt"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestRequireJWTUnaryServerInterceptorAllowsValidBearerToken(t *testing.T) {
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

	interceptor := RequireJWTUnaryServerInterceptor(
		WithGRPCJWTClaimsFactory(func() any { return &jwtClaims{} }),
		WithGRPCJWTValidator(func(ctx context.Context, token jwtservice.Token) error {
			var claims jwtClaims
			return json.Unmarshal(token.Claims, &claims)
		}),
	)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	handlerCalled := false
	_, err = interceptor(ctx, "request", &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, func(ctx context.Context, req any) (any, error) {
		handlerCalled = true

		claimsValue, ok := JWTClaimsFromContext(ctx)
		if !ok {
			t.Fatal("expected claims in context")
		}
		claims, ok := claimsValue.(*jwtClaims)
		if !ok {
			t.Fatalf("expected *jwtClaims in context, got %T", claimsValue)
		}
		if claims.UserID != "42" {
			t.Fatalf("expected user id 42, got %s", claims.UserID)
		}
		if _, ok := JWTTokenFromContext(ctx); !ok {
			t.Fatal("expected parsed token in context")
		}
		return "response", nil
	})
	if err != nil {
		t.Fatalf("expected interceptor without error, got %v", err)
	}
	if !handlerCalled {
		t.Fatal("expected handler to be called")
	}
}

func TestRequireJWTUnaryServerInterceptorRejectsMissingAuthorization(t *testing.T) {
	configureMiddlewareJWT()
	defer viper.Reset()

	interceptor := RequireJWTUnaryServerInterceptor()
	handlerCalled := false
	_, err := interceptor(context.Background(), "request", &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, func(ctx context.Context, req any) (any, error) {
		handlerCalled = true
		return nil, nil
	})
	if handlerCalled {
		t.Fatal("expected handler not to be called")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v from %v", status.Code(err), err)
	}
}

func TestRequireJWTStreamServerInterceptorAllowsValidBearerToken(t *testing.T) {
	configureMiddlewareJWT()
	defer viper.Reset()

	service, err := jwtservice.NewConfiguredService(nil)
	if err != nil {
		t.Fatalf("expected jwt service without error, got %v", err)
	}
	token, err := service.Create(jwtClaims{UserID: "7", Role: "reader"})
	if err != nil {
		t.Fatalf("expected token without error, got %v", err)
	}

	interceptor := RequireJWTStreamServerInterceptor(
		WithGRPCJWTClaimsFactory(func() any { return &jwtClaims{} }),
	)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	stream := &testServerStream{ctx: ctx}
	handlerCalled := false
	err = interceptor(nil, stream, &grpc.StreamServerInfo{}, func(srv any, stream grpc.ServerStream) error {
		handlerCalled = true
		claimsValue, ok := JWTClaimsFromContext(stream.Context())
		if !ok {
			t.Fatal("expected claims in stream context")
		}
		claims, ok := claimsValue.(*jwtClaims)
		if !ok {
			t.Fatalf("expected *jwtClaims in stream context, got %T", claimsValue)
		}
		if claims.UserID != "7" {
			t.Fatalf("expected user id 7, got %s", claims.UserID)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected stream interceptor without error, got %v", err)
	}
	if !handlerCalled {
		t.Fatal("expected stream handler to be called")
	}
}

type testServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (stream *testServerStream) Context() context.Context {
	return stream.ctx
}
