// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package middlewares

import (
	"context"
	"strings"
	"sync"

	jwtservice "github.com/PointerByte/forge-go/security/auth/jwt"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const defaultGRPCAuthorizationMetadata = "authorization"

type jwtContextKey string

const (
	jwtTokenContextKey  jwtContextKey = "jwt.token"
	jwtClaimsContextKey jwtContextKey = "jwt.claims"
)

// JWTGRPCOption customizes gRPC JWT interceptors.
type JWTGRPCOption func(*jwtGRPCConfig)

type jwtGRPCConfig struct {
	metadataName   string
	bearerPrefix   string
	claimsFactory  ClaimsFactory
	validator      jwtservice.Validator
	serviceFactory func(*jwtservice.Validator) (*jwtservice.Service, error)

	once       sync.Once
	service    *jwtservice.Service
	serviceErr error
}

// JWTTokenFromContext returns the parsed JWT stored by a gRPC JWT interceptor.
func JWTTokenFromContext(ctx context.Context) (*jwtservice.Token, bool) {
	token, ok := ctx.Value(jwtTokenContextKey).(*jwtservice.Token)
	return token, ok
}

// JWTClaimsFromContext returns the decoded claims stored by a gRPC JWT
// interceptor. The concrete type depends on WithGRPCJWTClaimsFactory; without a
// factory it is map[string]any.
func JWTClaimsFromContext(ctx context.Context) (any, bool) {
	claims := ctx.Value(jwtClaimsContextKey)
	return claims, claims != nil
}

// RequireJWTUnaryServerInterceptor validates bearer JWTs from incoming gRPC
// metadata and stores the parsed token and decoded claims in context.
func RequireJWTUnaryServerInterceptor(options ...JWTGRPCOption) grpc.UnaryServerInterceptor {
	config := newJWTGRPCConfig(options...)
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if viper.IsSet("jwt.enable") && !viper.GetBool("jwt.enable") {
			return handler(ctx, req)
		}

		authCtx, err := config.authenticate(ctx)
		if err != nil {
			return nil, grpcJWTError(err)
		}
		return handler(authCtx, req)
	}
}

// RequireJWTStreamServerInterceptor validates bearer JWTs from incoming gRPC
// stream metadata and stores the parsed token and decoded claims in context.
func RequireJWTStreamServerInterceptor(options ...JWTGRPCOption) grpc.StreamServerInterceptor {
	config := newJWTGRPCConfig(options...)
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if viper.IsSet("jwt.enable") && !viper.GetBool("jwt.enable") {
			return handler(srv, stream)
		}

		authCtx, err := config.authenticate(stream.Context())
		if err != nil {
			return grpcJWTError(err)
		}
		return handler(srv, &jwtServerStream{ServerStream: stream, ctx: authCtx})
	}
}

// WithGRPCJWTServiceFactory overrides the service constructor used by gRPC JWT
// interceptors. It is useful for custom JWT strategies that are not viper-backed.
func WithGRPCJWTServiceFactory(factory func(*jwtservice.Validator) (*jwtservice.Service, error)) JWTGRPCOption {
	return func(config *jwtGRPCConfig) {
		if factory != nil {
			config.serviceFactory = factory
		}
	}
}

// WithGRPCJWTValidator registers an extra validator for the service built by
// gRPC JWT interceptors.
func WithGRPCJWTValidator(validator jwtservice.Validator) JWTGRPCOption {
	return func(config *jwtGRPCConfig) {
		config.validator = validator
	}
}

// WithGRPCJWTClaimsFactory configures the claims destination created per gRPC
// request or stream.
func WithGRPCJWTClaimsFactory(factory ClaimsFactory) JWTGRPCOption {
	return func(config *jwtGRPCConfig) {
		config.claimsFactory = factory
	}
}

func newJWTGRPCConfig(options ...JWTGRPCOption) *jwtGRPCConfig {
	config := &jwtGRPCConfig{
		metadataName:   defaultGRPCAuthorizationMetadata,
		bearerPrefix:   defaultBearerPrefix,
		serviceFactory: newConfiguredJWTService,
	}
	for _, option := range options {
		if option == nil {
			continue
		}
		option(config)
	}
	return config
}

func (config *jwtGRPCConfig) authenticate(ctx context.Context) (context.Context, error) {
	service, err := config.resolveService()
	if err != nil {
		return nil, err
	}
	if service == nil {
		return nil, ErrNilJWTService
	}

	token, err := tokenFromIncomingMetadata(ctx, config.metadataName, config.bearerPrefix)
	if err != nil {
		return nil, err
	}

	defaultClaims := map[string]any{}
	var destination any = &defaultClaims
	storedClaims := any(defaultClaims)

	if config.claimsFactory != nil {
		destination = config.claimsFactory()
		storedClaims = destination
	}

	parsedToken, err := service.Decode(ctx, token, destination)
	if err != nil {
		return nil, err
	}

	ctx = context.WithValue(ctx, jwtTokenContextKey, parsedToken)
	ctx = context.WithValue(ctx, jwtClaimsContextKey, storedClaims)
	return ctx, nil
}

func (config *jwtGRPCConfig) resolveService() (*jwtservice.Service, error) {
	config.once.Do(func() {
		config.service, config.serviceErr = config.serviceFactory(jwtValidatorPtr(config.validator))
	})
	return config.service, config.serviceErr
}

func tokenFromIncomingMetadata(ctx context.Context, metadataName string, bearerPrefix string) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrMissingAuthorization
	}

	values := md.Get(strings.ToLower(strings.TrimSpace(metadataName)))
	if len(values) == 0 {
		return "", ErrMissingAuthorization
	}
	return extractBearerToken(values[0], bearerPrefix)
}

func grpcJWTError(err error) error {
	return status.Error(codes.Unauthenticated, err.Error())
}

type jwtServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (stream *jwtServerStream) Context() context.Context {
	return stream.ctx
}
