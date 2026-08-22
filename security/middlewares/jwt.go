// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package middlewares

import (
	"errors"
	"net/http"
	"strings"

	jwtservice "github.com/PointerByte/forge-go/security/auth/jwt"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

const (
	defaultAuthorizationHeader = "Authorization"
	defaultBearerPrefix        = "Bearer "
)

// GinContextKey represents a typed key used to store values in a Gin context.
type GinContextKey string

// String returns the string value stored in Gin's context map.
func (key GinContextKey) String() string {
	return string(key)
}

const (
	JWTTokenContextKey  GinContextKey = "jwt.token"
	JWTClaimsContextKey GinContextKey = "jwt.claims"
)

var (
	ErrNilJWTService            = errors.New("middlewares: jwt service is required")
	ErrMissingAuthorization     = errors.New("middlewares: authorization header is required")
	ErrInvalidAuthorizationType = errors.New("middlewares: authorization header must use Bearer scheme")
)

// ClaimsFactory creates a destination value where JWT claims will be decoded
// before being stored in the Gin context.
type ClaimsFactory func() any

// JWTMiddlewareOption customizes the JWT middleware behavior.
type JWTMiddlewareOption func(*jwtMiddlewareConfig)

type jwtMiddlewareConfig struct {
	headerName          string
	bearerPrefix        string
	tokenContextKey     GinContextKey
	claimsContextKey    GinContextKey
	claimsFactory       ClaimsFactory
	validator           jwtservice.Validator
	service             *jwtservice.Service
	unauthorizedHandler func(*gin.Context, error)
}

// RequireJWT returns a Gin middleware that extracts a Bearer token from the
// request, validates it through the JWT service, and stores the parsed token
// and decoded claims in the Gin context.
//
// By default, claims are decoded into a map[string]any and stored under the
// JWTClaimsContextKey, while the parsed token is stored under JWTTokenContextKey.
func RequireJWT(options ...JWTMiddlewareOption) gin.HandlerFunc {
	if viper.IsSet("jwt.enable") && !viper.GetBool("jwt.enable") {
		return func(ctx *gin.Context) {
			ctx.Next()
		}
	}

	config := jwtMiddlewareConfig{
		headerName:       defaultAuthorizationHeader,
		bearerPrefix:     defaultBearerPrefix,
		tokenContextKey:  JWTTokenContextKey,
		claimsContextKey: JWTClaimsContextKey,
		unauthorizedHandler: func(c *gin.Context, err error) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
			})
		},
	}

	for _, option := range options {
		if option == nil {
			continue
		}
		option(&config)
	}

	service := config.service
	if service == nil {
		var err error
		service, err = newConfiguredJWTService(jwtValidatorPtr(config.validator))
		if err != nil {
			return func(c *gin.Context) {
				config.unauthorizedHandler(c, err)
			}
		}
	}

	return func(c *gin.Context) {
		if service == nil {
			config.unauthorizedHandler(c, ErrNilJWTService)
			return
		}

		token, err := extractBearerToken(c.GetHeader(config.headerName), config.bearerPrefix)
		if err != nil {
			config.unauthorizedHandler(c, err)
			return
		}

		defaultClaims := map[string]any{}
		var destination any = &defaultClaims
		storedClaims := any(defaultClaims)

		if config.claimsFactory != nil {
			destination = config.claimsFactory()
			storedClaims = destination
		}

		parsedToken, err := service.Decode(c.Request.Context(), token, destination)
		if err != nil {
			config.unauthorizedHandler(c, err)
			return
		}

		c.Set(config.tokenContextKey.String(), parsedToken)
		c.Set(config.claimsContextKey.String(), storedClaims)
		c.Next()
	}
}

// WithJWTService injects the JWT service used by the middleware. This is useful
// for custom JWT strategies that are not viper-backed.
func WithJWTService(service *jwtservice.Service) JWTMiddlewareOption {
	return func(config *jwtMiddlewareConfig) {
		if service != nil {
			config.service = service
		}
	}
}

// WithJWTValidator registers an extra validator for the service built by the
// middleware.
func WithJWTValidator(validator jwtservice.Validator) JWTMiddlewareOption {
	return func(config *jwtMiddlewareConfig) {
		config.validator = validator
	}
}

// WithJWTClaimsFactory configures the claims destination created per request.
// This is useful when handlers expect a strongly typed claims struct.
func WithJWTClaimsFactory(factory ClaimsFactory) JWTMiddlewareOption {
	return func(config *jwtMiddlewareConfig) {
		config.claimsFactory = factory
	}
}

// WithJWTContextKeys overrides the Gin context keys used to store the parsed
// token and decoded claims.
func WithJWTContextKeys(tokenKey GinContextKey, claimsKey GinContextKey) JWTMiddlewareOption {
	return func(config *jwtMiddlewareConfig) {
		if tokenKey != GinContextKey("") {
			config.tokenContextKey = tokenKey
		}
		if claimsKey != GinContextKey("") {
			config.claimsContextKey = claimsKey
		}
	}
}

// WithJWTUnauthorizedHandler overrides the default 401 JSON response emitted
// when token extraction or validation fails.
func WithJWTUnauthorizedHandler(handler func(*gin.Context, error)) JWTMiddlewareOption {
	return func(config *jwtMiddlewareConfig) {
		if handler != nil {
			config.unauthorizedHandler = handler
		}
	}
}

func extractBearerToken(headerValue string, bearerPrefix string) (string, error) {
	if headerValue == "" {
		return "", ErrMissingAuthorization
	}

	if !strings.HasPrefix(headerValue, bearerPrefix) {
		return "", ErrInvalidAuthorizationType
	}

	token := strings.TrimSpace(strings.TrimPrefix(headerValue, bearerPrefix))
	if token == "" {
		return "", ErrMissingAuthorization
	}
	return token, nil
}

func newConfiguredJWTService(validator *jwtservice.Validator) (*jwtservice.Service, error) {
	return jwtservice.NewConfiguredService(validator)
}

func jwtValidatorPtr(validator jwtservice.Validator) *jwtservice.Validator {
	if validator == nil {
		return nil
	}
	return &validator
}
