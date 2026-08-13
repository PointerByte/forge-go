// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package middlewares

import (
	"net/http"

	cookiesauth "github.com/PointerByte/forge-go/security/auth/cookies"
	jwtservice "github.com/PointerByte/forge-go/security/auth/jwt"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// CookieMiddlewareOption customizes cookie-based JWT middleware behavior.
type CookieMiddlewareOption func(*cookieMiddlewareConfig)

type cookieMiddlewareConfig struct {
	tokenContextKey     GinContextKey
	claimsContextKey    GinContextKey
	claimsFactory       ClaimsFactory
	validator           jwtservice.Validator
	serviceConfig       cookiesauth.ConfigServiceInput
	serviceFactory      func(cookiesauth.ConfigServiceInput) (*cookiesauth.Service, error)
	unauthorizedHandler func(*gin.Context, error)
}

// RequireJWTCookie returns a Gin middleware that extracts a JWT from a cookie,
// validates it, and stores the parsed token and claims in the Gin context.
func RequireJWTCookie(options ...CookieMiddlewareOption) gin.HandlerFunc {
	if viper.IsSet("jwt.enable") && !viper.GetBool("jwt.enable") {
		return func(ctx *gin.Context) {
			ctx.Next()
		}
	}

	config := cookieMiddlewareConfig{
		tokenContextKey:  JWTTokenContextKey,
		claimsContextKey: JWTClaimsContextKey,
		serviceFactory:   cookiesauth.NewConfiguredService,
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

	if config.validator != nil {
		config.serviceConfig.JWT.Validator = config.validator
	}

	service, err := config.serviceFactory(config.serviceConfig)
	if err != nil {
		return func(c *gin.Context) {
			config.unauthorizedHandler(c, err)
		}
	}

	return func(c *gin.Context) {
		defaultClaims := map[string]any{}
		var destination any = &defaultClaims
		storedClaims := any(defaultClaims)

		if config.claimsFactory != nil {
			destination = config.claimsFactory()
			storedClaims = destination
		}

		parsedToken, err := service.Decode(c.Request.Context(), c.Request, destination)
		if err != nil {
			config.unauthorizedHandler(c, err)
			return
		}

		c.Set(config.tokenContextKey.String(), parsedToken)
		c.Set(config.claimsContextKey.String(), storedClaims)
		c.Next()
	}
}

// WithJWTCookieServiceConfig customizes how the cookie middleware builds its
// auth service from viper-backed configuration.
func WithJWTCookieServiceConfig(input cookiesauth.ConfigServiceInput) CookieMiddlewareOption {
	return func(config *cookieMiddlewareConfig) {
		config.serviceConfig = input
	}
}

// WithJWTCookieValidator registers an extra validator for the internally built
// JWT service used by the cookie middleware.
func WithJWTCookieValidator(validator jwtservice.Validator) CookieMiddlewareOption {
	return func(config *cookieMiddlewareConfig) {
		config.validator = validator
	}
}

// WithJWTCookieClaimsFactory configures the claims destination created per
// request.
func WithJWTCookieClaimsFactory(factory ClaimsFactory) CookieMiddlewareOption {
	return func(config *cookieMiddlewareConfig) {
		config.claimsFactory = factory
	}
}

// WithJWTCookieContextKeys overrides the Gin context keys used to store the
// parsed token and decoded claims.
func WithJWTCookieContextKeys(tokenKey GinContextKey, claimsKey GinContextKey) CookieMiddlewareOption {
	return func(config *cookieMiddlewareConfig) {
		if tokenKey != GinContextKey("") {
			config.tokenContextKey = tokenKey
		}
		if claimsKey != GinContextKey("") {
			config.claimsContextKey = claimsKey
		}
	}
}

// WithJWTCookieUnauthorizedHandler overrides the default 401 JSON response.
func WithJWTCookieUnauthorizedHandler(handler func(*gin.Context, error)) CookieMiddlewareOption {
	return func(config *cookieMiddlewareConfig) {
		if handler != nil {
			config.unauthorizedHandler = handler
		}
	}
}
