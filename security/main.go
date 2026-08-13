// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	jwtservice "github.com/PointerByte/forge-go/security/auth/jwt"
	"github.com/PointerByte/forge-go/security/middlewares"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// No use in production!
const demoJWTSecret = "oXPZp-Y9yu2zmfECMU*_"     // #nosec G101 -- example-only secret for the demo server, not used in production
const demoCustomJWTSecret = "custom-demo-secret" // #nosec G101 -- example-only secret for the demo server, not used in production

const (
	hmacAlgorithmKey = "jwt.hmac.algorithm"
	hmacSecretKey    = jwtservice.DefaultHMACSecretKey
	rsaAlgorithmKey  = "jwt.rsa.algorithm"
	rsaPrivateKeyKey = jwtservice.DefaultJWTPrivateKeyKey
	rsaPublicKeyKey  = jwtservice.DefaultJWTPublicKeyKey
)

// Example requests:
//
//  1. Start the server:
//     go run .
//
//  2. Request an HMAC token:
//     curl -X POST http://localhost:8080/hmac/login ^
//     -H "Content-Type: application/json" ^
//     -d "{\"user_id\":\"42\",\"role\":\"admin\"}"
//
//  3. Call an HMAC protected endpoint with the returned token:
//     curl http://localhost:8080/hmac/api/me ^
//     -H "Authorization: Bearer <HMAC_TOKEN>"
//
//  4. Request an RSA token:
//     curl -X POST http://localhost:8080/rsa/login ^
//     -H "Content-Type: application/json" ^
//     -d "{\"user_id\":\"42\",\"role\":\"admin\"}"
//
//  5. Call an RSA protected endpoint with the returned token:
//     curl http://localhost:8080/rsa/api/admin ^
//     -H "Authorization: Bearer <RSA_TOKEN>"
//
//  6. Try a blocked user to see the extra validator reject the token:
//     curl -X POST http://localhost:8080/hmac/login ^
//     -H "Content-Type: application/json" ^
//     -d "{\"user_id\":\"blocked-user\",\"role\":\"admin\"}"
//
//     Then use that token on /hmac/api/me or /rsa/api/me and the validator
//     validateActiveSession will reject the request.
//
//  7. Request a custom-strategy token:
//     curl -X POST http://localhost:8080/custom/login ^
//     -H "Content-Type: application/json" ^
//     -d "{\"user_id\":\"42\",\"role\":\"admin\"}"
//
//  8. Call a custom-strategy protected endpoint:
//     curl http://localhost:8080/custom/api/me ^
//     -H "Authorization: Bearer <CUSTOM_TOKEN>"
type loginRequest struct {
	UserID string `json:"user_id" binding:"required"`
	Role   string `json:"role" binding:"required"`
}

type sessionClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

var (
	runRouterFn = func(router *gin.Engine) error {
		return router.Run(":8080")
	}
	logFatalfFn = log.Fatalf
)

func main() {
	if err := runApp(); err != nil {
		logFatalfFn("application startup failed: %v", err)
	}
}

func runApp() error {
	configureViper()

	if err := ensureDefaultHMACSecret(); err != nil {
		return fmt.Errorf("prepare hmac config: %w", err)
	}

	if err := ensureDefaultRSAKeys(); err != nil {
		return fmt.Errorf("prepare rsa config: %w", err)
	}

	router := newRouter()
	if err := runRouterFn(router); err != nil {
		return fmt.Errorf("run gin server: %w", err)
	}
	return nil
}

func ensureDefaultHMACSecret() error {
	if viper.GetString(hmacSecretKey) != "" {
		return nil
	}
	viper.Set(hmacSecretKey, demoJWTSecret)
	return nil
}

func ensureDefaultRSAKeys() error {
	if hasUsableRSAConfig(viper.GetString(rsaPrivateKeyKey), viper.GetString(rsaPublicKeyKey)) {
		return nil
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	viper.Set(rsaPrivateKeyKey, base64.StdEncoding.EncodeToString(privateDER))
	viper.Set(rsaPublicKeyKey, base64.StdEncoding.EncodeToString(publicDER))
	return nil
}

func hasUsableRSAConfig(privateKey string, publicKey string) bool {
	return hasUsableRSAConfigValue(privateKey) && hasUsableRSAConfigValue(publicKey)
}

func hasUsableRSAConfigValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if strings.HasSuffix(strings.ToLower(value), ".pem") {
		_, err := os.Stat(value)
		return err == nil
	}
	return true
}

func configureViper() {
	viper.SetDefault(hmacAlgorithmKey, "HS256")
	viper.SetDefault(rsaAlgorithmKey, "RS256")
}

func newRouter() *gin.Engine {
	configureViper()

	router := gin.Default()
	router.Use(middlewares.SecurityHeaders())

	router.GET("/health", healthHandler(""))
	registerJWTExampleRoutes(router.Group("/hmac"))
	registerJWTExampleRoutes(router.Group("/rsa"))
	registerJWTExampleRoutes(router.Group("/custom"))
	return router
}

func registerJWTExampleRoutes(group *gin.RouterGroup) {
	jwtService, jwtMiddlewareService, exampleName := jwtExampleServicesAndName(group.BasePath())

	group.GET("/health", healthHandler(exampleName))
	group.POST("/login", loginHandler(jwtService))

	jwtMiddlewareOptions := []middlewares.JWTMiddlewareOption{
		middlewares.WithJWTClaimsFactory(func() any { return &sessionClaims{} }),
		middlewares.WithJWTValidator(validateActiveSession),
	}
	if jwtMiddlewareService != nil {
		jwtMiddlewareOptions = append(jwtMiddlewareOptions, middlewares.WithJWTService(jwtMiddlewareService))
	}

	protected := group.Group("/api")
	protected.Use(middlewares.RequireJWT(jwtMiddlewareOptions...))
	protected.GET("/me", meHandler(exampleName))
	protected.GET("/admin", adminHandler(exampleName))
}

func jwtExampleServicesAndName(basePath string) (*jwtservice.Service, *jwtservice.Service, string) {
	lowerBasePath := strings.ToLower(basePath)
	if strings.Contains(lowerBasePath, "rsa") {
		return configuredJWTExampleServices(basePath, "RS256", "RSA / RS256")
	}
	if strings.Contains(lowerBasePath, "custom") {
		loginService, err := newCustomJWTService(nil)
		if err != nil {
			panic(fmt.Sprintf("build jwt service for %s: %v", basePath, err))
		}

		validator := jwtservice.Validator(validateActiveSession)
		middlewareService, err := newCustomJWTService(&validator)
		if err != nil {
			panic(fmt.Sprintf("build jwt middleware service for %s: %v", basePath, err))
		}
		return loginService, middlewareService, "Custom / CUSTOM"
	}
	return configuredJWTExampleServices(basePath, "HS256", "HMAC / HS256")
}

func configuredJWTExampleServices(basePath string, algorithm string, exampleName string) (*jwtservice.Service, *jwtservice.Service, string) {
	viper.Set(jwtservice.DefaultAlgorithmKey, algorithm)
	service, err := jwtservice.NewConfiguredService(nil)
	if err != nil {
		panic(fmt.Sprintf("build jwt service for %s: %v", basePath, err))
	}
	return service, nil, exampleName
}

func newCustomJWTService(validator *jwtservice.Validator) (*jwtservice.Service, error) {
	options := []jwtservice.Option{
		jwtservice.WithCustomStrategy("CUSTOM", customJWTSign, customJWTVerify),
	}
	if validator != nil {
		options = append(options, jwtservice.WithValidator(*validator))
	}
	return jwtservice.New(options...)
}

func customJWTSign(ctx context.Context, signingInput []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, []byte(demoCustomJWTSecret))
	if _, err := mac.Write(signingInput); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

func customJWTVerify(ctx context.Context, signingInput []byte, signature []byte) error {
	expectedSignature, err := customJWTSign(ctx, signingInput)
	if err != nil {
		return err
	}
	if !hmac.Equal(signature, expectedSignature) {
		return jwtservice.ErrInvalidSignature
	}
	return nil
}

func healthHandler(exampleName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		response := gin.H{"status": "ok"}
		if exampleName != "" {
			response["example"] = exampleName
		}
		c.JSON(http.StatusOK, response)
	}
}

func loginHandler(jwtService *jwtservice.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request loginRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid login payload",
			})
			return
		}

		token, err := jwtService.Create(sessionClaims(request))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "could not create token",
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"token": token,
		})
	}
}

func meHandler(exampleName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := claimsFromContext(c)
		if !ok {
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"example": exampleName,
			"user_id": claims.UserID,
			"role":    claims.Role,
		})
	}
}

func adminHandler(exampleName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := claimsFromContext(c)
		if !ok {
			return
		}

		if claims.Role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "admin role required",
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"example": exampleName,
			"message": "welcome admin",
		})
	}
}

func claimsFromContext(c *gin.Context) (*sessionClaims, bool) {
	claimsValue, _ := c.Get(middlewares.JWTClaimsContextKey.String())
	claims, ok := claimsValue.(*sessionClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "claims not available in context",
		})
		return nil, false
	}
	return claims, true
}

func validateActiveSession(ctx context.Context, token jwtservice.Token) error {
	var claims sessionClaims
	if err := json.Unmarshal(token.Claims, &claims); err != nil {
		return err
	}

	// Example of an extra validation hook, such as a database lookup.
	if claims.UserID == "blocked-user" {
		return errors.New("user session is blocked")
	}
	return nil
}
