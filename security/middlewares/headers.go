// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package middlewares

import "github.com/gin-gonic/gin"

// SecurityHeaders returns a Gin middleware that adds a set of common HTTP
// security headers to every response.
//
// It currently sets:
//   - X-Frame-Options to reduce clickjacking risk.
//   - Content-Security-Policy to restrict allowed content sources.
//   - X-XSS-Protection to enable legacy XSS browser protections.
//   - Strict-Transport-Security to enforce HTTPS on future requests.
//   - Referrer-Policy to control referrer information.
//   - X-Content-Type-Options to disable MIME type sniffing.
//   - Permissions-Policy to limit access to browser capabilities.
//
// This middleware should be placed early in the chain so the headers are added
// consistently to protected routes.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("Content-Security-Policy", "default-src 'self'; connect-src *; font-src *; script-src-elem * 'unsafe-inline'; img-src * data:; style-src * 'unsafe-inline';")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Referrer-Policy", "strict-origin")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Permissions-Policy", "geolocation=(),midi=(),sync-xhr=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()")
		c.Next()
	}
}
