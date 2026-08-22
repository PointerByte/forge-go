// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package middlewares provides reusable Gin security middleware for the
// security module.
//
// It includes:
//   - JWT Bearer authentication middleware
//   - cookie-based JWT authentication middleware
//   - common HTTP security headers
//
// The authentication middlewares validate the incoming token, decode claims,
// and store both the parsed token and the claims in the Gin context so handlers
// can consume them without repeating auth logic.
//
// Main entry points:
//   - RequireJWT for Authorization header validation
//   - RequireJWTCookie for cookie-based token validation
//   - SecurityHeaders for standard defensive HTTP headers
package middlewares
