// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package cookies provides cookie-based authentication helpers built on top of
// the JWT service from the security module.
//
// It extracts a JWT from an HTTP cookie, validates it through a jwt.Service,
// and exposes helpers that can be reused by middleware or application code.
//
// Main entry points:
//   - New to build a Service from explicit options
//   - NewConfiguredService to build a Service from viper-backed configuration
//   - TokenFromRequest to extract the raw token from an HTTP request
//   - Decode to validate the token and unmarshal its claims
package cookies
