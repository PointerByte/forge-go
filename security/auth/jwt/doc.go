// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package jwt provides JWT creation, signing, decoding, and validation helpers
// for the security module.
//
// It supports multiple signing strategies, including HMAC, RSA, RSA-PSS, and
// Ed25519. After signature verification it validates present exp and nbf
// NumericDate claims, then lets applications attach custom validation callbacks
// for policies such as expected issuers and audiences.
//
// Main entry points:
//   - New to build a Service from explicit options
//   - NewConfiguredService to build a Service from viper-backed configuration
//   - Encode to create a signed token from claims
//   - Decode to validate a token and unmarshal claims into a destination value
//
// The package is transport-agnostic and can be used directly by HTTP handlers,
// gRPC services, or higher-level authentication middleware.
package jwt
