// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package middlewares groups logger middleware subpackages.
//
// Use the http subpackage for Gin middleware and the grpc subpackage for gRPC
// server interceptors. Shared context keys live in the root logger/common
// package.
//
// Main entry points:
//   - middlewares/http.InitLogger to initialize the request-scoped logger context for Gin
//   - middlewares/http.LoggerWithConfig to emit the final structured HTTP log entry
//   - middlewares/grpc.InitLoggerUnaryServerInterceptor for unary gRPC requests
//   - middlewares/grpc.InitLoggerStreamServerInterceptor for streaming gRPC requests
package middlewares
