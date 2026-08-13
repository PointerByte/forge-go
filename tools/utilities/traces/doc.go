// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package traces configures OpenTelemetry tracing and metrics for the config
// module.
//
// It centralizes three concerns:
//   - initialization of tracer and meter providers from OTEL_* environment variables
//   - construction of OpenTelemetry resources using application metadata from Viper
//   - middleware and interceptor wiring for Gin and gRPC server instrumentation
//
// Main entry points:
//   - InitOtel to install global tracer and meter providers
//   - MiddlewareOtel to instrument incoming Gin requests
//   - MiddlewareOtelGRPCUnary to instrument unary gRPC handlers
//   - MiddlewareOtelGRPCStream to instrument streaming gRPC handlers
package traces
