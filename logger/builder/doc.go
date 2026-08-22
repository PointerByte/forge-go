// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package builder provides the runtime integration layer for the logger.
//
// It contains the pieces most applications use directly:
//   - logger initialization through InitLogger
//   - request-scoped context creation through MiddlewareInitLogger
//   - HTTP log emission through MiddlewareLoggerWithConfig
//   - request/response body capture through MiddlewareCaptureBody
//   - convenience logging helpers for Gin handlers
//
// Body capture and body emission are intentionally separate concerns:
// MiddlewareCaptureBody stores the raw request and response payloads in the
// gin.Context, while MiddlewareLoggerWithConfig decides whether those payloads
// are copied into the final structured log.
//
// Request and response bodies are omitted from final log entries by default.
// To include them for a given request, use the HTTP or gRPC middleware helper
// EnableBody before the log formatter is executed.
package builder
