// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package common

// InstrumentationName is the OpenTelemetry instrumentation scope reported by
// every span this module starts. A scope names the instrumentation library; the
// service identity travels in the resource, not in the scope.
const InstrumentationName = "github.com/PointerByte/forge-go/logger"

type KeyContex string

const (
	TraceIDHeader                         = "X-Trace-Id"
	TraceIDKey                  KeyContex = "traceID"
	DetailsKey                  KeyContex = "details"
	DisableRequestBodyKey       KeyContex = "disableRequestBody"
	DisableResponseBodyKey      KeyContex = "disableResponseBody"
	DisableTraceRequestBodyKey  KeyContex = "disableTraceRequestBody"
	DisableTraceResponseBodyKey KeyContex = "disableTraceResponseBody"
	RequestbodyKey              KeyContex = "requestBody"
	ResponsebodyKey             KeyContex = "responseBody"
	RequestBodyCaptureKey       KeyContex = "requestBodyCapture"
	ResponseBodyCaptureKey      KeyContex = "responseBodyCapture"
	MethodKey                   KeyContex = "method"
	LineKey                     KeyContex = "line"
)
