// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/PointerByte/forge-go/logger/common"
)

// EnableBody marks whether the final gRPC request log should include request
// and response bodies independently.
//
// Internally it stores the inverse disable flags in the request-scoped logger
// context so LoggerWithConfig can decide what to copy into details.request and
// details.response.
func EnableBody(ctxLogger *builder.Context, enableRequestBody bool, enableResponseBody bool) {
	ctxLogger.Set(common.DisableRequestBodyKey, !enableRequestBody)
	ctxLogger.Set(common.DisableResponseBodyKey, !enableResponseBody)
}

// EnableTraceBody marks whether downstream trace services should include their
// request and response bodies when builder.Context.TraceEnd finishes a trace.
func EnableTraceBody(ctxLogger *builder.Context, enableRequestBody bool, enableResponseBody bool) {
	ctxLogger.Set(common.DisableTraceRequestBodyKey, !enableRequestBody)
	ctxLogger.Set(common.DisableTraceResponseBodyKey, !enableResponseBody)
}
