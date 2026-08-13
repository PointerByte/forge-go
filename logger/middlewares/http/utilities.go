// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/PointerByte/forge-go/logger/common"
	"github.com/gin-gonic/gin"
)

// EnableBody marks whether the final Gin request log should include request
// and response bodies independently.
//
// Internally it stores the inverse disable flags in the gin.Context so
// LoggerWithConfig can decide what to copy into details.request and
// details.response.
func EnableBody(ctx *gin.Context, enableRequestBody bool, enableResponseBody bool) {
	ctx.Set(common.DisableRequestBodyKey, !enableRequestBody)
	ctx.Set(common.DisableResponseBodyKey, !enableResponseBody)
}

// EnableTraceBody marks whether downstream trace services should include their
// request and response bodies when the current request-scoped logger finishes a
// trace with builder.Context.TraceEnd.
//
// Unlike EnableBody, these flags are stored only in the logger context because
// they control formatter.Service trace entries, not the final Gin access log.
func EnableTraceBody(ctx *gin.Context, enableRequestBody bool, enableResponseBody bool) {
	ctxLogger := builder.New(ctx.Request.Context())
	ctxLogger.Set(common.DisableTraceRequestBodyKey, !enableRequestBody)
	ctxLogger.Set(common.DisableTraceResponseBodyKey, !enableResponseBody)
}
