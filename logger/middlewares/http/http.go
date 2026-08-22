// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/PointerByte/forge-go/logger/common"
	"github.com/PointerByte/forge-go/logger/formatter"
	"github.com/PointerByte/forge-go/logger/utilities"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// InitLogger creates or reuses the request-scoped logger context and stores the
// base HTTP metadata that will later be used in structured logs.
//
// Tracing ownership: this middleware never creates a second server span. When
// another OpenTelemetry instrumentation already owns the HTTP boundary — the
// otelgin middleware installed by tools/utilities/traces, or any equivalent —
// the request context already carries the server span, and the logger simply
// adopts its trace and span ids. Only when nothing has opened a span does the
// middleware extract the incoming W3C context and start one itself, so the
// logger stays usable standalone without ever producing duplicate spans for a
// single request.
func InitLogger() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// ---- Default disable request and response bodies ----
		ctx.Set(common.DisableRequestBodyKey, true)
		ctx.Set(common.DisableResponseBodyKey, true)

		// ---- Create logger context, owning the span only if nobody else does ----
		parent, span, ownsSpan := serverSpanContext(ctx.Request)
		ctxLogger := builder.New(parent)

		// ---- Get TraceID ----
		// A real trace wins over the legacy correlation header: a structured
		// log must be reachable from the span it was emitted under. The header
		// is honoured only when no span context is available.
		traceID := ""
		if spanContext := span.SpanContext(); spanContext.IsValid() {
			traceID = spanContext.TraceID().String()
			ctxLogger.SetSpanID(spanContext.SpanID().String())
		}
		if traceID == "" {
			traceID = ctx.Request.Header.Get(common.TraceIDHeader)
		}
		if traceID != "" {
			ctxLogger.SetTraceID(traceID)
		}

		details := formatter.Details{
			System:   viperdata.GetViperData(string(viperdata.AppAtribute)).(string),
			Client:   ctx.ClientIP(),
			Protocol: ctx.Request.Proto,
			Method:   ctx.Request.Method,
			Path:     ctx.Request.URL.Path,
		}
		details.SetHeaders(ctx.Request.Header)
		ctxLogger.Set(common.DetailsKey, details)

		// ---- reinyectar contexto con span ----
		ctx.Request = ctx.Request.WithContext(ctxLogger)

		// Continuamos
		ctx.Next()

		// ---- cerrar span al final del request ----
		if ownsSpan {
			span.End()
		}
	}
}

// serverSpanContext returns the context the logger must build on, the span that
// represents the request, and whether this middleware started that span and is
// therefore responsible for ending it.
//
// A span already present in the request context was started in this process by
// whoever owns the HTTP boundary. Re-extracting the remote context on top of it
// would detach the logger from that span and produce a sibling root, so the
// extraction happens only when there is nothing to adopt.
func serverSpanContext(request *http.Request) (context.Context, trace.Span, bool) {
	ctx := request.Context()
	if spanContext := trace.SpanContextFromContext(ctx); spanContext.IsValid() && !spanContext.IsRemote() {
		return ctx, trace.SpanFromContext(ctx), false
	}

	parent := otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(request.Header))
	appName := viperdata.GetViperData(string(viperdata.AppAtribute)).(string)
	ctx, span := otel.Tracer(common.InstrumentationName).Start(
		parent,
		appName,
		trace.WithSpanKind(trace.SpanKindServer),
	)
	return ctx, span, true
}

type responseBodyWriter struct {
	gin.ResponseWriter
	body          *boundedBodyCapture
	shouldCapture func() bool
}

func (r responseBodyWriter) Write(b []byte) (int, error) {
	if r.shouldCapture() {
		_, _ = r.body.Write(b)
	}
	return r.ResponseWriter.Write(b)
}

func (r responseBodyWriter) WriteString(s string) (int, error) {
	if r.shouldCapture() {
		_, _ = r.body.Write([]byte(s))
	}
	return r.ResponseWriter.WriteString(s)
}

type requestBodyCaptureReadCloser struct {
	io.ReadCloser
	body          *boundedBodyCapture
	shouldCapture func() bool
	readBytes     int64
	sawEOF        bool
}

func (r *requestBodyCaptureReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.readBytes += int64(n)
	if err == io.EOF {
		r.sawEOF = true
	}
	if n > 0 && r.shouldCapture() {
		_, _ = r.body.Write(p[:n])
	}
	return n, err
}

func (r *requestBodyCaptureReadCloser) finish(contentLength int64) {
	incomplete := false
	if contentLength >= 0 {
		incomplete = r.readBytes < contentLength
	} else {
		incomplete = !r.sawEOF
	}
	if r.readBytes > int64(r.body.body.Len()) {
		incomplete = true
	}
	if incomplete {
		r.body.truncated = true
	}
}

type boundedBodyCapture struct {
	body      bytes.Buffer
	limit     int
	truncated bool
}

func newBoundedBodyCapture(limit int) *boundedBodyCapture {
	if limit <= 0 {
		limit = viperdata.DefaultBodyCaptureMaxBytes
	}
	return &boundedBodyCapture{limit: limit}
}

func (b *boundedBodyCapture) Write(payload []byte) (int, error) {
	remaining := b.remaining()
	if len(payload) > remaining {
		b.truncated = true
	}
	if remaining > 0 {
		toWrite := len(payload)
		if toWrite > remaining {
			toWrite = remaining
		}
		_, _ = b.body.Write(payload[:toWrite])
	}
	return len(payload), nil
}

func (b *boundedBodyCapture) remaining() int {
	remaining := b.limit - b.body.Len()
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (b *boundedBodyCapture) metadata() *formatter.BodyCaptureMetadata {
	if !b.truncated {
		return nil
	}
	return &formatter.BodyCaptureMetadata{
		Truncated:     true,
		CapturedBytes: b.body.Len(),
		LimitBytes:    b.limit,
	}
}

// CaptureBody captures raw request and response bodies only when body logging
// is enabled for the current request.
//
// Request body capture is lazy: the middleware wraps the request body and only
// stores bytes while the request body flag is enabled. It never drains unread
// request bytes after the handler returns; an unread or only partially read body
// is reported as truncated instead. Each side retains at most
// logger.bodyCaptureMaxBytes and stores truncation metadata when additional
// bytes are observed. Disabled payloads are never retained.
func CaptureBody() gin.HandlerFunc {
	return func(c *gin.Context) {
		maxBytes := viperdata.BodyCaptureMaxBytes()
		requestBody := newBoundedBodyCapture(maxBytes)
		var requestCapture *requestBodyCaptureReadCloser
		if c.Request.Body != nil {
			requestCapture = &requestBodyCaptureReadCloser{
				ReadCloser:    c.Request.Body,
				body:          requestBody,
				shouldCapture: func() bool { return shouldCaptureGinBody(c, common.DisableRequestBodyKey) },
			}
			c.Request.Body = requestCapture
		}

		responseBody := newBoundedBodyCapture(maxBytes)
		writer := &responseBodyWriter{
			ResponseWriter: c.Writer,
			body:           responseBody,
			shouldCapture:  func() bool { return shouldCaptureGinBody(c, common.DisableResponseBodyKey) },
		}
		c.Writer = writer

		c.Next()

		if shouldCaptureGinBody(c, common.DisableRequestBodyKey) {
			if requestCapture != nil {
				requestCapture.finish(c.Request.ContentLength)
			}
			c.Set(common.RequestbodyKey, requestBody.body.String())
			if metadata := requestBody.metadata(); metadata != nil {
				c.Set(common.RequestBodyCaptureKey, *metadata)
			}
		}
		if shouldCaptureGinBody(c, common.DisableResponseBodyKey) {
			c.Set(common.ResponsebodyKey, responseBody.body.String())
			if metadata := responseBody.metadata(); metadata != nil {
				c.Set(common.ResponseBodyCaptureKey, *metadata)
			}
		}
	}
}

func shouldCaptureGinBody(c *gin.Context, key common.KeyContex) bool {
	value, ok := c.Get(key)
	if !ok {
		return false
	}
	disabled, ok := value.(bool)
	return ok && !disabled
}

// LoggerWithConfig emits the final HTTP log entry using Gin's
// LoggerWithConfig hook and the package logger helpers.
//
// Body handling is controlled through disableRequestBodyKey and
// disableResponseBodyKey in gin.Context:
//   - if a flag is present and false, the captured body is copied into details
//   - if a flag is present and true, that body is intentionally omitted
//
// This middleware expects the request-scoped context produced by
// LoggerWithConfig and is commonly paired with MiddlewareCaptureBody.
func LoggerWithConfig() gin.HandlerFunc {
	return gin.LoggerWithConfig(gin.LoggerConfig{
		Formatter: func(param gin.LogFormatterParams) string {
			ctx := param.Request.Context()
			ctxLogger := builder.New(ctx)
			if v, ok := param.Keys[common.MethodKey]; ok {
				ctxLogger.Method = v.(string)
			}
			if v, ok := param.Keys[common.LineKey]; ok {
				ctxLogger.Line = v.(int)
			}

			if v, ok := ctxLogger.Get(common.DetailsKey); ok {
				ctxLogger.Details = v.(formatter.Details)
			}
			if v, ok := param.Keys[common.DisableRequestBodyKey]; ok {
				if !v.(bool) {
					var requestBody any
					if param.Keys != nil {
						if v, ok := param.Keys[common.RequestbodyKey]; ok {
							requestBody = v
						}
					}
					ctxLogger.Details.Request = requestBody
					if metadata, ok := bodyCaptureMetadata(param.Keys[common.RequestBodyCaptureKey]); ok {
						ctxLogger.Details.RequestCapture = metadata
					}
				}
			}
			if v, ok := param.Keys[common.DisableResponseBodyKey]; ok {
				if !v.(bool) {
					var responseBody any
					if param.Keys != nil {
						if v, ok := param.Keys[common.ResponsebodyKey]; ok {
							responseBody = v
						}
					}
					ctxLogger.Details.Response = responseBody
					if metadata, ok := bodyCaptureMetadata(param.Keys[common.ResponseBodyCaptureKey]); ok {
						ctxLogger.Details.ResponseCapture = metadata
					}
				}
			}
			ctxLogger.Set(common.DetailsKey, ctxLogger.Details)

			if value, ok := param.Keys[formatter.InfoLevel]; ok {
				if msg, ok := value.(string); ok {
					ctxLogger.Info(msg)
					return ""
				}
			}
			if value, ok := param.Keys[formatter.DebugLevel]; ok {
				if msg, ok := value.(string); ok {
					ctxLogger.Debug(msg)
					return ""
				}
			}
			if value, ok := param.Keys[formatter.WarnLevel]; ok {
				if msg, ok := value.(string); ok {
					ctxLogger.Warn(msg)
					return ""
				}
			}
			if value, ok := param.Keys[formatter.ErrorLevel]; ok {
				if msg, ok := value.(error); ok {
					ctxLogger.Error(msg)
					return ""
				}
			}
			return ""
		},
		SkipPaths:       viperdata.GetViperData(string(viperdata.GinLoggerWithConfigSkipPathsAtribute)).([]string),
		SkipQueryString: viperdata.GetViperData(string(viperdata.GinLoggerWithConfigSkipQueryStringAtribute)).(bool),
		Skip: func(c *gin.Context) bool {
			return !viperdata.GetViperData(string(viperdata.GinLoggerWithConfigEnabledAtribute)).(bool)
		},
	})
}

func bodyCaptureMetadata(value any) (*formatter.BodyCaptureMetadata, bool) {
	switch metadata := value.(type) {
	case formatter.BodyCaptureMetadata:
		copy := metadata
		return &copy, true
	case *formatter.BodyCaptureMetadata:
		if metadata == nil {
			return nil, false
		}
		copy := *metadata
		return &copy, true
	default:
		return nil, false
	}
}

// PrintInfo schedules an info-level log message for the current Gin request and
// stores the caller metadata so the formatter can include method and line.
func PrintInfo(ctx *gin.Context, message string) {
	ctxLogger := builder.New(ginRequestContext(ctx))
	method, line := utilities.TraceCaller(ctxLogger.GetTraceCallerSkip())
	ctx.Set(common.MethodKey, method)
	ctx.Set(common.LineKey, line)
	ctx.Set(formatter.InfoLevel, message)
}

// PrintDebug schedules a debug-level log message for the current Gin request
// and stores the caller metadata used by the formatter.
func PrintDebug(ctx *gin.Context, message string) {
	ctxLogger := builder.New(ginRequestContext(ctx))
	method, line := utilities.TraceCaller(ctxLogger.GetTraceCallerSkip())
	ctx.Set(common.MethodKey, method)
	ctx.Set(common.LineKey, line)
	ctx.Set(formatter.DebugLevel, message)
}

// PrintWarn schedules a warn-level log message for the current Gin request and
// stores the caller metadata used by the formatter.
func PrintWarn(ctx *gin.Context, message string) {
	ctxLogger := builder.New(ginRequestContext(ctx))
	method, line := utilities.TraceCaller(ctxLogger.GetTraceCallerSkip())
	ctx.Set(common.MethodKey, method)
	ctx.Set(common.LineKey, line)
	ctx.Set(formatter.WarnLevel, message)
}

// PrintError schedules an error-level log message for the current Gin request
// and stores the caller metadata used by the formatter.
func PrintError(ctx *gin.Context, err error) {
	ctxLogger := builder.New(ginRequestContext(ctx))
	method, line := utilities.TraceCaller(ctxLogger.GetTraceCallerSkip())
	ctx.Set(common.MethodKey, method)
	ctx.Set(common.LineKey, line)
	ctx.Set(formatter.ErrorLevel, err)
}

func ginRequestContext(ctx *gin.Context) context.Context {
	if ctx == nil || ctx.Request == nil {
		return context.Background()
	}
	return ctx.Request.Context()
}
