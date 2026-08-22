// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"net/http"
	"net/textproto"
	"reflect"
	"strings"

	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/PointerByte/forge-go/logger/common"
	"github.com/PointerByte/forge-go/logger/formatter"
	"github.com/PointerByte/forge-go/logger/utilities"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type grpcMetadataCarrier metadata.MD

func (c grpcMetadataCarrier) Get(key string) string {
	values := metadata.MD(c).Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (c grpcMetadataCarrier) Set(key string, value string) {
	key = strings.ToLower(key)
	md := metadata.MD(c)
	md[key] = append(md[key], value)
}

func (c grpcMetadataCarrier) Keys() []string {
	md := metadata.MD(c)
	keys := make([]string, 0, len(md))
	for key := range md {
		keys = append(keys, key)
	}
	return keys
}

type grpcCaptureStream struct {
	grpc.ServerStream
	ctx       context.Context
	requests  *grpcBodyCapture
	responses *grpcBodyCapture
}

func (s *grpcCaptureStream) Context() context.Context {
	return s.ctx
}

func (s *grpcCaptureStream) RecvMsg(m any) error {
	err := s.ServerStream.RecvMsg(m)
	if err == nil && shouldIncludeGRPCBody(builder.New(s.ctx), common.DisableRequestBodyKey) {
		s.requestCapture().add(m)
	}
	return err
}

func (s *grpcCaptureStream) SendMsg(m any) error {
	if err := s.ServerStream.SendMsg(m); err != nil {
		return err
	}
	if shouldIncludeGRPCBody(builder.New(s.ctx), common.DisableResponseBodyKey) {
		s.responseCapture().add(m)
	}
	return nil
}

func (s *grpcCaptureStream) requestCapture() *grpcBodyCapture {
	if s.requests == nil {
		s.requests = newGRPCBodyCapture(viperdata.BodyCaptureMaxBytes())
	}
	return s.requests
}

func (s *grpcCaptureStream) responseCapture() *grpcBodyCapture {
	if s.responses == nil {
		s.responses = newGRPCBodyCapture(viperdata.BodyCaptureMaxBytes())
	}
	return s.responses
}

// InitLoggerUnaryServerInterceptor creates the request-scoped logger context
// for unary gRPC calls.
//
// It attaches the base gRPC metadata used by structured logs and passes the
// enriched context to the next handler.
//
// Tracing ownership: this interceptor never creates a second server span. When
// the official otelgrpc stats handler (or any equivalent instrumentation)
// already owns the RPC boundary, the context carries the server span and the
// logger only adopts its trace and span ids. It extracts the incoming context
// and starts a span itself only when nothing else has, so the logger stays
// usable standalone without producing duplicate spans for one RPC.
func InitLoggerUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctxLogger, span, ownsSpan := newGRPCLoggerContext(ctx)
		if info != nil {
			setGRPCMethodDetails(builder.New(ctxLogger), info.FullMethod)
		}
		if ownsSpan {
			defer span.End()
		}
		return handler(ctxLogger, req)
	}
}

// InitLoggerStreamServerInterceptor creates the request-scoped logger context
// for streaming gRPC calls.
//
// It performs the same setup as InitLoggerUnaryServerInterceptor, but wraps the
// grpc.ServerStream so downstream handlers observe the enriched context through
// stream.Context().
func InitLoggerStreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctxLogger, span, ownsSpan := newGRPCLoggerContext(stream.Context())
		if info != nil {
			setGRPCMethodDetails(builder.New(ctxLogger), info.FullMethod)
		}
		if ownsSpan {
			defer span.End()
		}

		return handler(srv, &grpcContextStream{
			ServerStream: stream,
			ctx:          ctxLogger,
		})
	}
}

// CaptureBodyUnaryServerInterceptor stores unary request and response payloads
// in the logger context only when body logging is enabled.
//
// The captured values are later consumed by LoggerWithConfigUnaryServerInterceptor
// to populate details.request and details.response when each body is enabled.
func CaptureBodyUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctxLogger := builder.New(ctx)
		resp, err := handler(ctxLogger, req)
		if shouldIncludeGRPCBody(ctxLogger, common.DisableRequestBodyKey) {
			capture := newGRPCBodyCapture(viperdata.BodyCaptureMaxBytes())
			capture.add(req)
			ctxLogger.Set(common.RequestbodyKey, capture.value())
			if metadata := capture.metadata(); metadata != nil {
				ctxLogger.Set(common.RequestBodyCaptureKey, *metadata)
			}
		}
		if shouldIncludeGRPCBody(ctxLogger, common.DisableResponseBodyKey) {
			capture := newGRPCBodyCapture(viperdata.BodyCaptureMaxBytes())
			capture.add(resp)
			ctxLogger.Set(common.ResponsebodyKey, capture.value())
			if metadata := capture.metadata(); metadata != nil {
				ctxLogger.Set(common.ResponseBodyCaptureKey, *metadata)
			}
		}
		return resp, err
	}
}

// CaptureBodyStreamServerInterceptor captures inbound and outbound stream
// messages only while body logging is enabled, then stores the captured values
// in the logger context.
//
// When only one request or response message is observed, the stored value is
// that message directly. When multiple messages are exchanged, the stored value
// becomes a slice so the final log can reflect the full interaction.
func CaptureBodyStreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctxLogger := builder.New(stream.Context())
		captureStream := &grpcCaptureStream{
			ServerStream: stream,
			ctx:          ctxLogger,
			requests:     newGRPCBodyCapture(viperdata.BodyCaptureMaxBytes()),
			responses:    newGRPCBodyCapture(viperdata.BodyCaptureMaxBytes()),
		}

		err := handler(srv, captureStream)
		if shouldIncludeGRPCBody(ctxLogger, common.DisableRequestBodyKey) {
			ctxLogger.Set(common.RequestbodyKey, captureStream.requests.value())
			if metadata := captureStream.requests.metadata(); metadata != nil {
				ctxLogger.Set(common.RequestBodyCaptureKey, *metadata)
			}
		}
		if shouldIncludeGRPCBody(ctxLogger, common.DisableResponseBodyKey) {
			ctxLogger.Set(common.ResponsebodyKey, captureStream.responses.value())
			if metadata := captureStream.responses.metadata(); metadata != nil {
				ctxLogger.Set(common.ResponseBodyCaptureKey, *metadata)
			}
		}
		return err
	}
}

// DisableGRPCBody marks the current request-scoped logger context so the final
// gRPC structured log can omit request and response bodies independently.
//
// The returned context is the logger context carrying those flags. In handlers
// reached through InitLoggerUnaryServerInterceptor or
// InitLoggerStreamServerInterceptor, the input context already contains the
// logger and the return value is mostly useful for chaining.
func DisableGRPCBody(ctx context.Context, disableRequestBody bool, disableResponseBody bool) context.Context {
	ctxLogger := builder.New(ctx)
	ctxLogger.Set(common.DisableRequestBodyKey, disableRequestBody)
	ctxLogger.Set(common.DisableResponseBodyKey, disableResponseBody)
	return ctxLogger
}

// DisableGRPCTraceBody marks whether downstream trace services should omit
// their request and response bodies when builder.Context.TraceEnd finishes a
// trace inside a gRPC request.
func DisableGRPCTraceBody(ctx context.Context, disableRequestBody bool, disableResponseBody bool) context.Context {
	ctxLogger := builder.New(ctx)
	ctxLogger.Set(common.DisableTraceRequestBodyKey, disableRequestBody)
	ctxLogger.Set(common.DisableTraceResponseBodyKey, disableResponseBody)
	return ctxLogger
}

// LoggerWithConfigUnaryServerInterceptor emits the final structured log entry
// for a unary gRPC call.
//
// It merges any captured request and response bodies into the logger details
// and then writes the log using the level previously stored in the logger
// context. If neither a log level nor a non-nil error is present, the function
// treats that condition as a developer error.
func LoggerWithConfigUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctxLogger := builder.New(ctx)
		resp, err := handler(ctxLogger, req)
		fullMethod := ""
		if info != nil {
			fullMethod = info.FullMethod
			setGRPCMethodDetails(ctxLogger, fullMethod)
		}
		applyGRPCBodyDetails(ctxLogger)
		writeGRPCLog(ctxLogger, fullMethod, err)
		return resp, err
	}
}

// LoggerWithConfigStreamServerInterceptor emits the final structured log entry
// for a streaming gRPC call.
//
// It applies the same finalization flow as the unary variant, but operates on
// the stream context and writes the log once the stream handler completes.
func LoggerWithConfigStreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctxLogger := builder.New(stream.Context())
		err := handler(srv, &grpcContextStream{
			ServerStream: stream,
			ctx:          ctxLogger,
		})
		fullMethod := ""
		if info != nil {
			fullMethod = info.FullMethod
			setGRPCMethodDetails(ctxLogger, fullMethod)
		}
		applyGRPCBodyDetails(ctxLogger)
		writeGRPCLog(ctxLogger, fullMethod, err)
		return err
	}
}

type grpcContextStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *grpcContextStream) Context() context.Context {
	return s.ctx
}

func extractGRPCContext(ctx context.Context) context.Context {
	md, _ := metadata.FromIncomingContext(ctx)
	if md == nil {
		md = metadata.MD{}
	}
	return otel.GetTextMapPropagator().Extract(ctx, grpcMetadataCarrier(md.Copy()))
}

func newGRPCLoggerContext(incoming context.Context) (context.Context, trace.Span, bool) {
	parent, span, ownsSpan := serverSpanContext(incoming)
	ctxLogger := builder.New(parent)
	appName := viperdata.GetViperData(string(viperdata.AppAtribute)).(string)

	// A real trace wins over the legacy correlation metadata entry: a
	// structured log must be reachable from the span it was emitted under. The
	// metadata value is honoured only when no span context is available.
	traceID := ""
	if spanContext := span.SpanContext(); spanContext.IsValid() {
		traceID = spanContext.TraceID().String()
		ctxLogger.SetSpanID(spanContext.SpanID().String())
	}
	if traceID == "" {
		if md, ok := metadata.FromIncomingContext(incoming); ok {
			if values := md.Get(strings.ToLower(common.TraceIDHeader)); len(values) > 0 {
				traceID = values[0]
			}
		}
	}
	if traceID != "" {
		ctxLogger.SetTraceID(traceID)
	}

	details := formatter.Details{
		System:   appName,
		Protocol: "gRPC",
	}
	if p, ok := peer.FromContext(incoming); ok && p.Addr != nil {
		details.Client = p.Addr.String()
	}
	if md, ok := metadata.FromIncomingContext(incoming); ok {
		details.SetHeaders(metadataToHTTPHeader(md))
	}

	ctxLogger.Details = details
	ctxLogger.Set(common.DetailsKey, details)
	return ctxLogger, span, ownsSpan
}

// serverSpanContext returns the context the logger must build on, the span that
// represents the RPC, and whether this interceptor started that span and is
// therefore responsible for ending it.
//
// A span already present in the context was started in this process by whoever
// owns the RPC boundary. Re-extracting the remote context on top of it would
// detach the logger from that span and produce a sibling root, so the
// extraction happens only when there is nothing to adopt.
func serverSpanContext(incoming context.Context) (context.Context, trace.Span, bool) {
	if spanContext := trace.SpanContextFromContext(incoming); spanContext.IsValid() && !spanContext.IsRemote() {
		return incoming, trace.SpanFromContext(incoming), false
	}

	parent := extractGRPCContext(incoming)
	appName := viperdata.GetViperData(string(viperdata.AppAtribute)).(string)
	ctx, span := otel.Tracer(common.InstrumentationName).Start(
		parent,
		appName,
		trace.WithSpanKind(trace.SpanKindServer),
	)
	return ctx, span, true
}

func metadataToHTTPHeader(md metadata.MD) http.Header {
	if len(md) == 0 {
		return nil
	}
	headers := make(http.Header, len(md))
	for key, values := range md {
		valueCopy := make([]string, len(values))
		copy(valueCopy, values)
		headers[textproto.CanonicalMIMEHeaderKey(key)] = valueCopy
	}
	return headers
}

func collapseCapturedBodies(items []any) any {
	switch len(items) {
	case 0:
		return nil
	case 1:
		return items[0]
	default:
		return items
	}
}

func applyGRPCBodyDetails(ctxLogger *builder.Context) {
	includeRequest := shouldIncludeGRPCBody(ctxLogger, common.DisableRequestBodyKey)
	includeResponse := shouldIncludeGRPCBody(ctxLogger, common.DisableResponseBodyKey)
	if !includeRequest && !includeResponse {
		return
	}

	details := ctxLogger.Details
	if details.System == "" {
		detailsAny, ok := ctxLogger.Get(common.DetailsKey)
		if !ok {
			return
		}
		castDetails, castOK := detailsAny.(formatter.Details)
		if !castOK {
			return
		}
		details = castDetails
	}
	if requestBody, ok := ctxLogger.Get(common.RequestbodyKey); includeRequest && ok {
		details.Request = requestBody
	}
	if metadata, ok := grpcBodyCaptureMetadata(ctxLogger, common.RequestBodyCaptureKey); includeRequest && ok {
		details.RequestCapture = metadata
	}
	if responseBody, ok := ctxLogger.Get(common.ResponsebodyKey); includeResponse && ok {
		details.Response = responseBody
	}
	if metadata, ok := grpcBodyCaptureMetadata(ctxLogger, common.ResponseBodyCaptureKey); includeResponse && ok {
		details.ResponseCapture = metadata
	}
	ctxLogger.Details = details
	ctxLogger.Set(common.DetailsKey, details)
}

func grpcBodyCaptureMetadata(ctxLogger *builder.Context, key common.KeyContex) (*formatter.BodyCaptureMetadata, bool) {
	value, ok := ctxLogger.Get(key)
	if !ok {
		value, ok = ctxLogger.Get(string(key))
	}
	if !ok {
		return nil, false
	}
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

func setGRPCMethodDetails(ctxLogger *builder.Context, fullMethod string) {
	if fullMethod == "" {
		return
	}

	details := ctxLogger.Details
	if details.System == "" {
		if detailsAny, ok := ctxLogger.Get(common.DetailsKey); ok {
			if castDetails, castOK := detailsAny.(formatter.Details); castOK {
				details = castDetails
			}
		}
	}
	details.Method = grpcFunctionName(fullMethod)
	details.Path = fullMethod
	ctxLogger.Details = details
	ctxLogger.Set(common.DetailsKey, details)
}

func shouldIncludeGRPCBody(ctxLogger *builder.Context, key common.KeyContex) bool {
	v, ok := ctxLogger.Get(string(key))
	if !ok {
		v, ok = ctxLogger.Get(key)
	}
	if !ok {
		return false
	}
	disabled, typeOK := v.(bool)
	return typeOK && !disabled
}

// PrintInfo schedules an info-level log message for the current gRPC request
// and stores caller metadata so the final logger interceptor can emit it.
func PrintInfo(ctxLogger *builder.Context, message string) {
	ctxLogger.Method, ctxLogger.Line = utilities.TraceCaller(ctxLogger.GetTraceCallerSkip())
	ctxLogger.Set(formatter.InfoLevel, message)
}

// PrintDebug schedules a debug-level log message for the current gRPC request
// and stores caller metadata so the final logger interceptor can emit it.
func PrintDebug(ctxLogger *builder.Context, message string) {
	ctxLogger.Method, ctxLogger.Line = utilities.TraceCaller(ctxLogger.GetTraceCallerSkip())
	ctxLogger.Set(formatter.DebugLevel, message)
}

// PrintWarn schedules a warn-level log message for the current gRPC request
// and stores caller metadata so the final logger interceptor can emit it.
func PrintWarn(ctxLogger *builder.Context, message string) {
	ctxLogger.Method, ctxLogger.Line = utilities.TraceCaller(ctxLogger.GetTraceCallerSkip())
	ctxLogger.Set(formatter.WarnLevel, message)
}

// PrintError schedules an error-level log message for the current gRPC request
// and stores caller metadata so the final logger interceptor can emit it.
func PrintError(ctxLogger *builder.Context, err error) {
	ctxLogger.Method, ctxLogger.Line = utilities.TraceCaller(ctxLogger.GetTraceCallerSkip())
	ctxLogger.Set(formatter.ErrorLevel, err)
}

func writeGRPCLog(ctxLogger *builder.Context, fullMethod string, err error) {
	if !viperdata.GetViperData(string(viperdata.GRPCLoggerWithConfigEnabledAtribute)).(bool) {
		return
	}
	if shouldSkipGRPCFunction(fullMethod) {
		return
	}
	if isAuthorizationGRPCError(err) {
		return
	}

	if value, ok := ctxLogger.Get(formatter.InfoLevel); ok {
		if msg, castOK := value.(string); castOK {
			ctxLogger.Info(msg)
			return
		}
	}
	if value, ok := ctxLogger.Get(formatter.DebugLevel); ok {
		if msg, castOK := value.(string); castOK {
			ctxLogger.Debug(msg)
			return
		}
	}
	if value, ok := ctxLogger.Get(formatter.WarnLevel); ok {
		if msg, castOK := value.(string); castOK {
			ctxLogger.Warn(msg)
			return
		}
	}
	if value, ok := ctxLogger.Get(formatter.ErrorLevel); ok {
		if loggedErr, castOK := value.(error); castOK && hasError(loggedErr) {
			if isAuthorizationGRPCError(loggedErr) {
				return
			}
			ctxLogger.Error(loggedErr)
			return
		}
	}
	if !hasError(err) {
		return
	}
	ctxLogger.Error(err)
}

func isAuthorizationGRPCError(err error) bool {
	switch status.Code(err) {
	case codes.Unauthenticated, codes.PermissionDenied:
		return true
	default:
		return false
	}
}

func shouldSkipGRPCFunction(fullMethod string) bool {
	skipFunctions := viperdata.GetViperData(string(viperdata.GRPCLoggerWithConfigSkipFunctionAtribute)).([]string)
	functionName := grpcFunctionName(fullMethod)
	for _, skipFunction := range skipFunctions {
		skipFunction = strings.TrimSpace(skipFunction)
		if skipFunction == "" {
			continue
		}
		if skipFunction == fullMethod || skipFunction == functionName {
			return true
		}
	}
	return false
}

func grpcFunctionName(fullMethod string) string {
	parts := strings.Split(strings.TrimPrefix(fullMethod, "/"), "/")
	if len(parts) == 0 {
		return fullMethod
	}
	return parts[len(parts)-1]
}

func hasError(err error) bool {
	if err == nil {
		return false
	}
	value := reflect.ValueOf(err)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !value.IsNil()
	default:
		return true
	}
}
