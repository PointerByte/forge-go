// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package traces

import (
	"context"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
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
	md := metadata.MD(c)
	md[strings.ToLower(key)] = append(md[strings.ToLower(key)], value)
}

func (c grpcMetadataCarrier) Keys() []string {
	md := metadata.MD(c)
	keys := make([]string, 0, len(md))
	for key := range md {
		keys = append(keys, key)
	}
	return keys
}

type grpcContextStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *grpcContextStream) Context() context.Context {
	return s.ctx
}

// StatsHandlerOtelGRPCServer returns the official OpenTelemetry gRPC server
// instrumentation as a grpc.StatsHandler.
//
// This is the single supported tracing owner for the gRPC server boundary in
// Forge. It creates exactly one SpanKindServer span per RPC, extracts the
// incoming W3C context with the globally configured propagator, records the
// current RPC semantic conventions (rpc.system.name, rpc.method,
// rpc.response.status_code) and emits the rpc.server.call.duration metric.
//
// Install it with grpc.StatsHandler:
//
//	grpc.NewServer(grpc.StatsHandler(traces.StatsHandlerOtelGRPCServer()))
//
// Do not combine it with a second tracing interceptor on the same server: that
// produces two server spans for one RPC.
func StatsHandlerOtelGRPCServer(options ...otelgrpc.Option) stats.Handler {
	return otelgrpc.NewServerHandler(append(defaultGRPCOptions(), options...)...)
}

// StatsHandlerOtelGRPCClient returns the official OpenTelemetry gRPC client
// instrumentation as a grpc.StatsHandler.
//
// It creates exactly one SpanKindClient span per RPC and injects the W3C
// context into the outgoing metadata. Install it with grpc.WithStatsHandler.
func StatsHandlerOtelGRPCClient(options ...otelgrpc.Option) stats.Handler {
	return otelgrpc.NewClientHandler(append(defaultGRPCOptions(), options...)...)
}

// defaultGRPCOptions binds the official instrumentation to the providers Forge
// installed globally in InitOtel, so a caller that never touches the OTel
// globals still gets the configured pipeline.
func defaultGRPCOptions() []otelgrpc.Option {
	return []otelgrpc.Option{
		otelgrpc.WithTracerProvider(otel.GetTracerProvider()),
		otelgrpc.WithMeterProvider(otel.GetMeterProvider()),
		otelgrpc.WithPropagators(otel.GetTextMapPropagator()),
	}
}

// MiddlewareOtelGRPCUnary returns a unary server interceptor that traces the
// RPC when no other OpenTelemetry instrumentation already owns the boundary.
//
// Deprecated: use StatsHandlerOtelGRPCServer with grpc.StatsHandler instead.
// The official instrumentation additionally records RPC duration metrics and
// message events. This interceptor is kept for callers that build their own
// grpc.Server and cannot install a stats handler; it no longer starts a span
// when the context already carries a local span, so stacking it on top of
// StatsHandlerOtelGRPCServer does not produce duplicate server spans.
func MiddlewareOtelGRPCUnary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if hasLocalSpan(ctx) {
			return handler(ctx, req)
		}

		ctx, span := startGRPCSpan(ctx, info.FullMethod)
		defer span.End()

		resp, err := handler(ctx, req)
		recordGRPCSpanResult(span, err)
		return resp, err
	}
}

// MiddlewareOtelGRPCStream returns a stream server interceptor that traces the
// RPC when no other OpenTelemetry instrumentation already owns the boundary.
//
// Deprecated: use StatsHandlerOtelGRPCServer with grpc.StatsHandler instead.
// See MiddlewareOtelGRPCUnary for the rationale and the duplicate-span guard.
func MiddlewareOtelGRPCStream() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if hasLocalSpan(stream.Context()) {
			return handler(srv, stream)
		}

		ctx, span := startGRPCSpan(stream.Context(), info.FullMethod)
		defer span.End()

		err := handler(srv, &grpcContextStream{
			ServerStream: stream,
			ctx:          ctx,
		})
		recordGRPCSpanResult(span, err)
		return err
	}
}

// hasLocalSpan reports whether ctx already carries a span started in this
// process. A span extracted from inbound metadata is remote and does not count,
// because nothing in this process has opened a server span for it yet.
func hasLocalSpan(ctx context.Context) bool {
	spanContext := trace.SpanFromContext(ctx).SpanContext()
	return spanContext.IsValid() && !spanContext.IsRemote()
}

func startGRPCSpan(ctx context.Context, fullMethod string) (context.Context, trace.Span) {
	md, _ := metadata.FromIncomingContext(ctx)
	if md == nil {
		md = metadata.MD{}
	}
	parent := otel.GetTextMapPropagator().Extract(ctx, grpcMetadataCarrier(md.Copy()))

	name, attributes := grpcMethodAttributes(fullMethod)
	return otel.GetTracerProvider().Tracer(instrumentationName).Start(
		parent,
		name,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attributes...),
	)
}

// grpcMethodAttributes derives the span name and the current RPC semantic
// convention attributes from a gRPC full method, consistently with the official
// instrumentation: the span is named "<package>.<Service>/<Method>" and
// rpc.method carries that same fully-qualified logical name.
func grpcMethodAttributes(fullMethod string) (string, []attribute.KeyValue) {
	if !strings.HasPrefix(fullMethod, "/") {
		return fullMethod, []attribute.KeyValue{semconv.RPCSystemNameGRPC}
	}
	name := fullMethod[1:]
	return name, []attribute.KeyValue{
		semconv.RPCSystemNameGRPC,
		semconv.RPCMethod(name),
	}
}

func recordGRPCSpanResult(span trace.Span, err error) {
	if err == nil {
		span.SetAttributes(semconv.RPCResponseStatusCode(GRPCStatusCode(grpccodes.OK)))
		return
	}

	st := status.Convert(err)
	span.RecordError(err)
	span.SetAttributes(
		semconv.RPCResponseStatusCode(GRPCStatusCode(st.Code())),
		semconv.ErrorTypeKey.String(GRPCStatusCode(st.Code())),
	)
	if code, message := grpcServerSpanStatus(st.Code(), st.Message()); code != otelcodes.Unset {
		span.SetStatus(code, message)
	}
}

// grpcServerSpanStatus maps a gRPC status code to the span status a server span
// must report, following the same rule as the official instrumentation and the
// OpenTelemetry gRPC semantic conventions: only codes that describe a failure of
// the server itself set the span status to Error. Codes such as NOT_FOUND or
// PERMISSION_DENIED describe a legitimate outcome the server produced on
// purpose, so the span status stays Unset and the outcome travels in
// rpc.response.status_code. A server span is never explicitly marked Ok either,
// because Ok is reserved for an application deliberately overriding the
// default.
func grpcServerSpanStatus(code grpccodes.Code, message string) (otelcodes.Code, string) {
	switch code {
	case grpccodes.Unknown,
		grpccodes.DeadlineExceeded,
		grpccodes.Unimplemented,
		grpccodes.Internal,
		grpccodes.Unavailable,
		grpccodes.DataLoss:
		return otelcodes.Error, message
	default:
		return otelcodes.Unset, ""
	}
}

// GRPCStatusCode returns the canonical uppercase name of a gRPC status code as
// required by the rpc.response.status_code semantic convention
// (for example "OK", "DEADLINE_EXCEEDED", "CANCELLED").
func GRPCStatusCode(code grpccodes.Code) string {
	switch code {
	case grpccodes.OK:
		return "OK"
	case grpccodes.Canceled:
		return "CANCELLED"
	case grpccodes.Unknown:
		return "UNKNOWN"
	case grpccodes.InvalidArgument:
		return "INVALID_ARGUMENT"
	case grpccodes.DeadlineExceeded:
		return "DEADLINE_EXCEEDED"
	case grpccodes.NotFound:
		return "NOT_FOUND"
	case grpccodes.AlreadyExists:
		return "ALREADY_EXISTS"
	case grpccodes.PermissionDenied:
		return "PERMISSION_DENIED"
	case grpccodes.ResourceExhausted:
		return "RESOURCE_EXHAUSTED"
	case grpccodes.FailedPrecondition:
		return "FAILED_PRECONDITION"
	case grpccodes.Aborted:
		return "ABORTED"
	case grpccodes.OutOfRange:
		return "OUT_OF_RANGE"
	case grpccodes.Unimplemented:
		return "UNIMPLEMENTED"
	case grpccodes.Internal:
		return "INTERNAL"
	case grpccodes.Unavailable:
		return "UNAVAILABLE"
	case grpccodes.DataLoss:
		return "DATA_LOSS"
	case grpccodes.Unauthenticated:
		return "UNAUTHENTICATED"
	default:
		return code.String()
	}
}

// grpcServiceMethod splits a gRPC full method into its service and method
// parts.
//
// Deprecated: the current RPC semantic conventions carry the fully-qualified
// "<package>.<Service>/<Method>" name in a single rpc.method attribute; there
// is no rpc.service attribute any more. Kept only for callers that still need
// the split for non-OpenTelemetry purposes.
func grpcServiceMethod(fullMethod string) (string, string) {
	trimmed := strings.TrimPrefix(fullMethod, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}
