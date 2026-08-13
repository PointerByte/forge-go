// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package traces

import (
	"context"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
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

func MiddlewareOtelGRPCUnary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, span := startGRPCSpan(ctx, info.FullMethod)
		defer span.End()

		resp, err := handler(ctx, req)
		recordGRPCSpanResult(span, err)
		return resp, err
	}
}

func MiddlewareOtelGRPCStream() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
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

func startGRPCSpan(ctx context.Context, fullMethod string) (context.Context, trace.Span) {
	md, _ := metadata.FromIncomingContext(ctx)
	if md == nil {
		md = metadata.MD{}
	}
	parent := otel.GetTextMapPropagator().Extract(ctx, grpcMetadataCarrier(md.Copy()))

	service, method := grpcServiceMethod(fullMethod)
	return otel.GetTracerProvider().Tracer(serviceName()).Start(
		parent,
		fullMethod,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("rpc.system", "grpc"),
			attribute.String("rpc.service", service),
			attribute.String("rpc.method", method),
		),
	)
}

func recordGRPCSpanResult(span trace.Span, err error) {
	if err == nil {
		span.SetAttributes(attribute.Int("rpc.grpc.status_code", 0))
		span.SetStatus(otelcodes.Ok, "")
		return
	}

	st := status.Convert(err)
	span.RecordError(err)
	span.SetAttributes(attribute.Int("rpc.grpc.status_code", int(st.Code())))
	span.SetStatus(otelcodes.Error, st.Message())
}

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
