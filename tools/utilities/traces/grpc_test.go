// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package traces

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type otelFakeStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *otelFakeStream) Context() context.Context {
	return s.ctx
}

func TestMiddlewareOtelGRPCUnary(t *testing.T) {
	resetTestState(t)
	otel.SetTracerProvider(sdktrace.NewTracerProvider())
	otel.SetMeterProvider(noop.NewMeterProvider())
	otel.SetTextMapPropagator(propagation.TraceContext{})

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"))
	interceptor := MiddlewareOtelGRPCUnary()

	resp, err := interceptor(ctx, "request", &grpc.UnaryServerInfo{
		FullMethod: "/pkg.Greeter/SayHello",
	}, func(ctx context.Context, req any) (any, error) {
		span := oteltrace.SpanFromContext(ctx)
		if !span.SpanContext().IsValid() {
			t.Fatal("expected valid span in context")
		}
		return "response", nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	if resp != "response" {
		t.Fatalf("resp = %#v, want %#v", resp, "response")
	}
}

func TestMiddlewareOtelGRPCStream(t *testing.T) {
	resetTestState(t)
	otel.SetTracerProvider(sdktrace.NewTracerProvider())
	otel.SetMeterProvider(noop.NewMeterProvider())
	otel.SetTextMapPropagator(propagation.TraceContext{})

	stream := &otelFakeStream{ctx: context.Background()}
	interceptor := MiddlewareOtelGRPCStream()
	err := interceptor(nil, stream, &grpc.StreamServerInfo{
		FullMethod:     "/pkg.Greeter/StreamAlerts",
		IsServerStream: true,
	}, func(srv any, stream grpc.ServerStream) error {
		span := oteltrace.SpanFromContext(stream.Context())
		if !span.SpanContext().IsValid() {
			t.Fatal("expected valid span in stream context")
		}
		return status.Error(codes.Internal, "stream failure")
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("status.Code(err) = %v, want %v", status.Code(err), codes.Internal)
	}
}

func TestGRPCServiceMethod(t *testing.T) {
	service, method := grpcServiceMethod("/pkg.Greeter/SayHello")
	if service != "pkg.Greeter" {
		t.Fatalf("service = %q, want %q", service, "pkg.Greeter")
	}
	if method != "SayHello" {
		t.Fatalf("method = %q, want %q", method, "SayHello")
	}

	service, method = grpcServiceMethod("single")
	if service != "single" || method != "" {
		t.Fatalf("unexpected fallback values: service=%q method=%q", service, method)
	}
}
