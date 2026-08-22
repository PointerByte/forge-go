// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package traces

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PointerByte/forge-go/config/proto"
	loggerGRPC "github.com/PointerByte/forge-go/logger/middlewares/grpc"
	loggerHTTP "github.com/PointerByte/forge-go/logger/middlewares/http"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// recordSpans installs a tracer provider that keeps every finished span in
// memory, so a test can assert on how many spans a single request produced and
// on the attributes each of them carries.
func recordSpans(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	resetTestState(t)

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())
	})

	otel.SetTracerProvider(provider)
	otel.SetMeterProvider(metricnoop.NewMeterProvider())
	otel.SetTextMapPropagator(newPropagator())
	viper.Set("app.name", "forge-instrumentation-test")
	return recorder
}

func spansOfKind(spans []sdktrace.ReadOnlySpan, kind oteltrace.SpanKind) []sdktrace.ReadOnlySpan {
	matched := make([]sdktrace.ReadOnlySpan, 0, len(spans))
	for _, span := range spans {
		if span.SpanKind() == kind {
			matched = append(matched, span)
		}
	}
	return matched
}

func attributeValue(span sdktrace.ReadOnlySpan, key attribute.Key) (attribute.Value, bool) {
	for _, kv := range span.Attributes() {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return attribute.Value{}, false
}

func requireAttribute(t *testing.T, span sdktrace.ReadOnlySpan, key attribute.Key, want string) {
	t.Helper()
	value, ok := attributeValue(span, key)
	if !ok {
		t.Fatalf("span %q has no %q attribute; attributes = %v", span.Name(), key, span.Attributes())
	}
	if value.AsString() != want {
		t.Fatalf("span %q %q = %q, want %q", span.Name(), key, value.AsString(), want)
	}
}

type greeterServer struct {
	proto.UnimplementedGreeterServer
	fail bool
}

func (s *greeterServer) SayHello(context.Context, *proto.HelloRequest) (*proto.HelloReply, error) {
	if s.fail {
		return nil, status.Error(codes.PermissionDenied, "denied")
	}
	return &proto.HelloReply{Message: "hello"}, nil
}

// startGreeter runs a gRPC server carrying the full Forge default stack — the
// official OpenTelemetry stats handler plus the logger interceptors — and
// returns a client wired the way the Forge gRPC client bootstrap wires one.
func startGreeter(t *testing.T, fail bool) proto.GreeterClient {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	server := grpc.NewServer(
		grpc.StatsHandler(StatsHandlerOtelGRPCServer()),
		grpc.ChainUnaryInterceptor(
			loggerGRPC.InitLoggerUnaryServerInterceptor(),
		),
	)
	proto.RegisterGreeterServer(server, &greeterServer{fail: fail})

	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	connection, err := grpc.NewClient(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStatsHandler(StatsHandlerOtelGRPCClient()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })

	return proto.NewGreeterClient(connection)
}

// TestGRPCProducesOneServerSpanPerRPC is the duplicate-instrumentation guard for
// the gRPC boundary: the official stats handler and the logger interceptor run
// together on every Forge server, and together they must still yield exactly
// one server span, joined to the caller's client span in one trace.
func TestGRPCProducesOneServerSpanPerRPC(t *testing.T) {
	recorder := recordSpans(t)
	client := startGreeter(t, false)

	if _, err := client.SayHello(context.Background(), &proto.HelloRequest{Name: "forge"}); err != nil {
		t.Fatalf("SayHello() error = %v", err)
	}

	spans := recorder.Ended()
	serverSpans := spansOfKind(spans, oteltrace.SpanKindServer)
	clientSpans := spansOfKind(spans, oteltrace.SpanKindClient)

	if len(serverSpans) != 1 {
		t.Fatalf("server spans = %d, want 1: %v", len(serverSpans), spanNames(spans))
	}
	if len(clientSpans) != 1 {
		t.Fatalf("client spans = %d, want 1: %v", len(clientSpans), spanNames(spans))
	}

	serverSpan, clientSpan := serverSpans[0], clientSpans[0]
	if serverSpan.SpanContext().TraceID() != clientSpan.SpanContext().TraceID() {
		t.Fatalf("server trace id = %s, client trace id = %s: the RPC produced two unrelated traces",
			serverSpan.SpanContext().TraceID(), clientSpan.SpanContext().TraceID())
	}
	if serverSpan.Parent().SpanID() != clientSpan.SpanContext().SpanID() {
		t.Fatalf("server span parent = %s, want the client span %s",
			serverSpan.Parent().SpanID(), clientSpan.SpanContext().SpanID())
	}
}

// TestGRPCUsesCurrentRPCSemanticConventions pins the migration away from the
// obsolete rpc.system / rpc.service / rpc.grpc.status_code attributes.
func TestGRPCUsesCurrentRPCSemanticConventions(t *testing.T) {
	recorder := recordSpans(t)
	client := startGreeter(t, false)

	if _, err := client.SayHello(context.Background(), &proto.HelloRequest{Name: "forge"}); err != nil {
		t.Fatalf("SayHello() error = %v", err)
	}

	for _, span := range recorder.Ended() {
		if span.SpanKind() != oteltrace.SpanKindServer && span.SpanKind() != oteltrace.SpanKindClient {
			continue
		}
		if span.Name() != "helloworld.Greeter/SayHello" {
			t.Fatalf("span name = %q, want the fully-qualified method", span.Name())
		}
		requireAttribute(t, span, semconv.RPCSystemNameKey, "grpc")
		requireAttribute(t, span, semconv.RPCMethodKey, "helloworld.Greeter/SayHello")
		requireAttribute(t, span, semconv.RPCResponseStatusCodeKey, "OK")

		for _, obsolete := range []attribute.Key{"rpc.system", "rpc.service", "rpc.grpc.status_code"} {
			if _, ok := attributeValue(span, obsolete); ok {
				t.Fatalf("span %q still carries the obsolete attribute %q", span.Name(), obsolete)
			}
		}
	}
}

// TestGRPCErrorSemantics checks that a failed RPC reports the canonical status
// name rather than a numeric gRPC code.
func TestGRPCErrorSemantics(t *testing.T) {
	recorder := recordSpans(t)
	client := startGreeter(t, true)

	if _, err := client.SayHello(context.Background(), &proto.HelloRequest{Name: "forge"}); err == nil {
		t.Fatal("SayHello() error = nil, want PermissionDenied")
	}

	serverSpans := spansOfKind(recorder.Ended(), oteltrace.SpanKindServer)
	if len(serverSpans) != 1 {
		t.Fatalf("server spans = %d, want 1", len(serverSpans))
	}
	// PERMISSION_DENIED is an outcome the server produced deliberately, so the
	// conventions keep the span status Unset and carry the outcome in
	// rpc.response.status_code. Only server-side failures set Error.
	requireAttribute(t, serverSpans[0], semconv.RPCResponseStatusCodeKey, "PERMISSION_DENIED")
	if got := serverSpans[0].Status().Code; got != otelcodes.Unset {
		t.Fatalf("span status = %v, want Unset for a deliberate PERMISSION_DENIED", got)
	}
}

// TestGRPCServerSpanStatusMapping pins the span-status rule the deprecated
// Forge interceptor shares with the official instrumentation.
func TestGRPCServerSpanStatusMapping(t *testing.T) {
	errorCodes := []codes.Code{
		codes.Unknown, codes.DeadlineExceeded, codes.Unimplemented,
		codes.Internal, codes.Unavailable, codes.DataLoss,
	}
	for _, code := range errorCodes {
		if got, _ := grpcServerSpanStatus(code, "boom"); got != otelcodes.Error {
			t.Fatalf("grpcServerSpanStatus(%v) = %v, want Error", code, got)
		}
	}

	unsetCodes := []codes.Code{
		codes.OK, codes.Canceled, codes.InvalidArgument, codes.NotFound,
		codes.AlreadyExists, codes.PermissionDenied, codes.ResourceExhausted,
		codes.FailedPrecondition, codes.Aborted, codes.OutOfRange, codes.Unauthenticated,
	}
	for _, code := range unsetCodes {
		if got, _ := grpcServerSpanStatus(code, "boom"); got != otelcodes.Unset {
			t.Fatalf("grpcServerSpanStatus(%v) = %v, want Unset", code, got)
		}
	}
}

// TestDeprecatedGRPCInterceptorDoesNotDuplicateSpans covers the compatibility
// path: an application that kept the deprecated interceptor while adopting the
// stats handler must not end up with two server spans.
func TestDeprecatedGRPCInterceptorDoesNotDuplicateSpans(t *testing.T) {
	recorder := recordSpans(t)

	remote := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID:    oteltrace.TraceID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		SpanID:     oteltrace.SpanID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		TraceFlags: oteltrace.FlagsSampled,
		Remote:     true,
	})
	ctx := oteltrace.ContextWithSpanContext(context.Background(), remote)

	// The stats handler owns the boundary; the deprecated interceptor sees a
	// local span and must step aside.
	ctx, owner := otel.Tracer(instrumentationName).Start(ctx, "helloworld.Greeter/SayHello",
		oteltrace.WithSpanKind(oteltrace.SpanKindServer))

	interceptor := MiddlewareOtelGRPCUnary()
	_, err := interceptor(ctx, "request", &grpc.UnaryServerInfo{FullMethod: "/helloworld.Greeter/SayHello"},
		func(context.Context, any) (any, error) { return "response", nil })
	if err != nil {
		t.Fatalf("interceptor error = %v", err)
	}
	owner.End()

	if spans := spansOfKind(recorder.Ended(), oteltrace.SpanKindServer); len(spans) != 1 {
		t.Fatalf("server spans = %d, want 1: %v", len(spans), spanNames(recorder.Ended()))
	}
}

// TestHTTPProducesOneServerSpanPerRequest is the duplicate-instrumentation guard
// for the HTTP boundary, where the otelgin middleware and the logger middleware
// run back to back on every Forge Gin engine.
func TestHTTPProducesOneServerSpanPerRequest(t *testing.T) {
	recorder := recordSpans(t)
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	engine.Use(MiddlewareOtel(), loggerHTTP.InitLogger())
	engine.GET("/orders/:id", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	request := httptest.NewRequest(http.MethodGet, "/orders/42", nil)
	request.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	engine.ServeHTTP(httptest.NewRecorder(), request)

	serverSpans := spansOfKind(recorder.Ended(), oteltrace.SpanKindServer)
	if len(serverSpans) != 1 {
		t.Fatalf("server spans = %d, want 1: %v", len(serverSpans), spanNames(recorder.Ended()))
	}

	span := serverSpans[0]
	if got := span.SpanContext().TraceID().String(); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("trace id = %s, want the propagated 4bf92f3577b34da6a3ce929d0e0e4736", got)
	}
	// The route template, never the raw path, is what keeps HTTP metric and
	// span cardinality bounded.
	requireAttribute(t, span, semconv.HTTPRouteKey, "/orders/:id")
}

func spanNames(spans []sdktrace.ReadOnlySpan) []string {
	names := make([]string, 0, len(spans))
	for _, span := range spans {
		names = append(names, span.Name()+"["+span.SpanKind().String()+"]")
	}
	return names
}

// TestPropagationDefaultsToW3C documents the default propagation contract: W3C
// trace context plus W3C baggage, and nothing Forge-specific.
func TestPropagationDefaultsToW3C(t *testing.T) {
	t.Setenv("OTEL_PROPAGATORS", "")

	fields := newPropagator().Fields()
	want := map[string]bool{"traceparent": false, "tracestate": false, "baggage": false}
	for _, field := range fields {
		if _, ok := want[field]; !ok {
			t.Fatalf("unexpected propagation field %q; Forge must not define its own wire format", field)
		}
		want[field] = true
	}
	for field, seen := range want {
		if !seen {
			t.Fatalf("propagator does not carry %q; fields = %v", field, fields)
		}
	}
}

// TestPropagationRoundTrip proves a context injected by one Forge process is
// recovered unchanged by another.
func TestPropagationRoundTrip(t *testing.T) {
	propagator := newPropagator()

	spanContext := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID:    oteltrace.TraceID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01},
		SpanID:     oteltrace.SpanID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		TraceFlags: oteltrace.FlagsSampled,
	})

	carrier := propagation.HeaderCarrier{}
	propagator.Inject(
		oteltrace.ContextWithSpanContext(context.Background(), spanContext),
		carrier,
	)
	if carrier.Get("traceparent") == "" {
		t.Fatal("Inject() wrote no traceparent header")
	}

	extracted := oteltrace.SpanContextFromContext(
		propagator.Extract(context.Background(), carrier),
	)
	if extracted.TraceID() != spanContext.TraceID() || extracted.SpanID() != spanContext.SpanID() {
		t.Fatalf("round trip lost the context: got %s/%s, want %s/%s",
			extracted.TraceID(), extracted.SpanID(), spanContext.TraceID(), spanContext.SpanID())
	}
	if !extracted.IsRemote() {
		t.Fatal("extracted span context is not marked remote")
	}
}
