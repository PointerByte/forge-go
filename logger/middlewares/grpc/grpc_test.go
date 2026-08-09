// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"

	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/PointerByte/forge-go/logger/common"
	"github.com/PointerByte/forge-go/logger/formatter"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type nilPointerError struct{}

func (*nilPointerError) Error() string {
	return "nil-pointer-error"
}

type fakeServerStream struct {
	grpc.ServerStream
	ctx       context.Context
	recvItems []any
	sendItems []any
	sendErr   error
}

type grpcLogCaptureHandler struct {
	payload []byte
}

func (h *grpcLogCaptureHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *grpcLogCaptureHandler) Handle(ctx context.Context, record slog.Record) error {
	ctxLogger, ok := builder.From(ctx)
	if !ok {
		return errors.New("logger context was not propagated to final log")
	}
	payload, err := formatter.New("json").Format(formatter.LogFormat{
		Message: record.Message,
		Process: ctxLogger.Processes(),
	})
	if err != nil {
		return err
	}
	h.payload = payload
	return nil
}

func (h *grpcLogCaptureHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

func (h *grpcLogCaptureHandler) WithGroup(string) slog.Handler {
	return h
}

func (s *fakeServerStream) Context() context.Context {
	return s.ctx
}

func (s *fakeServerStream) RecvMsg(m any) error {
	if len(s.recvItems) == 0 {
		return io.EOF
	}
	item := s.recvItems[0]
	s.recvItems = s.recvItems[1:]
	switch dst := m.(type) {
	case *string:
		*dst = item.(string)
	}
	return nil
}

func (s *fakeServerStream) SendMsg(m any) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sendItems = append(s.sendItems, m)
	return nil
}

func resetGRPCTestState(t *testing.T) {
	t.Helper()
	viper.Reset()
	viperdata.ResetViperDataSingleton()
	t.Cleanup(func() {
		viper.Reset()
		viperdata.ResetViperDataSingleton()
	})

	viper.Set(string(viperdata.AppAtribute), "test-service")
	viper.Set(string(viperdata.LoggerIgnoredHeadersAtribute), []string{})
	viper.Set(string(viperdata.LoggerModeTestAtribute), false)
	viper.Set(string(viperdata.GRPCLoggerWithConfigEnabledAtribute), true)
	viper.Set(string(viperdata.GRPCLoggerWithConfigSkipFunctionAtribute), []string{})
}

func TestInitLoggerUnaryServerInterceptor(t *testing.T) {
	resetGRPCTestState(t)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-request-id", "abc123",
		"x-trace-id", "trace-grpc-in",
	))
	ctx = peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}})

	var gotCtxLogger *builder.Context
	interceptor := InitLoggerUnaryServerInterceptor()
	_, err := interceptor(ctx, "request", &grpc.UnaryServerInfo{FullMethod: "/pkg.Greeter/SayHello"}, func(ctx context.Context, req any) (any, error) {
		gotCtxLogger = builder.New(ctx)
		return "response", nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	detailsAny, ok := gotCtxLogger.Get(common.DetailsKey)
	if !ok {
		t.Fatalf("expected %q in logger context", common.DetailsKey)
	}
	details := detailsAny.(formatter.Details)
	if details.Protocol != "gRPC" {
		t.Fatalf("details.Protocol = %q, want %q", details.Protocol, "gRPC")
	}
	if details.Method != "SayHello" {
		t.Fatalf("details.Method = %q, want %q", details.Method, "SayHello")
	}
	if details.Path != "/pkg.Greeter/SayHello" {
		t.Fatalf("details.Path = %q, want %q", details.Path, "/pkg.Greeter/SayHello")
	}
	if got := details.Headers.Get("x-request-id"); got != "abc123" {
		t.Fatalf("details.Headers[x-request-id] = %q, want %q", got, "abc123")
	}
	if got := gotCtxLogger.TraceID(); got != "trace-grpc-in" {
		t.Fatalf("TraceID() = %q, want %q", got, "trace-grpc-in")
	}
}

func TestUnaryInterceptorsCaptureBodiesAndPopulateDetails(t *testing.T) {
	resetGRPCTestState(t)

	var gotCtxLogger *builder.Context
	resp, err := InitLoggerUnaryServerInterceptor()(context.Background(), map[string]any{"kind": "info"}, &grpc.UnaryServerInfo{
		FullMethod: "/pkg.Greeter/SayHello",
	}, func(ctx context.Context, req any) (any, error) {
		return LoggerWithConfigUnaryServerInterceptor()(ctx, req, &grpc.UnaryServerInfo{
			FullMethod: "/pkg.Greeter/SayHello",
		}, func(ctx context.Context, req any) (any, error) {
			return CaptureBodyUnaryServerInterceptor()(ctx, req, &grpc.UnaryServerInfo{
				FullMethod: "/pkg.Greeter/SayHello",
			}, func(ctx context.Context, req any) (any, error) {
				gotCtxLogger = builder.New(ctx)
				gotCtxLogger.Set(common.DisableRequestBodyKey, false)
				gotCtxLogger.Set(common.DisableResponseBodyKey, false)
				gotCtxLogger.Set(formatter.InfoLevel, "request processed")
				return map[string]any{"message": "ok"}, nil
			})
		})
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}

	detailsAny, ok := gotCtxLogger.Get(common.DetailsKey)
	if !ok {
		t.Fatalf("expected %q in logger context", common.DetailsKey)
	}
	details := detailsAny.(formatter.Details)
	requestBody, ok := details.Request.(map[string]any)
	if !ok || requestBody["kind"] != "info" {
		t.Fatalf("details.Request = %#v, want captured request map", details.Request)
	}
	responseBody, ok := details.Response.(map[string]any)
	if !ok || responseBody["message"] != "ok" {
		t.Fatalf("details.Response = %#v, want captured response map", details.Response)
	}
	if details.Method != "SayHello" {
		t.Fatalf("details.Method = %q, want %q", details.Method, "SayHello")
	}
	if details.Path != "/pkg.Greeter/SayHello" {
		t.Fatalf("details.Path = %q, want %q", details.Path, "/pkg.Greeter/SayHello")
	}
}

func TestUnaryInterceptorChainPreservesAndSerializesCompletedTraces(t *testing.T) {
	resetGRPCTestState(t)

	type userInterceptorContextKey struct{}

	oldLogger := slog.Default()
	capture := &grpcLogCaptureHandler{}
	slog.SetDefault(slog.New(capture))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	var handlerLogger *builder.Context
	userInterceptor := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// A user interceptor may wrap the context; builder.From must still find
		// the request-scoped logger and its shared process collection.
		return handler(context.WithValue(ctx, userInterceptorContextKey{}, true), req)
	}

	_, err := InitLoggerUnaryServerInterceptor()(context.Background(), "request", &grpc.UnaryServerInfo{
		FullMethod: "/pkg.CMK/Decrypt",
	}, func(ctx context.Context, req any) (any, error) {
		return LoggerWithConfigUnaryServerInterceptor()(ctx, req, &grpc.UnaryServerInfo{
			FullMethod: "/pkg.CMK/Decrypt",
		}, func(ctx context.Context, req any) (any, error) {
			return CaptureBodyUnaryServerInterceptor()(ctx, req, &grpc.UnaryServerInfo{
				FullMethod: "/pkg.CMK/Decrypt",
			}, func(ctx context.Context, req any) (any, error) {
				return userInterceptor(ctx, req, &grpc.UnaryServerInfo{FullMethod: "/pkg.CMK/Decrypt"}, func(ctx context.Context, req any) (any, error) {
					handlerLogger = builder.New(ctx)
					for _, name := range []string{"query database", "write audit record"} {
						process := &formatter.Process{System: "test-service", Process: name}
						handlerLogger.TraceInit(process)
						handlerLogger.TraceEnd(process)
					}
					handlerLogger.Set(formatter.InfoLevel, "Decrypt completed")
					return "response", nil
				})
			})
		})
	})
	if err != nil {
		t.Fatalf("interceptor chain returned error: %v", err)
	}
	if handlerLogger == nil {
		t.Fatal("handler did not receive a logger context")
	}

	var decoded map[string]any
	if err := json.Unmarshal(capture.payload, &decoded); err != nil {
		t.Fatalf("final log payload is not JSON: %v; payload=%s", err, capture.payload)
	}
	processes, ok := decoded["process"].([]any)
	if !ok || len(processes) != 2 {
		t.Fatalf("process = %#v, want two traces", decoded["process"])
	}
	for index, want := range []string{"query database", "write audit record"} {
		process, ok := processes[index].(map[string]any)
		if !ok {
			t.Fatalf("process[%d] = %T, want object", index, processes[index])
		}
		if process["system"] != "test-service" || process["process"] != want || process["status"] != "SUCCESS" {
			t.Fatalf("process[%d] = %#v, want completed %q trace", index, process, want)
		}
	}
	if _, exists := decoded["pro"+"ccess"]; exists {
		t.Fatalf("final payload used legacy process field: %s", capture.payload)
	}
}

func TestLoggerWithConfigUnaryOmitsBodiesWhenDisabled(t *testing.T) {
	resetGRPCTestState(t)

	var gotCtxLogger *builder.Context
	_, err := InitLoggerUnaryServerInterceptor()(context.Background(), "request", &grpc.UnaryServerInfo{
		FullMethod: "/pkg.Greeter/SayHello",
	}, func(ctx context.Context, req any) (any, error) {
		return LoggerWithConfigUnaryServerInterceptor()(ctx, req, &grpc.UnaryServerInfo{
			FullMethod: "/pkg.Greeter/SayHello",
		}, func(ctx context.Context, req any) (any, error) {
			return CaptureBodyUnaryServerInterceptor()(ctx, req, &grpc.UnaryServerInfo{
				FullMethod: "/pkg.Greeter/SayHello",
			}, func(ctx context.Context, req any) (any, error) {
				gotCtxLogger = builder.New(ctx)
				gotCtxLogger.Set(common.DisableRequestBodyKey, true)
				gotCtxLogger.Set(common.DisableResponseBodyKey, true)
				return "response", errors.New("boom")
			})
		})
	})
	if err == nil {
		t.Fatal("expected error")
	}

	detailsAny, ok := gotCtxLogger.Get(common.DetailsKey)
	if !ok {
		t.Fatalf("expected %q in logger context", common.DetailsKey)
	}
	details := detailsAny.(formatter.Details)
	if details.Request != nil {
		t.Fatalf("details.Request = %#v, want nil", details.Request)
	}
	if details.Response != nil {
		t.Fatalf("details.Response = %#v, want nil", details.Response)
	}
	if requestBody, ok := gotCtxLogger.Get(common.RequestbodyKey); ok {
		t.Fatalf("request body was stored = %#v, want no stored body", requestBody)
	}
	if responseBody, ok := gotCtxLogger.Get(common.ResponsebodyKey); ok {
		t.Fatalf("response body was stored = %#v, want no stored body", responseBody)
	}
}

func TestDisableGRPCBody(t *testing.T) {
	resetGRPCTestState(t)

	var gotCtxLogger *builder.Context
	resp, err := InitLoggerUnaryServerInterceptor()(context.Background(), "request", &grpc.UnaryServerInfo{
		FullMethod: "/pkg.Greeter/SayHello",
	}, func(ctx context.Context, req any) (any, error) {
		return LoggerWithConfigUnaryServerInterceptor()(ctx, req, &grpc.UnaryServerInfo{
			FullMethod: "/pkg.Greeter/SayHello",
		}, func(ctx context.Context, req any) (any, error) {
			return CaptureBodyUnaryServerInterceptor()(ctx, req, &grpc.UnaryServerInfo{
				FullMethod: "/pkg.Greeter/SayHello",
			}, func(ctx context.Context, req any) (any, error) {
				ctx = DisableGRPCBody(ctx, true, false)
				gotCtxLogger = builder.New(ctx)
				gotCtxLogger.Set(formatter.InfoLevel, "request processed")
				return "response", nil
			})
		})
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != "response" {
		t.Fatalf("response = %#v, want %#v", resp, "response")
	}

	requestFlag, ok := gotCtxLogger.Get(common.DisableRequestBodyKey)
	if !ok || requestFlag != true {
		t.Fatalf("%q = %#v, want true", common.DisableRequestBodyKey, requestFlag)
	}
	responseFlag, ok := gotCtxLogger.Get(common.DisableResponseBodyKey)
	if !ok || responseFlag != false {
		t.Fatalf("%q = %#v, want false", common.DisableResponseBodyKey, responseFlag)
	}

	detailsAny, ok := gotCtxLogger.Get(common.DetailsKey)
	if !ok {
		t.Fatalf("expected %q in logger context", common.DetailsKey)
	}
	details := detailsAny.(formatter.Details)
	if details.Request != nil {
		t.Fatalf("details.Request = %#v, want nil", details.Request)
	}
	if details.Response != "response" {
		t.Fatalf("details.Response = %#v, want %#v", details.Response, "response")
	}
	if requestBody, ok := gotCtxLogger.Get(common.RequestbodyKey); ok {
		t.Fatalf("request body was stored = %#v, want no stored body", requestBody)
	}
	if responseBody, ok := gotCtxLogger.Get(common.ResponsebodyKey); !ok || responseBody != "response" {
		t.Fatalf("response body stored = %#v, presence %v, want response", responseBody, ok)
	}
}

func TestDisableGRPCTraceBody(t *testing.T) {
	resetGRPCTestState(t)

	tests := []struct {
		name                string
		disableRequestBody  bool
		disableResponseBody bool
		wantRequest         any
		wantResponse        any
	}{
		{
			name:                "disables only trace request body",
			disableRequestBody:  true,
			disableResponseBody: false,
			wantRequest:         nil,
			wantResponse:        "trace-response",
		},
		{
			name:                "disables only trace response body",
			disableRequestBody:  false,
			disableResponseBody: true,
			wantRequest:         "trace-request",
			wantResponse:        nil,
		},
		{
			name:                "keeps both trace bodies",
			disableRequestBody:  false,
			disableResponseBody: false,
			wantRequest:         "trace-request",
			wantResponse:        "trace-response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctxLogger := builder.New(context.Background())
			ctx := DisableGRPCTraceBody(ctxLogger, tt.disableRequestBody, tt.disableResponseBody)
			ctxLogger = builder.New(ctx)

			requestFlag, ok := ctxLogger.Get(common.DisableTraceRequestBodyKey)
			if !ok || requestFlag != tt.disableRequestBody {
				t.Fatalf("%q = %#v, want %#v", common.DisableTraceRequestBodyKey, requestFlag, tt.disableRequestBody)
			}
			responseFlag, ok := ctxLogger.Get(common.DisableTraceResponseBodyKey)
			if !ok || responseFlag != tt.disableResponseBody {
				t.Fatalf("%q = %#v, want %#v", common.DisableTraceResponseBodyKey, responseFlag, tt.disableResponseBody)
			}

			process := &formatter.Process{
				System:   "test-service",
				Process:  "trace-process",
				Code:     http.StatusOK,
				Request:  "trace-request",
				Response: "trace-response",
			}
			ctxLogger.TraceInit(process)
			ctxLogger.TraceEnd(process)

			if process.Request != tt.wantRequest {
				t.Fatalf("process.Request = %#v, want %#v", process.Request, tt.wantRequest)
			}
			if process.Response != tt.wantResponse {
				t.Fatalf("process.Response = %#v, want %#v", process.Response, tt.wantResponse)
			}
		})
	}
}

func TestCaptureBodyStreamServerInterceptor(t *testing.T) {
	resetGRPCTestState(t)

	stream := &fakeServerStream{
		ctx:       context.Background(),
		recvItems: []any{"first", "second"},
	}
	var gotCtxLogger *builder.Context

	err := CaptureBodyStreamServerInterceptor()(nil, stream, &grpc.StreamServerInfo{
		FullMethod:     "/pkg.Greeter/StreamAlerts",
		IsServerStream: true,
		IsClientStream: true,
	}, func(srv any, stream grpc.ServerStream) error {
		gotCtxLogger = builder.New(stream.Context())
		EnableBody(gotCtxLogger, true, true)
		var first string
		if err := stream.RecvMsg(&first); err != nil {
			return err
		}
		var second string
		if err := stream.RecvMsg(&second); err != nil {
			return err
		}
		if err := stream.SendMsg("out-1"); err != nil {
			return err
		}
		return stream.SendMsg("out-2")
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	requestBody, _ := gotCtxLogger.Get(common.RequestbodyKey)
	responseBody, _ := gotCtxLogger.Get(common.ResponsebodyKey)

	requests, ok := requestBody.([]any)
	if !ok || len(requests) != 2 {
		t.Fatalf("requestBody = %#v, want 2 captured messages", requestBody)
	}
	responses, ok := responseBody.([]any)
	if !ok || len(responses) != 2 {
		t.Fatalf("responseBody = %#v, want 2 captured messages", responseBody)
	}
}

func TestGRPCMetadataCarrier(t *testing.T) {
	carrier := grpcMetadataCarrier(metadata.MD{})

	if got := carrier.Get("missing"); got != "" {
		t.Fatalf("Get(missing) = %q, want empty string", got)
	}

	carrier.Set("X-Trace-Id", "abc")
	if got := carrier.Get("x-trace-id"); got != "abc" {
		t.Fatalf("Get(x-trace-id) = %q, want %q", got, "abc")
	}

	keys := carrier.Keys()
	if len(keys) != 1 || keys[0] != "x-trace-id" {
		t.Fatalf("Keys() = %#v, want %#v", keys, []string{"x-trace-id"})
	}
}

func TestGRPCCaptureStreamHelpers(t *testing.T) {
	type contextKey string
	const testContextKey contextKey = "k"
	baseCtx := builder.New(context.WithValue(context.Background(), testContextKey, "v"))
	EnableBody(baseCtx, true, true)
	stream := &grpcCaptureStream{
		ServerStream: &fakeServerStream{
			ctx:       baseCtx,
			recvItems: []any{"hello"},
		},
		ctx: baseCtx,
	}

	if got := stream.Context(); got != baseCtx {
		t.Fatal("Context() did not return wrapped context")
	}

	var msg string
	if err := stream.RecvMsg(&msg); err != nil {
		t.Fatalf("RecvMsg() error = %v, want nil", err)
	}
	if msg != "hello" {
		t.Fatalf("RecvMsg() message = %q, want %q", msg, "hello")
	}
	if stream.requests == nil || len(stream.requests.values) != 1 {
		t.Fatalf("requests = %#v, want 1 captured value", stream.requests)
	}

	if err := stream.SendMsg("world"); err != nil {
		t.Fatalf("SendMsg() error = %v, want nil", err)
	}
	if stream.responses == nil || len(stream.responses.values) != 1 {
		t.Fatalf("responses = %#v, want 1 captured value", stream.responses)
	}
}

func TestGRPCCaptureStreamSendErrorDoesNotCaptureResponse(t *testing.T) {
	wantErr := errors.New("send failed")
	stream := &grpcCaptureStream{
		ServerStream: &fakeServerStream{
			ctx:     context.Background(),
			sendErr: wantErr,
		},
		ctx: context.Background(),
	}

	err := stream.SendMsg("world")
	if !errors.Is(err, wantErr) {
		t.Fatalf("SendMsg() error = %v, want %v", err, wantErr)
	}
	if stream.responses != nil && len(stream.responses.values) != 0 {
		t.Fatalf("responses = %#v, want no captured values", stream.responses.values)
	}
}

func TestUnaryBodyCaptureIsBoundedAndReportsTruncation(t *testing.T) {
	resetGRPCTestState(t)
	viper.Set(string(viperdata.LoggerBodyCaptureMaxBytesAtribute), 5)
	viperdata.ResetViperDataSingleton()

	var ctxLogger *builder.Context
	response, err := CaptureBodyUnaryServerInterceptor()(
		context.Background(),
		"request-secret",
		&grpc.UnaryServerInfo{FullMethod: "/pkg.Service/Call"},
		func(ctx context.Context, _ any) (any, error) {
			ctxLogger = builder.New(ctx)
			EnableBody(ctxLogger, true, true)
			ctxLogger.Details = formatter.Details{System: "test-service"}
			ctxLogger.Set(common.DetailsKey, ctxLogger.Details)
			return "response-secret", nil
		},
	)
	if err != nil || response != "response-secret" {
		t.Fatalf("interceptor response = %#v, error = %v", response, err)
	}

	for _, side := range []struct {
		bodyKey     common.KeyContex
		metadataKey common.KeyContex
		want        string
	}{
		{bodyKey: common.RequestbodyKey, metadataKey: common.RequestBodyCaptureKey, want: "reque"},
		{bodyKey: common.ResponsebodyKey, metadataKey: common.ResponseBodyCaptureKey, want: "respo"},
	} {
		body, ok := ctxLogger.Get(side.bodyKey)
		if !ok || body != side.want {
			t.Fatalf("%q = %#v, want %q", side.bodyKey, body, side.want)
		}
		metadataValue, ok := ctxLogger.Get(side.metadataKey)
		metadata, castOK := metadataValue.(formatter.BodyCaptureMetadata)
		if !ok || !castOK {
			t.Fatalf("%q = %T, want formatter.BodyCaptureMetadata", side.metadataKey, metadataValue)
		}
		if !metadata.Truncated || metadata.CapturedBytes != 5 || metadata.LimitBytes != 5 {
			t.Fatalf("%q = %#v, want truncated 5-byte capture", side.metadataKey, metadata)
		}
	}
	applyGRPCBodyDetails(ctxLogger)
	if ctxLogger.Details.RequestCapture == nil || ctxLogger.Details.ResponseCapture == nil {
		t.Fatalf("details capture metadata = %#v/%#v, want both sides", ctxLogger.Details.RequestCapture, ctxLogger.Details.ResponseCapture)
	}
}

func TestStreamingBodyCaptureUsesAggregateLimit(t *testing.T) {
	resetGRPCTestState(t)
	viper.Set(string(viperdata.LoggerBodyCaptureMaxBytesAtribute), 8)
	viperdata.ResetViperDataSingleton()

	stream := &fakeServerStream{
		ctx:       context.Background(),
		recvItems: []any{"first", "second"},
	}
	var ctxLogger *builder.Context
	err := CaptureBodyStreamServerInterceptor()(nil, stream, nil, func(_ any, wrapped grpc.ServerStream) error {
		ctxLogger = builder.New(wrapped.Context())
		EnableBody(ctxLogger, true, true)
		for range 2 {
			var input string
			if err := wrapped.RecvMsg(&input); err != nil {
				return err
			}
		}
		if err := wrapped.SendMsg("out-one"); err != nil {
			return err
		}
		return wrapped.SendMsg("out-two")
	})
	if err != nil {
		t.Fatalf("interceptor error = %v", err)
	}

	requestValue, requestOK := ctxLogger.Get(common.RequestbodyKey)
	requests, ok := requestValue.([]any)
	if !requestOK || !ok || len(requests) != 2 || requests[0] != "first" || requests[1] != "sec" {
		t.Fatalf("request capture = %#v, want [first sec]", requestValue)
	}
	responseValue, responseOK := ctxLogger.Get(common.ResponsebodyKey)
	responses, ok := responseValue.([]any)
	if !responseOK || !ok || len(responses) != 2 || responses[0] != "out-one" || responses[1] != "o" {
		t.Fatalf("response capture = %#v, want [out-one o]", responseValue)
	}
	for _, key := range []common.KeyContex{common.RequestBodyCaptureKey, common.ResponseBodyCaptureKey} {
		value, present := ctxLogger.Get(key)
		metadata, ok := value.(formatter.BodyCaptureMetadata)
		if !present || !ok || !metadata.Truncated || metadata.CapturedBytes != 8 || metadata.LimitBytes != 8 {
			t.Fatalf("%q = %#v, want truncated 8-byte capture", key, value)
		}
	}
}

func TestStructuredBodyCaptureDetachesMutableBackingStorage(t *testing.T) {
	largeBacking := make([]string, 1, 1<<18)
	largeBacking[0] = "before"
	capture := newGRPCBodyCapture(64)
	capture.add(largeBacking)

	largeBacking[0] = "after"
	captured, ok := capture.value().([]any)
	if !ok || len(captured) != 1 || captured[0] != "before" {
		t.Fatalf("capture = %#v, want detached [before]", capture.value())
	}
	if capture.metadata() != nil {
		t.Fatalf("metadata = %#v, want no truncation", capture.metadata())
	}
}

func TestStreamingBodyCaptureChargesEmptyMessagesAgainstLimit(t *testing.T) {
	capture := newGRPCBodyCapture(2)
	capture.add("")
	capture.add([]byte{})
	capture.add("")

	values, ok := capture.value().([]any)
	if !ok || len(values) != 2 {
		t.Fatalf("capture = %#v, want exactly two retained empty messages", capture.value())
	}
	metadata := capture.metadata()
	if metadata == nil || !metadata.Truncated || metadata.CapturedBytes != 2 || metadata.LimitBytes != 2 {
		t.Fatalf("metadata = %#v, want truncated 2-byte capture", metadata)
	}
}

func TestInitLoggerStreamServerInterceptor(t *testing.T) {
	resetGRPCTestState(t)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-request-id", "stream-123"))
	stream := &fakeServerStream{ctx: ctx}
	var gotCtxLogger *builder.Context

	err := InitLoggerStreamServerInterceptor()(nil, stream, &grpc.StreamServerInfo{
		FullMethod:     "/pkg.Greeter/StreamAlerts",
		IsServerStream: true,
	}, func(srv any, stream grpc.ServerStream) error {
		gotCtxLogger = builder.New(stream.Context())
		return nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	detailsAny, ok := gotCtxLogger.Get(common.DetailsKey)
	if !ok {
		t.Fatalf("expected %q in logger context", common.DetailsKey)
	}
	details := detailsAny.(formatter.Details)
	if details.Method != "StreamAlerts" {
		t.Fatalf("details.Method = %q, want %q", details.Method, "StreamAlerts")
	}
	if details.Path != "/pkg.Greeter/StreamAlerts" {
		t.Fatalf("details.Path = %q, want %q", details.Path, "/pkg.Greeter/StreamAlerts")
	}
	if got := details.Headers.Get("X-Request-Id"); got != "stream-123" {
		t.Fatalf("details.Headers[X-Request-Id] = %q, want %q", got, "stream-123")
	}
}

func TestLoggerWithConfigStreamServerInterceptor(t *testing.T) {
	resetGRPCTestState(t)

	stream := &fakeServerStream{ctx: context.Background()}
	var gotCtxLogger *builder.Context

	err := InitLoggerStreamServerInterceptor()(nil, stream, &grpc.StreamServerInfo{
		FullMethod:     "/pkg.Greeter/StreamAlerts",
		IsServerStream: true,
	}, func(srv any, stream grpc.ServerStream) error {
		return LoggerWithConfigStreamServerInterceptor()(srv, stream, &grpc.StreamServerInfo{
			FullMethod:     "/pkg.Greeter/StreamAlerts",
			IsServerStream: true,
		}, func(srv any, stream grpc.ServerStream) error {
			return CaptureBodyStreamServerInterceptor()(srv, stream, &grpc.StreamServerInfo{
				FullMethod:     "/pkg.Greeter/StreamAlerts",
				IsServerStream: true,
			}, func(srv any, stream grpc.ServerStream) error {
				gotCtxLogger = builder.New(stream.Context())
				gotCtxLogger.Set(common.DisableRequestBodyKey, false)
				gotCtxLogger.Set(common.DisableResponseBodyKey, false)
				gotCtxLogger.Set(formatter.InfoLevel, "stream processed")
				if err := stream.SendMsg("out"); err != nil {
					return err
				}
				return nil
			})
		})
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}

	detailsAny, ok := gotCtxLogger.Get(common.DetailsKey)
	if !ok {
		t.Fatalf("expected %q in logger context", common.DetailsKey)
	}
	details := detailsAny.(formatter.Details)
	if details.Response != "out" {
		t.Fatalf("details.Response = %#v, want %#v", details.Response, "out")
	}
	if details.Method != "StreamAlerts" {
		t.Fatalf("details.Method = %q, want %q", details.Method, "StreamAlerts")
	}
	if details.Path != "/pkg.Greeter/StreamAlerts" {
		t.Fatalf("details.Path = %q, want %q", details.Path, "/pkg.Greeter/StreamAlerts")
	}
}

func TestExtractGRPCContextWithoutMetadata(t *testing.T) {
	got := extractGRPCContext(context.Background())
	if got == nil {
		t.Fatal("extractGRPCContext() returned nil context")
	}
}

func TestNewGRPCLoggerContextWithoutPeerOrMetadata(t *testing.T) {
	resetGRPCTestState(t)

	ctx, span := newGRPCLoggerContext(context.Background(), context.Background())
	defer span.End()

	ctxLogger := builder.New(ctx)
	detailsAny, ok := ctxLogger.Get(common.DetailsKey)
	if !ok {
		t.Fatalf("expected %q in logger context", common.DetailsKey)
	}
	details := detailsAny.(formatter.Details)
	if details.Client != "" {
		t.Fatalf("details.Client = %q, want empty", details.Client)
	}
	if details.Headers != nil {
		t.Fatalf("details.Headers = %#v, want nil", details.Headers)
	}
}

func TestMetadataToHTTPHeader(t *testing.T) {
	if got := metadataToHTTPHeader(nil); got != nil {
		t.Fatalf("metadataToHTTPHeader(nil) = %#v, want nil", got)
	}

	got := metadataToHTTPHeader(metadata.Pairs("x-request-id", "abc", "content-type", "application/json"))
	want := http.Header{
		"X-Request-Id": {"abc"},
		"Content-Type": {"application/json"},
	}
	if got.Get("X-Request-Id") != want.Get("X-Request-Id") {
		t.Fatalf("X-Request-Id = %q, want %q", got.Get("X-Request-Id"), want.Get("X-Request-Id"))
	}
	if got.Get("Content-Type") != want.Get("Content-Type") {
		t.Fatalf("Content-Type = %q, want %q", got.Get("Content-Type"), want.Get("Content-Type"))
	}
}

func TestCollapseCapturedBodies(t *testing.T) {
	if got := collapseCapturedBodies(nil); got != nil {
		t.Fatalf("collapseCapturedBodies(nil) = %#v, want nil", got)
	}
	if got := collapseCapturedBodies([]any{"one"}); got != "one" {
		t.Fatalf("collapseCapturedBodies(single) = %#v, want %#v", got, "one")
	}
	got := collapseCapturedBodies([]any{"one", "two"})
	items, ok := got.([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("collapseCapturedBodies(many) = %#v, want 2 items", got)
	}
}

func TestApplyGRPCBodyDetailsGuards(t *testing.T) {
	resetGRPCTestState(t)

	t.Run("returns when disable flag has invalid type", func(t *testing.T) {
		ctxLogger := builder.New(context.Background())
		ctxLogger.Set(common.DisableRequestBodyKey, "bad")
		ctxLogger.Details = formatter.Details{System: "svc"}
		ctxLogger.Set(common.RequestbodyKey, "req")
		applyGRPCBodyDetails(ctxLogger)
		if ctxLogger.Details.Request != nil {
			t.Fatalf("Details.Request = %#v, want nil", ctxLogger.Details.Request)
		}
	})

	t.Run("handles request and response flags independently", func(t *testing.T) {
		ctxLogger := builder.New(context.Background())
		ctxLogger.Details = formatter.Details{System: "svc"}
		ctxLogger.Set(common.DisableRequestBodyKey, true)
		ctxLogger.Set(common.DisableResponseBodyKey, false)
		ctxLogger.Set(common.RequestbodyKey, "req")
		ctxLogger.Set(common.ResponsebodyKey, "resp")
		applyGRPCBodyDetails(ctxLogger)
		if ctxLogger.Details.Request != nil {
			t.Fatalf("Details.Request = %#v, want nil", ctxLogger.Details.Request)
		}
		if ctxLogger.Details.Response != "resp" {
			t.Fatalf("Details.Response = %#v, want %#v", ctxLogger.Details.Response, "resp")
		}
	})

	t.Run("supports string body flags from external callers", func(t *testing.T) {
		ctxLogger := builder.New(context.Background())
		ctxLogger.Details = formatter.Details{System: "svc"}
		ctxLogger.Set(string(common.DisableRequestBodyKey), false)
		ctxLogger.Set(string(common.DisableResponseBodyKey), true)
		ctxLogger.Set(common.RequestbodyKey, "req")
		ctxLogger.Set(common.ResponsebodyKey, "resp")
		applyGRPCBodyDetails(ctxLogger)
		if ctxLogger.Details.Request != "req" {
			t.Fatalf("Details.Request = %#v, want %#v", ctxLogger.Details.Request, "req")
		}
		if ctxLogger.Details.Response != nil {
			t.Fatalf("Details.Response = %#v, want nil", ctxLogger.Details.Response)
		}
	})

	t.Run("returns when details key missing and details struct empty", func(t *testing.T) {
		ctxLogger := builder.New(context.Background())
		ctxLogger.Set(common.RequestbodyKey, "req")
		applyGRPCBodyDetails(ctxLogger)
	})

	t.Run("returns when details key has wrong type", func(t *testing.T) {
		ctxLogger := builder.New(context.Background())
		ctxLogger.Set(common.DetailsKey, "bad")
		ctxLogger.Set(common.RequestbodyKey, "req")
		applyGRPCBodyDetails(ctxLogger)
	})
}

func TestSetGRPCMethodDetails(t *testing.T) {
	resetGRPCTestState(t)

	ctxLogger := builder.New(context.Background())
	ctxLogger.Details = formatter.Details{
		System:   "test-service",
		Client:   "client",
		Protocol: "gRPC",
	}

	setGRPCMethodDetails(ctxLogger, "/pkg.Greeter/SayHello")

	if ctxLogger.Details.Method != "SayHello" {
		t.Fatalf("Details.Method = %q, want %q", ctxLogger.Details.Method, "SayHello")
	}
	if ctxLogger.Details.Path != "/pkg.Greeter/SayHello" {
		t.Fatalf("Details.Path = %q, want %q", ctxLogger.Details.Path, "/pkg.Greeter/SayHello")
	}
	detailsAny, ok := ctxLogger.Get(common.DetailsKey)
	if !ok {
		t.Fatalf("expected %q in logger context", common.DetailsKey)
	}
	details := detailsAny.(formatter.Details)
	if details.Method != "SayHello" || details.Path != "/pkg.Greeter/SayHello" {
		t.Fatalf("details from context = %#v, want gRPC method details", details)
	}
}

func TestWriteGRPCLogBranches(t *testing.T) {
	resetGRPCTestState(t)

	t.Run("returns when grpc logger is disabled", func(t *testing.T) {
		viper.Set(string(viperdata.GRPCLoggerWithConfigEnabledAtribute), false)
		viperdata.ResetViperDataSingleton()
		ctxLogger := builder.New(context.Background())
		ctxLogger.Method = "preset"
		ctxLogger.Line = 7
		ctxLogger.Set(formatter.InfoLevel, "info")
		writeGRPCLog(ctxLogger, "/pkg.Greeter/SayHello", nil)
		if ctxLogger.Method != "preset" || ctxLogger.Line != 7 {
			t.Fatalf("method/line changed unexpectedly: %q %d", ctxLogger.Method, ctxLogger.Line)
		}
		viper.Set(string(viperdata.GRPCLoggerWithConfigEnabledAtribute), true)
		viperdata.ResetViperDataSingleton()
	})

	t.Run("returns when grpc function is skipped", func(t *testing.T) {
		viper.Set(string(viperdata.GRPCLoggerWithConfigSkipFunctionAtribute), []string{"SayHello"})
		viperdata.ResetViperDataSingleton()
		ctxLogger := builder.New(context.Background())
		ctxLogger.Method = "preset"
		ctxLogger.Line = 7
		ctxLogger.Set(formatter.InfoLevel, "info")
		writeGRPCLog(ctxLogger, "/pkg.Greeter/SayHello", nil)
		if ctxLogger.Method != "preset" || ctxLogger.Line != 7 {
			t.Fatalf("method/line changed unexpectedly: %q %d", ctxLogger.Method, ctxLogger.Line)
		}
		viper.Set(string(viperdata.GRPCLoggerWithConfigSkipFunctionAtribute), []string{})
		viperdata.ResetViperDataSingleton()
	})

	t.Run("debug branch", func(t *testing.T) {
		ctxLogger := builder.New(context.Background())
		PrintDebug(ctxLogger, "debug")
		writeGRPCLog(ctxLogger, "/pkg.Greeter/SayHello", nil)
		if ctxLogger.Method == "" || ctxLogger.Line == 0 {
			t.Fatalf("method/line = %q/%d, want caller metadata", ctxLogger.Method, ctxLogger.Line)
		}
	})

	t.Run("warn branch", func(t *testing.T) {
		ctxLogger := builder.New(context.Background())
		PrintWarn(ctxLogger, "warn")
		writeGRPCLog(ctxLogger, "/pkg.Greeter/SayHello", nil)
	})

	t.Run("error level wrong type falls back to handler error", func(t *testing.T) {
		ctxLogger := builder.New(context.Background())
		ctxLogger.Set(formatter.ErrorLevel, "not-an-error")
		writeGRPCLog(ctxLogger, "/pkg.Greeter/SayHello", errors.New("boom"))
	})

	t.Run("authorization handler error is not logged", func(t *testing.T) {
		ctxLogger := builder.New(context.Background())
		ctxLogger.Method = "preset"
		ctxLogger.Line = 7
		writeGRPCLog(ctxLogger, "/pkg.Greeter/SayHello", status.Error(codes.Unauthenticated, "jwt unauthorized"))
		if ctxLogger.Method != "preset" || ctxLogger.Line != 7 {
			t.Fatalf("method/line changed unexpectedly: %q %d", ctxLogger.Method, ctxLogger.Line)
		}
	})

	t.Run("authorization error level is not logged", func(t *testing.T) {
		ctxLogger := builder.New(context.Background())
		ctxLogger.Method = "preset"
		ctxLogger.Line = 7
		ctxLogger.Set(formatter.ErrorLevel, status.Error(codes.PermissionDenied, "jwt forbidden"))
		writeGRPCLog(ctxLogger, "/pkg.Greeter/SayHello", nil)
		if ctxLogger.Method != "preset" || ctxLogger.Line != 7 {
			t.Fatalf("method/line changed unexpectedly: %q %d", ctxLogger.Method, ctxLogger.Line)
		}
	})

	t.Run("error branch", func(t *testing.T) {
		ctxLogger := builder.New(context.Background())
		PrintError(ctxLogger, errors.New("boom"))
		writeGRPCLog(ctxLogger, "/pkg.Greeter/SayHello", nil)
	})
}

func TestIsAuthorizationGRPCError(t *testing.T) {
	if !isAuthorizationGRPCError(status.Error(codes.Unauthenticated, "missing jwt")) {
		t.Fatal("expected unauthenticated error to be treated as authorization error")
	}
	if !isAuthorizationGRPCError(status.Error(codes.PermissionDenied, "forbidden")) {
		t.Fatal("expected permission denied error to be treated as authorization error")
	}
	if isAuthorizationGRPCError(status.Error(codes.Internal, "boom")) {
		t.Fatal("expected internal error not to be treated as authorization error")
	}
	if isAuthorizationGRPCError(nil) {
		t.Fatal("expected nil not to be treated as authorization error")
	}
}

func TestShouldSkipGRPCFunction(t *testing.T) {
	resetGRPCTestState(t)

	viper.Set(string(viperdata.GRPCLoggerWithConfigSkipFunctionAtribute), []string{"SayHello", "/pkg.Greeter/StreamAlerts", " "})
	viperdata.ResetViperDataSingleton()

	if !shouldSkipGRPCFunction("/pkg.Greeter/SayHello") {
		t.Fatal("expected SayHello to be skipped by function name")
	}
	if !shouldSkipGRPCFunction("/pkg.Greeter/StreamAlerts") {
		t.Fatal("expected StreamAlerts to be skipped by full method")
	}
	if shouldSkipGRPCFunction("/pkg.Greeter/CreateChat") {
		t.Fatal("expected CreateChat not to be skipped")
	}
}

func TestHasError(t *testing.T) {
	if hasError(nil) {
		t.Fatal("hasError(nil) = true, want false")
	}

	var typedNilErr error = (*nilPointerError)(nil)
	if hasError(typedNilErr) {
		t.Fatal("hasError(typed nil) = true, want false")
	}

	if !hasError(errors.New("boom")) {
		t.Fatal("hasError(non-nil error) = false, want true")
	}
}
