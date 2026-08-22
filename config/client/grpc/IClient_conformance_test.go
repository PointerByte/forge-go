// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"strings"
	"testing"

	pb "github.com/PointerByte/forge-go/config/proto"
	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/PointerByte/forge-go/logger/common"
	"github.com/PointerByte/forge-go/logger/formatter"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestTraceUnaryClientInterceptorPropagatesInvocationError(t *testing.T) {
	resetClientGRPCTestState(t)

	ctxLogger := builder.New(context.Background())
	ctxLogger.SetTraceID("trace-grpc-error")
	ctx := metadata.AppendToOutgoingContext(ctxLogger, "x-request-id", "req-error")
	conn, err := grpc.NewClient("passthrough:///trace-unary-error", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient() failed: %v", err)
	}
	defer conn.Close()

	wantErr := status.Error(codes.PermissionDenied, "access denied")
	var gotTraceID string
	var gotRequestID string
	err = traceUnaryClientInterceptor()(
		ctx,
		"/proto.Greeter/SayHello",
		&pb.HelloRequest{Name: "Trace"},
		&pb.HelloReply{},
		conn,
		func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
			md, ok := metadata.FromOutgoingContext(ctx)
			if !ok {
				t.Fatal("invoker context has no outgoing metadata")
			}
			gotTraceID = firstMetadataValue(md, strings.ToLower(common.TraceIDHeader))
			gotRequestID = firstMetadataValue(md, "x-request-id")
			return wantErr
		},
	)

	if err != wantErr {
		t.Fatalf("interceptor() error = %v, want original error %v", err, wantErr)
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status.Code(error) = %v, want %v", status.Code(err), codes.PermissionDenied)
	}
	if gotTraceID != "trace-grpc-error" {
		t.Fatalf("x-trace-id = %q, want %q", gotTraceID, "trace-grpc-error")
	}
	if gotRequestID != "req-error" {
		t.Fatalf("x-request-id = %q, want %q", gotRequestID, "req-error")
	}
}

func TestBuildServiceRecordsUnaryInvocationError(t *testing.T) {
	resetClientGRPCTestState(t)

	service := &formatter.Process{}
	rpcErr := status.Error(codes.PermissionDenied, "access denied")
	if err := buildService(service, "req", "resp", "/pkg.Service/Call", "localhost:50051", context.Background(), rpcErr); err != nil {
		t.Fatalf("buildService() error = %v", err)
	}
	if service.Status != formatter.ERROR || service.Code != int64(codes.PermissionDenied) {
		t.Fatalf("error trace status/code = %v/%d, want %v/%d", service.Status, service.Code, formatter.ERROR, codes.PermissionDenied)
	}
	if service.Request != "req" || service.Response != rpcErr.Error() {
		t.Fatalf("error trace bodies = %#v/%#v", service.Request, service.Response)
	}
}

func firstMetadataValue(md metadata.MD, key string) string {
	values := md.Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
