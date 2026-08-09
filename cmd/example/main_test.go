// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	pb "github.com/PointerByte/forge-go/config/proto"
	serverGRPC "github.com/PointerByte/forge-go/config/server/grpc"
	"github.com/PointerByte/forge-go/logger/builder"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type fakeGRPCConfig struct {
	registerFn  RegisterServiceFuncCapture
	registerErr error
	serveErr    error
	serveCalls  int
}

type RegisterServiceFuncCapture struct {
	fn serverGRPC.RegisterServiceFunc
}

func (f *fakeGRPCConfig) SetAddress(string)        {}
func (f *fakeGRPCConfig) SetListener(net.Listener) {}
func (f *fakeGRPCConfig) Register(register serverGRPC.RegisterServiceFunc) error {
	f.registerFn.fn = register
	return f.registerErr
}
func (f *fakeGRPCConfig) Serve() error {
	f.serveCalls++
	return f.serveErr
}
func (f *fakeGRPCConfig) GracefulStop()             {}
func (f *fakeGRPCConfig) Stop()                     {}
func (f *fakeGRPCConfig) GetServer() *grpc.Server   { return nil }
func (f *fakeGRPCConfig) GetListener() net.Listener { return nil }

type fakeServiceRegistrar struct {
	serviceDesc *grpc.ServiceDesc
	impl        any
}

func (f *fakeServiceRegistrar) RegisterService(desc *grpc.ServiceDesc, impl any) {
	f.serviceDesc = desc
	f.impl = impl
}

type fakeClientStreamingServer struct {
	ctx      context.Context
	messages []*pb.ChatMessage
	index    int
	summary  *pb.ChatSummary
	sendErr  error
	recvErr  error
}

func (f *fakeClientStreamingServer) SetHeader(metadata.MD) error  { return nil }
func (f *fakeClientStreamingServer) SendHeader(metadata.MD) error { return nil }
func (f *fakeClientStreamingServer) SetTrailer(metadata.MD)       {}
func (f *fakeClientStreamingServer) Context() context.Context     { return f.ctx }
func (f *fakeClientStreamingServer) SendMsg(any) error            { return nil }
func (f *fakeClientStreamingServer) RecvMsg(any) error            { return nil }
func (f *fakeClientStreamingServer) Recv() (*pb.ChatMessage, error) {
	if f.recvErr != nil {
		return nil, f.recvErr
	}
	if f.index >= len(f.messages) {
		return nil, io.EOF
	}
	msg := f.messages[f.index]
	f.index++
	return msg, nil
}
func (f *fakeClientStreamingServer) SendAndClose(res *pb.ChatSummary) error {
	f.summary = res
	return f.sendErr
}

type fakeBidiStreamingServer struct {
	ctx       context.Context
	recvMsgs  []*pb.AlertMessage
	recvIndex int
	sentMsgs  []*pb.AlertMessage
	sendErr   error
	recvErr   error
}

func (f *fakeBidiStreamingServer) SetHeader(metadata.MD) error  { return nil }
func (f *fakeBidiStreamingServer) SendHeader(metadata.MD) error { return nil }
func (f *fakeBidiStreamingServer) SetTrailer(metadata.MD)       {}
func (f *fakeBidiStreamingServer) Context() context.Context     { return f.ctx }
func (f *fakeBidiStreamingServer) SendMsg(any) error            { return nil }
func (f *fakeBidiStreamingServer) RecvMsg(any) error            { return nil }
func (f *fakeBidiStreamingServer) Recv() (*pb.AlertMessage, error) {
	if f.recvErr != nil {
		return nil, f.recvErr
	}
	if f.recvIndex >= len(f.recvMsgs) {
		return nil, io.EOF
	}
	msg := f.recvMsgs[f.recvIndex]
	f.recvIndex++
	return msg, nil
}
func (f *fakeBidiStreamingServer) Send(msg *pb.AlertMessage) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sentMsgs = append(f.sentMsgs, msg)
	return nil
}

func resetMainTestState(t *testing.T) {
	t.Helper()

	origRunGin := runGinExampleFn
	origRunGRPC := runGRPCExampleFn
	origLogFatal := logFatalFn
	origLogPrintf := logPrintfFn
	origCreateGinApp := createGinAppFn
	origGetGinRoute := getGinRouteFn
	origStartGin := startGinServerFn
	origNewGRPC := newGRPCServerFn
	origMode := gin.Mode()

	t.Cleanup(func() {
		runGinExampleFn = origRunGin
		runGRPCExampleFn = origRunGRPC
		logFatalFn = origLogFatal
		logPrintfFn = origLogPrintf
		createGinAppFn = origCreateGinApp
		getGinRouteFn = origGetGinRoute
		startGinServerFn = origStartGin
		newGRPCServerFn = origNewGRPC
		gin.SetMode(origMode)
		os.Unsetenv(exampleModeEnv)
		viperdata.ResetViperDataSingleton()
	})

	gin.SetMode(gin.TestMode)
	builder.EnableModeTest()
	viperdata.ResetViperDataSingleton()
}

func TestMainDispatch(t *testing.T) {
	t.Run("gin", func(t *testing.T) {
		resetMainTestState(t)
		var called bool
		runGinExampleFn = func() error { called = true; return nil }
		logFatalFn = func(...any) { t.Fatal("logFatalFn should not be called") }
		t.Setenv(exampleModeEnv, exampleModeGin)

		main()

		if !called {
			t.Fatal("expected gin example to run")
		}
	})

	t.Run("grpc", func(t *testing.T) {
		resetMainTestState(t)
		var called bool
		runGRPCExampleFn = func() error { called = true; return nil }
		logFatalFn = func(...any) { t.Fatal("logFatalFn should not be called") }
		t.Setenv(exampleModeEnv, exampleModeGRPC)

		main()

		if !called {
			t.Fatal("expected grpc example to run")
		}
	})

	t.Run("default", func(t *testing.T) {
		resetMainTestState(t)
		var message string
		logPrintfFn = func(format string, args ...any) { message = format }

		main()

		if message == "" {
			t.Fatal("expected default usage log")
		}
	})

	t.Run("gin error logs fatal", func(t *testing.T) {
		resetMainTestState(t)
		wantErr := errors.New("gin failed")
		runGinExampleFn = func() error { return wantErr }
		var fatalArg any
		logFatalFn = func(args ...any) { fatalArg = args[0] }
		t.Setenv(exampleModeEnv, exampleModeGin)

		main()

		if !errors.Is(fatalArg.(error), wantErr) {
			t.Fatalf("fatalArg = %v, want %v", fatalArg, wantErr)
		}
	})

	t.Run("grpc error logs fatal", func(t *testing.T) {
		resetMainTestState(t)
		wantErr := errors.New("grpc failed")
		runGRPCExampleFn = func() error { return wantErr }
		var fatalArg any
		logFatalFn = func(args ...any) { fatalArg = args[0] }
		t.Setenv(exampleModeEnv, exampleModeGRPC)

		main()

		if !errors.Is(fatalArg.(error), wantErr) {
			t.Fatalf("fatalArg = %v, want %v", fatalArg, wantErr)
		}
	})
}

func TestRunGinExample(t *testing.T) {
	t.Run("create app error", func(t *testing.T) {
		resetMainTestState(t)
		wantErr := errors.New("create app")
		createGinAppFn = func() (*http.Server, error) { return nil, wantErr }

		err := runGinExample()
		if !errors.Is(err, wantErr) {
			t.Fatalf("runGinExample() error = %v, want %v", err, wantErr)
		}
	})

	t.Run("missing route group", func(t *testing.T) {
		resetMainTestState(t)
		createGinAppFn = func() (*http.Server, error) { return &http.Server{}, nil }
		getGinRouteFn = func(string) *gin.RouterGroup { return nil }

		err := runGinExample()
		if err == nil {
			t.Fatal("runGinExample() succeeded unexpectedly")
		}
	})

	t.Run("success registers hello route", func(t *testing.T) {
		resetMainTestState(t)
		router := gin.New()
		group := router.Group("/api/v1")
		createGinAppFn = func() (*http.Server, error) { return &http.Server{Handler: router}, nil }
		getGinRouteFn = func(string) *gin.RouterGroup { return group }
		var started *http.Server
		startGinServerFn = func(srv *http.Server) {
			started = srv
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/hello", nil)
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /api/v1/hello status = %d", rec.Code)
			}
			if body := rec.Body.String(); body == "" {
				t.Fatal("expected response body")
			}
		}

		if err := runGinExample(); err != nil {
			t.Fatalf("runGinExample() error = %v", err)
		}
		if started == nil {
			t.Fatal("expected server start to be invoked")
		}
	})
}

func TestRunGRPCExample(t *testing.T) {
	t.Run("register error", func(t *testing.T) {
		resetMainTestState(t)
		wantErr := errors.New("register failed")
		fake := &fakeGRPCConfig{registerErr: wantErr}
		newGRPCServerFn = func() serverGRPC.IConfig { return fake }

		err := runGRPCExample()
		if !errors.Is(err, wantErr) {
			t.Fatalf("runGRPCExample() error = %v, want %v", err, wantErr)
		}
	})

	t.Run("serve error", func(t *testing.T) {
		resetMainTestState(t)
		wantErr := errors.New("serve failed")
		fake := &fakeGRPCConfig{serveErr: wantErr}
		newGRPCServerFn = func() serverGRPC.IConfig { return fake }

		err := runGRPCExample()
		if !errors.Is(err, wantErr) {
			t.Fatalf("runGRPCExample() error = %v, want %v", err, wantErr)
		}
		if fake.registerFn.fn == nil {
			t.Fatal("expected service registration to be captured")
		}

		registrar := &fakeServiceRegistrar{}
		fake.registerFn.fn(registrar)
		if registrar.serviceDesc == nil || registrar.impl == nil {
			t.Fatal("expected greeter service to be registered")
		}
		if fake.serveCalls != 1 {
			t.Fatalf("serveCalls = %d, want 1", fake.serveCalls)
		}
	})
}

func TestExampleGreeterServerSayHello(t *testing.T) {
	resetMainTestState(t)

	server := exampleGreeterServer{}
	resp, err := server.SayHello(context.Background(), &pb.HelloRequest{Name: "Manuel"})
	if err != nil {
		t.Fatalf("SayHello() error = %v", err)
	}
	if resp.GetMessage() != "hello Manuel from GoForge gRPC" {
		t.Fatalf("SayHello() message = %q", resp.GetMessage())
	}
}

func TestExampleGreeterServerCreateChat(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		resetMainTestState(t)
		stream := &fakeClientStreamingServer{
			ctx: context.Background(),
			messages: []*pb.ChatMessage{
				{Message: "first"},
				{Message: "second"},
			},
		}

		err := exampleGreeterServer{}.CreateChat(stream)
		if err != nil {
			t.Fatalf("CreateChat() error = %v", err)
		}
		want := &pb.ChatSummary{ChatId: "example-chat", TotalMessages: 2, LastMessage: "second"}
		if !reflect.DeepEqual(stream.summary, want) {
			t.Fatalf("summary = %#v, want %#v", stream.summary, want)
		}
	})

	t.Run("recv error", func(t *testing.T) {
		resetMainTestState(t)
		wantErr := errors.New("recv failed")
		stream := &fakeClientStreamingServer{
			ctx:     context.Background(),
			recvErr: wantErr,
		}

		err := exampleGreeterServer{}.CreateChat(stream)
		if !errors.Is(err, wantErr) {
			t.Fatalf("CreateChat() error = %v, want %v", err, wantErr)
		}
	})

	t.Run("send and close error", func(t *testing.T) {
		resetMainTestState(t)
		wantErr := errors.New("close failed")
		stream := &fakeClientStreamingServer{
			ctx:     context.Background(),
			sendErr: wantErr,
		}

		err := exampleGreeterServer{}.CreateChat(stream)
		if !errors.Is(err, wantErr) {
			t.Fatalf("CreateChat() error = %v, want %v", err, wantErr)
		}
	})
}

func TestExampleGreeterServerStreamAlerts(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		resetMainTestState(t)
		stream := &fakeBidiStreamingServer{
			ctx: context.Background(),
			recvMsgs: []*pb.AlertMessage{
				{AlertId: "a1", Level: "WARN", Message: "disk"},
			},
		}

		err := exampleGreeterServer{}.StreamAlerts(stream)
		if err != nil {
			t.Fatalf("StreamAlerts() error = %v", err)
		}
		if len(stream.sentMsgs) != 1 {
			t.Fatalf("sentMsgs len = %d, want 1", len(stream.sentMsgs))
		}
		if stream.sentMsgs[0].GetMessage() != "echo: disk" {
			t.Fatalf("sent message = %q", stream.sentMsgs[0].GetMessage())
		}
		if stream.sentMsgs[0].GetSource() != "GoForge-example" {
			t.Fatalf("sent source = %q", stream.sentMsgs[0].GetSource())
		}
	})

	t.Run("recv error", func(t *testing.T) {
		resetMainTestState(t)
		wantErr := errors.New("recv failed")
		stream := &fakeBidiStreamingServer{
			ctx:     context.Background(),
			recvErr: wantErr,
		}

		err := exampleGreeterServer{}.StreamAlerts(stream)
		if !errors.Is(err, wantErr) {
			t.Fatalf("StreamAlerts() error = %v, want %v", err, wantErr)
		}
	})

	t.Run("send error", func(t *testing.T) {
		resetMainTestState(t)
		wantErr := errors.New("send failed")
		stream := &fakeBidiStreamingServer{
			ctx: context.Background(),
			recvMsgs: []*pb.AlertMessage{
				{AlertId: "a1", Level: "WARN", Message: "disk"},
			},
			sendErr: wantErr,
		}

		err := exampleGreeterServer{}.StreamAlerts(stream)
		if !errors.Is(err, wantErr) {
			t.Fatalf("StreamAlerts() error = %v, want %v", err, wantErr)
		}
	})
}
