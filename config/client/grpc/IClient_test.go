// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/PointerByte/forge-go/config/proto"
	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/PointerByte/forge-go/logger/common"
	"github.com/PointerByte/forge-go/logger/formatter"
	"github.com/golang/mock/gomock"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

type mockClient struct {
	connectErr   error
	closeErr     error
	conn         *grpc.ClientConn
	connectCalls int
	closeCalls   int
}

func (m *mockClient) SetAddress(string)                 {}
func (m *mockClient) SetConn(*grpc.ClientConn)          {}
func (m *mockClient) SetContext(context.Context)        {}
func (m *mockClient) SetDialOptions(...grpc.DialOption) {}
func (m *mockClient) Connect() error                    { m.connectCalls++; return m.connectErr }
func (m *mockClient) Close() error                      { m.closeCalls++; return m.closeErr }
func (m *mockClient) GetConn() *grpc.ClientConn         { return m.conn }

type greeterService struct {
	pb.UnimplementedGreeterServer
}

func (s greeterService) SayHello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloReply, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok && len(md.Get("x-request-id")) > 0 {
		builder.New(ctx).Set(formatter.InfoLevel, "hello with metadata")
	}
	builder.New(ctx).Set(formatter.InfoLevel, "say hello handled")
	return &pb.HelloReply{Message: "hello " + req.GetName()}, nil
}

func (s greeterService) CreateChat(stream grpc.ClientStreamingServer[pb.ChatMessage, pb.ChatSummary]) error {
	builder.New(stream.Context()).Set(formatter.InfoLevel, "create chat handled")
	for {
		_, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&pb.ChatSummary{ChatId: "chat-1"})
		}
		if err != nil {
			return err
		}
	}
}

func (s greeterService) StreamAlerts(stream grpc.BidiStreamingServer[pb.AlertMessage, pb.AlertMessage]) error {
	builder.New(stream.Context()).Set(formatter.InfoLevel, "stream alerts handled")
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.Send(&pb.AlertMessage{
			AlertId:       msg.GetAlertId(),
			Source:        msg.GetSource(),
			Level:         msg.GetLevel(),
			Message:       msg.GetMessage(),
			CreatedAtUnix: msg.GetCreatedAtUnix(),
		}); err != nil {
			return err
		}
	}
}

type generatedCertSet struct {
	serverCertFile string
	serverKeyFile  string
	clientCertFile string
	clientKeyFile  string
	caCertFile     string
	caPool         *x509.CertPool
}

type fakeClientStream struct {
	ctx       context.Context
	sendErr   error
	recvErr   error
	recvValue any
	recvCount int
}

func (f *fakeClientStream) Header() (metadata.MD, error) { return metadata.MD{}, nil }
func (f *fakeClientStream) Trailer() metadata.MD         { return metadata.MD{} }
func (f *fakeClientStream) CloseSend() error             { return nil }
func (f *fakeClientStream) Context() context.Context     { return f.ctx }
func (f *fakeClientStream) SendMsg(any) error            { return f.sendErr }
func (f *fakeClientStream) RecvMsg(m any) error {
	if f.recvErr != nil {
		return f.recvErr
	}
	if f.recvCount > 0 {
		return io.EOF
	}
	f.recvCount++
	reply, ok := m.(*pb.AlertMessage)
	if !ok {
		return nil
	}
	if value, ok := f.recvValue.(*pb.AlertMessage); ok && value != nil {
		reply.AlertId = value.GetAlertId()
		reply.Source = value.GetSource()
		reply.Level = value.GetLevel()
		reply.Message = value.GetMessage()
		reply.CreatedAtUnix = value.GetCreatedAtUnix()
	}
	return nil
}

func resetClientGRPCTestState(t *testing.T) {
	t.Helper()

	originalNewClient := newGRPCClient
	originalTLSConfig := clientTLSConfig
	originalLoadX509KeyPairFn := loadX509KeyPairFn
	originalReadFileFn := readFileFn
	originalNewCertPoolFn := newCertPoolFn

	t.Cleanup(func() {
		newGRPCClient = originalNewClient
		clientTLSConfig = originalTLSConfig
		loadX509KeyPairFn = originalLoadX509KeyPairFn
		readFileFn = originalReadFileFn
		newCertPoolFn = originalNewCertPoolFn
		viper.Reset()
	})

	viper.Reset()
	clientTLSConfig = nil
	viper.Set("app.name", "grpc-client-test")
	viper.Set("logger.ignoredHeaders", []string{})
	viper.Set("logger.modeTest", false)
}

func writeGeneratedCertificateFiles(t *testing.T) generatedCertSet {
	t.Helper()

	caCertPEM, caKeyPEM, caCert := generateCertificateAuthority(t)
	serverCertPEM, serverKeyPEM := generateSignedCertificate(t, caCert, caKeyPEM, false)
	clientCertPEM, clientKeyPEM := generateSignedCertificate(t, caCert, caKeyPEM, true)

	dir := t.TempDir()
	serverCertFile := filepath.Join(dir, "server-cert.pem")
	serverKeyFile := filepath.Join(dir, "server-key.pem")
	clientCertFile := filepath.Join(dir, "client-cert.pem")
	clientKeyFile := filepath.Join(dir, "client-key.pem")
	caCertFile := filepath.Join(dir, "ca.pem")

	mustWriteFile(t, serverCertFile, serverCertPEM)
	mustWriteFile(t, serverKeyFile, serverKeyPEM)
	mustWriteFile(t, clientCertFile, clientCertPEM)
	mustWriteFile(t, clientKeyFile, clientKeyPEM)
	mustWriteFile(t, caCertFile, caCertPEM)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		t.Fatal("failed to append generated CA cert")
	}

	return generatedCertSet{
		serverCertFile: serverCertFile,
		serverKeyFile:  serverKeyFile,
		clientCertFile: clientCertFile,
		clientKeyFile:  clientKeyFile,
		caCertFile:     caCertFile,
		caPool:         pool,
	}
}

func mustWriteFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", path, err)
	}
}

func generateCertificateAuthority(t *testing.T) ([]byte, []byte, *x509.Certificate) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() failed: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "grpc-client-test-ca",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(ca) failed: %v", err)
	}

	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(ca) failed: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return certPEM, keyPEM, caCert
}

func generateSignedCertificate(t *testing.T, caCert *x509.Certificate, caKeyPEM []byte, client bool) ([]byte, []byte) {
	t.Helper()

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		t.Fatal("failed to decode CA key PEM")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		t.Fatalf("x509.ParsePKCS1PrivateKey() failed: %v", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() failed: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	if client {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		template.DNSNames = nil
		template.IPAddresses = nil
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(leaf) failed: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return certPEM, keyPEM
}

func TestNewIClient(t *testing.T) {
	resetClientGRPCTestState(t)
	got := NewIClient(nil)
	if got == nil {
		t.Fatal("NewIClient() returned nil")
	}
}

func TestClientConfiguration(t *testing.T) {
	resetClientGRPCTestState(t)
	cli := NewIClient(nil).(*Client)
	conn, err := grpc.NewClient("passthrough:///config-test", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient() failed: %v", err)
	}
	defer conn.Close()

	cli.SetAddress("localhost:50051")
	cli.SetConn(conn)
	cli.SetContext(context.Background())
	cli.SetDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials()))

	if got := cli.GetConn(); got != conn {
		t.Fatalf("GetConn() = %v, want %v", got, conn)
	}
}

func TestClientConnect(t *testing.T) {
	resetClientGRPCTestState(t)

	tests := []struct {
		name    string
		setup   func() IClient
		wantErr bool
	}{
		{
			name: "requires address",
			setup: func() IClient {
				return NewIClient(nil)
			},
			wantErr: true,
		},
		{
			name: "keeps existing connection",
			setup: func() IClient {
				conn, err := grpc.NewClient("passthrough:///existing", grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					t.Fatalf("grpc.NewClient() failed: %v", err)
				}
				t.Cleanup(func() { _ = conn.Close() })
				return NewIClient(conn)
			},
		},
		{
			name: "creates connection",
			setup: func() IClient {
				cli := NewIClient(nil)
				cli.SetAddress("passthrough:///connect")
				cli.SetDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials()))
				return cli
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli := tt.setup()
			err := cli.Connect()
			if tt.wantErr && err == nil {
				t.Fatal("Connect() succeeded unexpectedly")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Connect() failed: %v", err)
			}
		})
	}
}

func TestClientConnectError(t *testing.T) {
	resetClientGRPCTestState(t)
	newGRPCClient = func(string, ...grpc.DialOption) (*grpc.ClientConn, error) {
		return nil, errors.New("dial failed")
	}

	cli := NewIClient(nil)
	cli.SetAddress("passthrough:///error")

	err := cli.Connect()
	if err == nil {
		t.Fatal("Connect() succeeded unexpectedly")
	}
	if err.Error() != "problem creating grpc client: dial failed" {
		t.Fatalf("Connect() error = %v", err)
	}
}

func TestClientClose(t *testing.T) {
	resetClientGRPCTestState(t)
	cli := NewIClient(nil)
	if err := cli.Close(); err != nil {
		t.Fatalf("Close() with nil conn failed: %v", err)
	}

	conn, err := grpc.NewClient("passthrough:///close", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient() failed: %v", err)
	}

	cli.SetConn(conn)
	if err := cli.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	if cli.GetConn() != nil {
		t.Fatal("GetConn() should be nil after Close()")
	}
}

func TestBuildClient(t *testing.T) {
	resetClientGRPCTestState(t)

	tests := []struct {
		name    string
		client  func() IClient
		builder BuildClientFunc[*struct{}]
		wantErr bool
	}{
		{
			name:    "requires client",
			client:  func() IClient { return nil },
			builder: func(grpc.ClientConnInterface) *struct{} { return &struct{}{} },
			wantErr: true,
		},
		{
			name:    "requires builder",
			client:  func() IClient { return NewIClient(nil) },
			wantErr: true,
		},
		{
			name: "propagates connect error",
			client: func() IClient {
				return &mockClient{connectErr: errors.New("connect failed")}
			},
			builder: func(grpc.ClientConnInterface) *struct{} { return &struct{}{} },
			wantErr: true,
		},
		{
			name: "requires connection after connect",
			client: func() IClient {
				return &mockClient{}
			},
			builder: func(grpc.ClientConnInterface) *struct{} { return &struct{}{} },
			wantErr: true,
		},
		{
			name: "builds generic client",
			client: func() IClient {
				conn, err := grpc.NewClient("passthrough:///build", grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					t.Fatalf("grpc.NewClient() failed: %v", err)
				}
				t.Cleanup(func() { _ = conn.Close() })
				return NewIClient(conn)
			},
			builder: func(grpc.ClientConnInterface) *struct{} { return &struct{}{} },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildClient(tt.client(), tt.builder)
			if tt.wantErr {
				if err == nil {
					t.Fatal("BuildClient() succeeded unexpectedly")
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildClient() failed: %v", err)
			}
			if got == nil {
				t.Fatal("BuildClient() returned nil")
			}
		})
	}
}

func TestBuildClientWithProtoClientAndBufconn(t *testing.T) {
	resetClientGRPCTestState(t)

	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	pb.RegisterGreeterServer(server, greeterService{})

	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient() failed: %v", err)
	}
	defer conn.Close()

	cli := NewIClient(conn)
	greeter, err := BuildClient(cli, pb.NewGreeterClient)
	if err != nil {
		t.Fatalf("BuildClient() failed: %v", err)
	}

	resp, err := greeter.SayHello(context.Background(), &pb.HelloRequest{Name: "Manuel"})
	if err != nil {
		t.Fatalf("SayHello() failed: %v", err)
	}
	if resp.GetMessage() != "hello Manuel" {
		t.Fatalf("SayHello() response = %q", resp.GetMessage())
	}
}

func TestBuildClientWithTracingAndMetadata(t *testing.T) {
	resetClientGRPCTestState(t)

	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	pb.RegisterGreeterServer(server, greeterService{})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()

	cli := NewIClient(nil)
	cli.SetAddress("passthrough:///bufnet")
	cli.SetDialOptions(
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	greeter, err := BuildClient(cli, pb.NewGreeterClient)
	if err != nil {
		t.Fatalf("BuildClient() failed: %v", err)
	}

	ctxLogger := builder.New(context.Background())
	ctx := metadata.AppendToOutgoingContext(ctxLogger, "x-request-id", "req-1")
	resp, err := greeter.SayHello(ctx, &pb.HelloRequest{Name: "Trace"})
	if err != nil {
		t.Fatalf("SayHello() failed: %v", err)
	}
	if resp.GetMessage() != "hello Trace" {
		t.Fatalf("SayHello() response = %q", resp.GetMessage())
	}
}

func TestClientStreamTracingInterceptor(t *testing.T) {
	resetClientGRPCTestState(t)

	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	pb.RegisterGreeterServer(server, greeterService{})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()

	cli := NewIClient(nil)
	cli.SetAddress("passthrough:///bufnet")
	cli.SetDialOptions(
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	greeter, err := BuildClient(cli, pb.NewGreeterClient)
	if err != nil {
		t.Fatalf("BuildClient() failed: %v", err)
	}

	ctxLogger := builder.New(context.Background())
	stream, err := greeter.StreamAlerts(ctxLogger)
	if err != nil {
		t.Fatalf("StreamAlerts() failed: %v", err)
	}
	if err := stream.Send(&pb.AlertMessage{Level: "INFO", Message: "hello"}); err != nil {
		t.Fatalf("Send() failed: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("Recv() failed: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend() failed: %v", err)
	}
}

func TestTraceUnaryClientInterceptorBuildsService(t *testing.T) {
	resetClientGRPCTestState(t)

	ctxLogger := builder.New(context.Background())
	ctxLogger.SetTraceID("trace-grpc-out")
	ctx := metadata.AppendToOutgoingContext(ctxLogger, "x-request-id", "req-1")
	var gotTraceID string
	reply := &pb.HelloReply{}
	conn, err := grpc.NewClient("passthrough:///trace-unary", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient() failed: %v", err)
	}
	defer conn.Close()

	interceptor := traceUnaryClientInterceptor()
	err = interceptor(
		ctx,
		"/proto.Greeter/SayHello",
		&pb.HelloRequest{Name: "Trace"},
		reply,
		conn,
		func(ctx context.Context, method string, req, reply any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
			if md, ok := metadata.FromOutgoingContext(ctx); ok {
				values := md.Get("x-trace-id")
				if len(values) > 0 {
					gotTraceID = values[0]
				}
			}
			response, ok := reply.(*pb.HelloReply)
			if !ok {
				t.Fatalf("reply type = %T", reply)
			}
			response.Message = "hello Trace"
			return nil
		},
	)
	if err != nil {
		t.Fatalf("interceptor() error = %v", err)
	}
	if reply.GetMessage() != "hello Trace" {
		t.Fatalf("reply.GetMessage() = %q, want %q", reply.GetMessage(), "hello Trace")
	}
	if gotTraceID != "trace-grpc-out" {
		t.Fatalf("x-trace-id = %q, want %q", gotTraceID, "trace-grpc-out")
	}
}

func TestContextWithTraceIDMetadataPreservesExistingTraceID(t *testing.T) {
	resetClientGRPCTestState(t)

	ctxLogger := builder.New(context.Background())
	ctxLogger.SetTraceID("trace-generated")
	ctx := metadata.AppendToOutgoingContext(ctxLogger, strings.ToLower(common.TraceIDHeader), "trace-existing")

	gotCtx := contextWithTraceIDMetadata(ctx)
	md, ok := metadata.FromOutgoingContext(gotCtx)
	if !ok {
		t.Fatal("expected outgoing metadata")
	}
	values := md.Get(strings.ToLower(common.TraceIDHeader))
	if len(values) != 1 || values[0] != "trace-existing" {
		t.Fatalf("x-trace-id metadata = %#v, want [trace-existing]", values)
	}
}

func TestTraceStreamClientInterceptorBuildsService(t *testing.T) {
	resetClientGRPCTestState(t)

	ctxLogger := builder.New(context.Background())
	ctx := metadata.AppendToOutgoingContext(ctxLogger, "x-request-id", "req-stream")
	conn, err := grpc.NewClient("passthrough:///trace-stream", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient() failed: %v", err)
	}
	defer conn.Close()

	streamer := func(context.Context, *grpc.StreamDesc, *grpc.ClientConn, string, ...grpc.CallOption) (grpc.ClientStream, error) {
		return &fakeClientStream{
			ctx: ctx,
			recvValue: &pb.AlertMessage{
				AlertId: "alert-1",
				Level:   "INFO",
				Message: "world",
			},
		}, nil
	}

	interceptor := traceStreamClientInterceptor()
	stream, err := interceptor(
		ctx,
		&grpc.StreamDesc{ClientStreams: true, ServerStreams: true},
		conn,
		"/proto.Greeter/StreamAlerts",
		streamer,
	)
	if err != nil {
		t.Fatalf("interceptor() error = %v", err)
	}

	if err := stream.SendMsg(&pb.AlertMessage{AlertId: "alert-1", Level: "INFO", Message: "hello"}); err != nil {
		t.Fatalf("SendMsg() error = %v", err)
	}

	reply := &pb.AlertMessage{}
	if err := stream.RecvMsg(reply); err != nil {
		t.Fatalf("RecvMsg() error = %v", err)
	}
	if err := stream.RecvMsg(reply); !errorsIsEOF(err) {
		t.Fatalf("RecvMsg() error = %v, want io.EOF", err)
	}

	if reply.GetMessage() != "world" {
		t.Fatalf("reply.GetMessage() = %q, want %q", reply.GetMessage(), "world")
	}
}

func TestResolveTLSConfigAndParseTLSVersion(t *testing.T) {
	resetClientGRPCTestState(t)
	certs := writeGeneratedCertificateFiles(t)

	t.Run("disabled", func(t *testing.T) {
		config, err := resolveTLSConfig()
		if err != nil {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
		if config != nil {
			t.Fatalf("resolveTLSConfig() = %#v, want nil", config)
		}
	})

	t.Run("manual config", func(t *testing.T) {
		want := &tls.Config{MinVersion: tls.VersionTLS13}
		SetTLSConfig(want)
		config, err := resolveTLSConfig()
		if err != nil {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
		if config != want {
			t.Fatalf("resolveTLSConfig() = %p, want %p", config, want)
		}
		SetTLSConfig(nil)
	})

	t.Run("tls", func(t *testing.T) {
		viper.Set("client.grpc.tls.enable", true)
		viper.Set("client.grpc.tls.caFile", certs.caCertFile)
		viper.Set("client.grpc.tls.serverName", "localhost")
		viper.Set("client.grpc.tls.version", "tlsv13")

		config, err := resolveTLSConfig()
		if err != nil {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
		if config.MinVersion != tls.VersionTLS13 {
			t.Fatalf("MinVersion = %v, want %v", config.MinVersion, tls.VersionTLS13)
		}
		if config.RootCAs == nil {
			t.Fatal("RootCAs = nil, want populated pool")
		}
	})

	t.Run("mtls requires cert and key", func(t *testing.T) {
		viper.Set("client.grpc.mtls.enable", true)
		_, err := resolveTLSConfig()
		if err == nil || err.Error() != "client.grpc.mtls.certFile and client.grpc.mtls.keyFile are required" {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
	})

	t.Run("mtls", func(t *testing.T) {
		viper.Set("client.grpc.tls.enable", true)
		viper.Set("client.grpc.tls.caFile", certs.caCertFile)
		viper.Set("client.grpc.tls.serverName", "localhost")
		viper.Set("client.grpc.mtls.enable", true)
		viper.Set("client.grpc.mtls.certFile", certs.clientCertFile)
		viper.Set("client.grpc.mtls.keyFile", certs.clientKeyFile)

		config, err := resolveTLSConfig()
		if err != nil {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
		if len(config.Certificates) != 1 {
			t.Fatalf("Certificates len = %d, want 1", len(config.Certificates))
		}
	})

	if got := parseTLSVersion("tlsv10"); got != tls.VersionTLS10 {
		t.Fatalf("parseTLSVersion(tlsv10) = %v, want %v", got, tls.VersionTLS10)
	}
	if got := parseTLSVersion("unknown"); got != tls.VersionTLS12 {
		t.Fatalf("parseTLSVersion(unknown) = %v, want %v", got, tls.VersionTLS12)
	}
}

func TestConnectWithTLSAndMTLS(t *testing.T) {
	t.Run("tls with custom dialer", func(t *testing.T) {
		resetClientGRPCTestState(t)
		certs := writeGeneratedCertificateFiles(t)

		listener := bufconn.Listen(1024 * 1024)
		server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{mustLoadKeyPair(t, certs.serverCertFile, certs.serverKeyFile)},
		})))
		pb.RegisterGreeterServer(server, greeterService{})
		go func() { _ = server.Serve(listener) }()
		defer server.Stop()

		cli := NewIClient(nil)
		cli.SetAddress("passthrough:///tls")
		cli.SetDialOptions(grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}))
		viper.Set("client.grpc.tls.enable", true)
		viper.Set("client.grpc.tls.caFile", certs.caCertFile)
		viper.Set("client.grpc.tls.serverName", "localhost")

		if err := cli.Connect(); err != nil {
			t.Fatalf("Connect() failed: %v", err)
		}
		_ = cli.Close()
	})

	t.Run("default transport options tls", func(t *testing.T) {
		resetClientGRPCTestState(t)
		certs := writeGeneratedCertificateFiles(t)

		originalNewClient := newGRPCClient
		defer func() { newGRPCClient = originalNewClient }()
		newGRPCClient = func(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
			return grpc.NewClient(target, append([]grpc.DialOption{
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
					listener := bufconn.Listen(1024 * 1024)
					server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
						Certificates: []tls.Certificate{mustLoadKeyPair(t, certs.serverCertFile, certs.serverKeyFile)},
					})))
					pb.RegisterGreeterServer(server, greeterService{})
					go func() { _ = server.Serve(listener) }()
					t.Cleanup(func() {
						server.Stop()
						listener.Close()
					})
					return listener.Dial()
				}),
			}, opts...)...)
		}

		cli := NewIClient(nil)
		cli.SetAddress("passthrough:///tls-default")
		viper.Set("client.grpc.tls.enable", true)
		viper.Set("client.grpc.tls.caFile", certs.caCertFile)
		viper.Set("client.grpc.tls.serverName", "localhost")

		if err := cli.Connect(); err != nil {
			t.Fatalf("Connect() failed: %v", err)
		}
		_ = cli.Close()
	})
}

func mustLoadKeyPair(t *testing.T, certFile, keyFile string) tls.Certificate {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("tls.LoadX509KeyPair() failed: %v", err)
	}
	return certificate
}

func TestHelpers(t *testing.T) {
	resetClientGRPCTestState(t)

	if got := collapseBodies(nil); got != nil {
		t.Fatalf("collapseBodies(nil) = %#v, want nil", got)
	}
	if got := collapseBodies([]any{"one"}); got != "one" {
		t.Fatalf("collapseBodies(single) = %#v, want %#v", got, "one")
	}
	if got := grpcMethodName("/pkg.Service/Call"); got != "Call" {
		t.Fatalf("grpcMethodName() = %q, want %q", got, "Call")
	}
	service, process := grpcServiceMethod("/pkg.Service/Call")
	if service != "pkg.Service" || process != "Call" {
		t.Fatalf("grpcServiceMethod() = %q, %q", service, process)
	}
	if got := metadataToHTTPHeader(metadata.Pairs("x-request-id", "abc")).Get("X-Request-Id"); got != "abc" {
		t.Fatalf("metadataToHTTPHeader() = %q, want %q", got, "abc")
	}
	if hasError(nil) {
		t.Fatal("hasError(nil) = true, want false")
	}
	if !hasError(errors.New("boom")) {
		t.Fatal("hasError(non-nil) = false, want true")
	}
	if errorsIsEOF(errors.New("boom")) {
		t.Fatal("errorsIsEOF(non-eof) = true, want false")
	}
	if !errorsIsEOF(io.EOF) {
		t.Fatal("errorsIsEOF(io.EOF) = false, want true")
	}
}

func TestBuildService(t *testing.T) {
	resetClientGRPCTestState(t)

	service := &formatter.Process{}
	ctx := metadata.AppendToOutgoingContext(context.Background(), "x-request-id", "abc")
	resp := &pb.HelloReply{Message: "ok"}

	if err := buildService(service, &pb.HelloRequest{Name: "test"}, resp, "/pkg.Service/Call", "localhost:50051", ctx, nil); err != nil {
		t.Fatalf("buildService() error = %v", err)
	}
	if service.Protocol != "gRPC" || service.Method != "Call" || service.Path != "/pkg.Service/Call" {
		t.Fatalf("unexpected service metadata: %#v", service)
	}
	if service.Headers == nil || service.Headers.Get("X-Request-Id") != "abc" {
		t.Fatalf("service.Headers = %#v, want outgoing metadata", service.Headers)
	}
	if service.Response != resp {
		t.Fatalf("service.Response = %#v, want %#v", service.Response, resp)
	}

	service = &formatter.Process{DisableBody: true}
	if err := buildService(service, "req", "resp", "/pkg.Service/Call", "localhost:50051", context.Background(), errors.New("boom")); err != nil {
		t.Fatalf("buildService() error = %v", err)
	}
	if service.Request != nil || service.Response != nil {
		t.Fatalf("expected disabled body capture, got request=%#v response=%#v", service.Request, service.Response)
	}
}

func TestMockIClientMethods(t *testing.T) {
	resetClientGRPCTestState(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	conn, err := grpc.NewClient("passthrough:///mock", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient() failed: %v", err)
	}
	defer conn.Close()

	mock := NewMockIClient(ctrl)
	mock.EXPECT().SetAddress(":50051")
	mock.EXPECT().SetConn(conn)
	mock.EXPECT().SetContext(gomock.Any())
	mock.EXPECT().SetDialOptions(gomock.Any())
	mock.EXPECT().Connect().Return(nil)
	mock.EXPECT().Close().Return(nil)
	mock.EXPECT().GetConn().Return(conn)

	mock.SetAddress(":50051")
	mock.SetConn(conn)
	mock.SetContext(context.Background())
	mock.SetDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err := mock.Connect(); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}
	if err := mock.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	if got := mock.GetConn(); got != conn {
		t.Fatalf("GetConn() = %v, want %v", got, conn)
	}
}
