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
	"github.com/PointerByte/forge-go/logger/formatter"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/golang/mock/gomock"
	"github.com/spf13/viper"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type mockUnitary struct {
	registerErr   error
	serveErr      error
	server        *grpc.Server
	listener      net.Listener
	registerCalls int
	serveCalls    int
	stopCalls     int
	gracefulCalls int
}

type shutdownObservationProcessor struct {
	shutdownCalls int
	shutdownErr   error
}

func (*shutdownObservationProcessor) Enabled(context.Context, sdklog.EnabledParameters) bool {
	return true
}

func (*shutdownObservationProcessor) OnEmit(context.Context, *sdklog.Record) error {
	return nil
}

func (p *shutdownObservationProcessor) Shutdown(context.Context) error {
	p.shutdownCalls++
	return p.shutdownErr
}

func (*shutdownObservationProcessor) ForceFlush(context.Context) error {
	return nil
}

func (m *mockUnitary) SetAddress(string)        {}
func (m *mockUnitary) SetListener(net.Listener) {}
func (m *mockUnitary) Register(RegisterServiceFunc) error {
	m.registerCalls++
	return m.registerErr
}
func (m *mockUnitary) Serve() error {
	m.serveCalls++
	return m.serveErr
}
func (m *mockUnitary) GracefulStop() { m.gracefulCalls++ }
func (m *mockUnitary) Stop()         { m.stopCalls++ }
func (m *mockUnitary) GetServer() *grpc.Server {
	return m.server
}
func (m *mockUnitary) GetListener() net.Listener {
	return m.listener
}

type greeterService struct {
	pb.UnimplementedGreeterServer
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
		_, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func resetServerGRPCTestState(t *testing.T) {
	t.Helper()

	originalListen := listenTCP
	originalTLSConfig := tlsConfig
	originalLoadX509KeyPairFn := loadX509KeyPairFn
	originalReadFileFn := readFileFn
	originalNewCertPoolFn := newCertPoolFn
	originalLoadEnv := loadEnv
	originalInitLogger := initLogger
	originalInitOtel := initOtel
	originalRunAsyncFn := runAsyncFn
	originalWaitForShutdownSignalFn := waitForShutdownSignalFn
	originalQuit := quit

	t.Cleanup(func() {
		listenTCP = originalListen
		tlsConfig = originalTLSConfig
		loadX509KeyPairFn = originalLoadX509KeyPairFn
		readFileFn = originalReadFileFn
		newCertPoolFn = originalNewCertPoolFn
		loadEnv = originalLoadEnv
		initLogger = originalInitLogger
		initOtel = originalInitOtel
		runAsyncFn = originalRunAsyncFn
		waitForShutdownSignalFn = originalWaitForShutdownSignalFn
		quit = originalQuit
		viper.Reset()
		viperdata.ResetViperDataSingleton()
	})

	viper.Reset()
	viperdata.ResetViperDataSingleton()
	tlsConfig = nil
	viper.Set("app.name", "grpc-test-service")
	viper.Set("app.version", "1.0.0")
	viper.Set("logger.ignoredHeaders", []string{})
	builder.EnableModeTest()
	loadEnv = func(string) error { return nil }
	initLogger = func(context.Context, string) (*sdklog.LoggerProvider, error) {
		return sdklog.NewLoggerProvider(), nil
	}
	initOtel = func(context.Context) (func(context.Context) error, error) {
		return func(context.Context) error { return nil }, nil
	}
	runAsyncFn = func(fn func()) { go fn() }
	waitForShutdownSignalFn = func(*grpc.Server, []handlerShutdown, <-chan struct{}) {}
	quit = make(chan os.Signal, 1)
}

func (s greeterService) SayHello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloReply, error) {
	builder.New(ctx).Set(formatter.InfoLevel, "say hello handled")
	return &pb.HelloReply{Message: "hello " + req.GetName()}, nil
}

type generatedCertSet struct {
	serverCertFile string
	serverKeyFile  string
	clientCertFile string
	clientKeyFile  string
	caCertFile     string
	caPool         *x509.CertPool
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
			CommonName: "grpc-test-ca",
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

	serialNumber := big.NewInt(time.Now().UnixNano())
	template := &x509.Certificate{
		SerialNumber: serialNumber,
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

func TestNewIUnitary(t *testing.T) {
	resetServerGRPCTestState(t)
	got := NewIConfig(nil, nil)
	if got == nil {
		t.Fatal("NewIUnitary() returned nil")
	}
	if got.GetServer() == nil {
		t.Fatal("GetServer() returned nil")
	}
}

func TestNewIConfigLoadsEnvBeforeRegister(t *testing.T) {
	resetServerGRPCTestState(t)

	wantErr := errors.New("load env failed")
	loadEnv = func(string) error { return wantErr }

	srv := NewIConfig(nil, nil)
	err := srv.Register(func(r grpc.ServiceRegistrar) {
		pb.RegisterGreeterServer(r, greeterService{})
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Register() error = %v, want %v", err, wantErr)
	}
}

func TestNewIConfigKeepsViperDataForLoggerAndOtel(t *testing.T) {
	resetServerGRPCTestState(t)

	loadCalls := 0
	loadEnv = func(string) error {
		loadCalls++
		viper.Set("app.name", "grpc-test-service")
		return nil
	}
	initLogger = func(context.Context, string) (*sdklog.LoggerProvider, error) {
		if got := viper.GetString("app.name"); got != "grpc-test-service" {
			t.Fatalf("app.name before InitLogger = %q, want grpc-test-service", got)
		}
		return sdklog.NewLoggerProvider(), nil
	}
	initOtel = func(context.Context) (func(context.Context) error, error) {
		if got := viper.GetString("app.name"); got != "grpc-test-service" {
			t.Fatalf("app.name before InitOtel = %q, want grpc-test-service", got)
		}
		return func(context.Context) error { return nil }, nil
	}
	srv := NewIConfig(nil, grpc.NewServer())

	err := srv.Serve()
	if err == nil {
		t.Fatal("Serve() succeeded unexpectedly")
	}
	if loadCalls != 1 {
		t.Fatalf("loadEnv calls = %d, want 1", loadCalls)
	}
}

func TestNewIConfigInitializesLoggerAndOtelAfterLoadEnv(t *testing.T) {
	resetServerGRPCTestState(t)

	var order []string
	viper.Set("logger.dir", "logs")
	loadEnv = func(string) error {
		order = append(order, "load")
		return nil
	}
	initLogger = func(_ context.Context, dir string) (*sdklog.LoggerProvider, error) {
		order = append(order, "logger")
		if filepath.Base(dir) != "logs" {
			t.Fatalf("InitLogger dir = %q, want logs suffix", dir)
		}
		return sdklog.NewLoggerProvider(), nil
	}
	initOtel = func(context.Context) (func(context.Context) error, error) {
		order = append(order, "otel")
		return func(context.Context) error { return nil }, nil
	}

	srv := NewIConfig(nil, grpc.NewServer()).(*Config)

	if got := strings.Join(order, ","); got != "load,logger,otel" {
		t.Fatalf("initialization order = %q, want load,logger,otel", got)
	}
	if len(srv.shutdownList) != 2 {
		t.Fatalf("shutdownList len = %d, want 2", len(srv.shutdownList))
	}
}

func TestNewIConfigInitLoggerError(t *testing.T) {
	resetServerGRPCTestState(t)

	wantErr := errors.New("init logger failed")
	initLogger = func(context.Context, string) (*sdklog.LoggerProvider, error) {
		return nil, wantErr
	}

	srv := NewIConfig(nil, nil)
	err := srv.Register(func(r grpc.ServiceRegistrar) {
		pb.RegisterGreeterServer(r, greeterService{})
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Register() error = %v, want %v", err, wantErr)
	}
}

func TestLoadConfigShutsDownLoggerWhenOtelInitializationFails(t *testing.T) {
	resetServerGRPCTestState(t)

	otelErr := errors.New("init otel failed")
	shutdownErr := errors.New("shutdown logger failed")
	processor := &shutdownObservationProcessor{shutdownErr: shutdownErr}
	initLogger = func(context.Context, string) (*sdklog.LoggerProvider, error) {
		return sdklog.NewLoggerProvider(sdklog.WithProcessor(processor)), nil
	}
	initOtel = func(context.Context) (func(context.Context) error, error) {
		return nil, otelErr
	}

	shutdownList, err := loadConfig(t.TempDir())
	if shutdownList != nil {
		t.Fatalf("shutdownList = %#v, want nil after failed initialization", shutdownList)
	}
	if !errors.Is(err, otelErr) || !errors.Is(err, shutdownErr) {
		t.Fatalf("loadConfig() error = %v, want joined OTEL and logger shutdown errors", err)
	}
	if processor.shutdownCalls != 1 {
		t.Fatalf("logger processor Shutdown calls = %d, want 1", processor.shutdownCalls)
	}
}

func TestSubUnitaryConfiguration(t *testing.T) {
	resetServerGRPCTestState(t)
	srv := NewIConfig(nil, grpc.NewServer()).(*Config)
	listener := bufconn.Listen(1024)
	defer listener.Close()

	srv.SetAddress("127.0.0.1:9000")
	srv.SetListener(listener)

	if got := srv.GetListener(); got != listener {
		t.Fatalf("GetListener() = %v, want %v", got, listener)
	}
	if got := srv.GetServer(); got == nil {
		t.Fatal("GetServer() returned nil")
	}
}

func TestSubUnitaryRegister(t *testing.T) {
	resetServerGRPCTestState(t)
	tests := []struct {
		name    string
		setup   func() IConfig
		wantErr bool
	}{
		{
			name: "delegates to mock",
			setup: func() IConfig {
				return NewIConfig(&mockUnitary{}, grpc.NewServer())
			},
		},
		{
			name: "rejects nil register",
			setup: func() IConfig {
				return NewIConfig(nil, grpc.NewServer())
			},
			wantErr: true,
		},
		{
			name: "registers proto service",
			setup: func() IConfig {
				return NewIConfig(nil, grpc.NewServer())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := tt.setup()
			var err error
			switch tt.name {
			case "rejects nil register":
				err = srv.Register(nil)
			default:
				err = srv.Register(func(r grpc.ServiceRegistrar) {
					pb.RegisterGreeterServer(r, greeterService{})
				})
			}
			if tt.wantErr && err == nil {
				t.Fatal("Register() succeeded unexpectedly")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Register() failed: %v", err)
			}
		})
	}
}

func TestSubUnitaryServeDelegatesToMock(t *testing.T) {
	resetServerGRPCTestState(t)
	expectedErr := errors.New("serve failed")
	srv := NewIConfig(&mockUnitary{serveErr: expectedErr}, grpc.NewServer())

	err := srv.Serve()
	if !errors.Is(err, expectedErr) {
		t.Fatalf("Serve() error = %v", err)
	}
}

func TestSubUnitaryServeLoadEnvError(t *testing.T) {
	resetServerGRPCTestState(t)

	wantErr := errors.New("load env failed")
	loadEnv = func(string) error { return wantErr }
	srv := NewIConfig(nil, grpc.NewServer())

	err := srv.Serve()
	if !errors.Is(err, wantErr) {
		t.Fatalf("Serve() error = %v, want %v", err, wantErr)
	}
}

func TestSubUnitaryServeRequiresAddressOrListener(t *testing.T) {
	resetServerGRPCTestState(t)
	srv := NewIConfig(nil, grpc.NewServer())

	err := srv.Serve()
	if err == nil {
		t.Fatal("Serve() succeeded unexpectedly")
	}
}

func TestSubUnitaryServeUsesViperPort(t *testing.T) {
	resetServerGRPCTestState(t)

	var listenedAddress string
	listenTCP = func(network, address string) (net.Listener, error) {
		listenedAddress = address
		return bufconn.Listen(1024), nil
	}
	viper.Set("server.grpc.port", ":50051")

	srv := NewIConfig(nil, grpc.NewServer())
	srv.GetServer().Stop()

	err := srv.Serve()
	if err == nil {
		t.Fatal("Serve() succeeded unexpectedly")
	}
	if listenedAddress != ":50051" {
		t.Fatalf("listenedAddress = %q, want %q", listenedAddress, ":50051")
	}
}

func TestSubUnitaryServeListenError(t *testing.T) {
	resetServerGRPCTestState(t)
	listenTCP = func(string, string) (net.Listener, error) {
		return nil, errors.New("listen failed")
	}

	srv := NewIConfig(nil, grpc.NewServer())
	srv.SetAddress("127.0.0.1:0")

	err := srv.Serve()
	if err == nil {
		t.Fatal("Serve() succeeded unexpectedly")
	}
	if err.Error() != "problem creating tcp listener: listen failed" {
		t.Fatalf("Serve() error = %v", err)
	}
}

func TestSubUnitaryServeUnaryFlowWithBufconn(t *testing.T) {
	resetServerGRPCTestState(t)
	listener := bufconn.Listen(1024 * 1024)
	srv := NewIConfig(nil, nil)
	srv.SetListener(listener)
	if err := srv.Register(func(r grpc.ServiceRegistrar) {
		pb.RegisterGreeterServer(r, greeterService{})
	}); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

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

	client := pb.NewGreeterClient(conn)
	resp, err := client.SayHello(ctx, &pb.HelloRequest{Name: "Manuel"})
	if err != nil {
		t.Fatalf("SayHello() failed: %v", err)
	}
	if resp.GetMessage() != "hello Manuel" {
		t.Fatalf("SayHello() response = %q", resp.GetMessage())
	}

	srv.GracefulStop()

	select {
	case serveErr := <-errCh:
		if serveErr != nil {
			t.Fatalf("Serve() returned error: %v", serveErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not stop after GracefulStop()")
	}
}

func TestSubUnitaryServeUnaryFlowWithCustomInterceptor(t *testing.T) {
	resetServerGRPCTestState(t)
	listener := bufconn.Listen(1024 * 1024)
	interceptorCalled := false
	srv := NewIConfig(nil, nil, WithUnaryInterceptors(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		interceptorCalled = true
		return handler(ctx, req)
	}))
	srv.SetListener(listener)
	if err := srv.Register(func(r grpc.ServiceRegistrar) {
		pb.RegisterGreeterServer(r, greeterService{})
	}); err != nil {
		t.Fatalf("Register() failed: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

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

	client := pb.NewGreeterClient(conn)
	if _, err := client.SayHello(ctx, &pb.HelloRequest{Name: "Manuel"}); err != nil {
		t.Fatalf("SayHello() failed: %v", err)
	}
	if !interceptorCalled {
		t.Fatal("expected custom unary interceptor to be called")
	}

	srv.GracefulStop()

	select {
	case serveErr := <-errCh:
		if serveErr != nil {
			t.Fatalf("Serve() returned error: %v", serveErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not stop after GracefulStop()")
	}
}

func TestSubUnitaryServeLogsServeError(t *testing.T) {
	resetServerGRPCTestState(t)

	listener := bufconn.Listen(1024)
	defer listener.Close()

	srv := NewIConfig(nil, grpc.NewServer())
	srv.SetListener(listener)
	srv.GetServer().Stop()

	err := srv.Serve()
	if err == nil {
		t.Fatal("Serve() succeeded unexpectedly")
	}
}

func TestWaitForShutdownSignalGracefullyStopsServer(t *testing.T) {
	resetServerGRPCTestState(t)

	server := grpc.NewServer()
	quit = make(chan os.Signal, 1)
	stopped := make(chan struct{}, 1)
	shutdownCalled := false
	runAsyncFn = func(fn func()) { go fn() }

	runAsyncFn(func() {
		waitForShutdownSignal(server, []handlerShutdown{
			func(context.Context) error {
				shutdownCalled = true
				return nil
			},
		}, make(chan struct{}))
		close(stopped)
	})

	quit <- os.Interrupt

	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("waitForShutdownSignal() did not stop the server after signal")
	}
	if !shutdownCalled {
		t.Fatal("expected shutdown handler to be called")
	}
}

func TestWaitForShutdownSignalReturnsWhenServeCompletes(t *testing.T) {
	resetServerGRPCTestState(t)

	done := make(chan struct{})
	returned := make(chan struct{})
	go func() {
		waitForShutdownSignal(grpc.NewServer(), nil, done)
		close(returned)
	}()
	close(done)

	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("shutdown waiter leaked after serve completion")
	}
}

func TestStopMethodsAreSafeWhenInitializationFailed(t *testing.T) {
	resetServerGRPCTestState(t)

	wantErr := errors.New("load failed")
	loadEnv = func(string) error { return wantErr }
	var logged []error
	logServerErrorFn = func(err error) {
		logged = append(logged, err)
	}

	srv := NewIConfig(nil, nil)
	srv.GracefulStop()
	srv.Stop()
	if got := srv.GetServer(); got != nil {
		t.Fatalf("GetServer() = %v, want nil after initialization failure", got)
	}
	if len(logged) != 3 {
		t.Fatalf("logged initialization errors = %d, want 3", len(logged))
	}
	for _, err := range logged {
		if !errors.Is(err, wantErr) {
			t.Fatalf("logged error %v does not wrap %v", err, wantErr)
		}
	}
}

func TestStopMethodsRetainInjectedServerAfterConfigurationFailure(t *testing.T) {
	resetServerGRPCTestState(t)

	loadEnv = func(string) error { return errors.New("load failed") }
	injected := grpc.NewServer()
	srv := NewIConfig(nil, injected)
	if got := srv.GetServer(); got != injected {
		t.Fatalf("GetServer() = %v, want injected server %v", got, injected)
	}
	srv.GracefulStop()
	srv.Stop()
}

func TestSubUnitaryStopAndGettersDelegateToMock(t *testing.T) {
	resetServerGRPCTestState(t)
	server := grpc.NewServer()
	listener := bufconn.Listen(1024)
	defer listener.Close()

	mock := &mockUnitary{server: server, listener: listener}
	srv := NewIConfig(mock, grpc.NewServer())

	srv.GracefulStop()
	srv.Stop()

	if mock.gracefulCalls != 1 {
		t.Fatalf("GracefulStop() calls = %d", mock.gracefulCalls)
	}
	if mock.stopCalls != 1 {
		t.Fatalf("Stop() calls = %d", mock.stopCalls)
	}
	if got := srv.GetServer(); got != server {
		t.Fatalf("GetServer() = %v, want %v", got, server)
	}
	if got := srv.GetListener(); got != listener {
		t.Fatalf("GetListener() = %v, want %v", got, listener)
	}
}

func TestMockIUnitaryMethods(t *testing.T) {
	resetServerGRPCTestState(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	server := grpc.NewServer()
	listener := bufconn.Listen(1024)
	defer listener.Close()

	mock := NewMockIConfig(ctrl)
	mock.EXPECT().SetAddress(":50051")
	mock.EXPECT().SetListener(listener)
	mock.EXPECT().Register(gomock.Any()).Return(nil)
	mock.EXPECT().Serve().Return(nil)
	mock.EXPECT().GracefulStop()
	mock.EXPECT().Stop()
	mock.EXPECT().GetServer().Return(server)
	mock.EXPECT().GetListener().Return(listener)

	mock.SetAddress(":50051")
	mock.SetListener(listener)
	err := mock.Register(func(grpc.ServiceRegistrar) {})
	if err != nil {
		t.Fatalf("Register() failed: %v", err)
	}
	if err := mock.Serve(); err != nil {
		t.Fatalf("Serve() failed: %v", err)
	}
	mock.GracefulStop()
	mock.Stop()
	if got := mock.GetServer(); got != server {
		t.Fatalf("GetServer() = %v, want %v", got, server)
	}
	if got := mock.GetListener(); got != listener {
		t.Fatalf("GetListener() = %v, want %v", got, listener)
	}
}

func TestResolveTLSConfigDisabled(t *testing.T) {
	resetServerGRPCTestState(t)

	config, err := resolveTLSConfig()
	if err != nil {
		t.Fatalf("resolveTLSConfig() error = %v, want nil", err)
	}
	if config != nil {
		t.Fatalf("resolveTLSConfig() = %#v, want nil", config)
	}
}

func TestLoadConfigDefaultGRPC(t *testing.T) {
	resetServerGRPCTestState(t)

	loadConfigDefaultGRPC()

	if got := viper.GetInt("server.grpc.rate.limit"); got != 1000 {
		t.Fatalf("server.grpc.rate.limit = %d, want 1000", got)
	}
	if got := viper.GetInt("server.grpc.rate.burst"); got != 2000 {
		t.Fatalf("server.grpc.rate.burst = %d, want 2000", got)
	}
}

func TestGRPCRateLimiterUnary(t *testing.T) {
	resetServerGRPCTestState(t)

	viper.Set("server.grpc.rate.limit", 1)
	viper.Set("server.grpc.rate.burst", 1)
	limiter := newGRPCRateLimiter()
	interceptor := rateLimitUnaryInterceptor(limiter)
	calls := 0
	handler := func(context.Context, any) (any, error) {
		calls++
		return "ok", nil
	}

	resp, err := interceptor(context.Background(), "request", &grpc.UnaryServerInfo{}, handler)
	if err != nil {
		t.Fatalf("first unary call failed: %v", err)
	}
	if resp != "ok" {
		t.Fatalf("first unary response = %v, want ok", resp)
	}

	_, err = interceptor(context.Background(), "request", &grpc.UnaryServerInfo{}, handler)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("second unary error code = %v, want ResourceExhausted", status.Code(err))
	}
	if calls != 1 {
		t.Fatalf("handler calls = %d, want 1", calls)
	}
}

func TestGRPCRateLimiterStream(t *testing.T) {
	resetServerGRPCTestState(t)

	viper.Set("server.grpc.rate.limit", 1)
	viper.Set("server.grpc.rate.burst", 1)
	limiter := newGRPCRateLimiter()
	interceptor := rateLimitStreamInterceptor(limiter)
	calls := 0
	handler := func(any, grpc.ServerStream) error {
		calls++
		return nil
	}

	if err := interceptor(nil, nil, &grpc.StreamServerInfo{}, handler); err != nil {
		t.Fatalf("first stream call failed: %v", err)
	}

	err := interceptor(nil, nil, &grpc.StreamServerInfo{}, handler)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("second stream error code = %v, want ResourceExhausted", status.Code(err))
	}
	if calls != 1 {
		t.Fatalf("handler calls = %d, want 1", calls)
	}
}

func TestGRPCRateLimiterDisabled(t *testing.T) {
	resetServerGRPCTestState(t)

	viper.Set("server.grpc.rate.limit", 0)
	if limiter := newGRPCRateLimiter(); limiter != nil {
		t.Fatal("expected nil limiter when server.grpc.rate.limit is 0")
	}
}

func TestResolveTLSConfigUsesManualConfig(t *testing.T) {
	resetServerGRPCTestState(t)

	want := &tls.Config{MinVersion: tls.VersionTLS13}
	SetTLSConfig(want)

	config, err := resolveTLSConfig()
	if err != nil {
		t.Fatalf("resolveTLSConfig() error = %v, want nil", err)
	}
	if config != want {
		t.Fatalf("resolveTLSConfig() = %p, want %p", config, want)
	}
}

func TestResolveTLSConfigErrors(t *testing.T) {
	resetServerGRPCTestState(t)

	t.Run("missing cert or key", func(t *testing.T) {
		viper.Set("server.grpc.tls.enable", true)
		_, err := resolveTLSConfig()
		if err == nil || err.Error() != "server.grpc.tls.certFile and server.grpc.tls.keyFile are required" {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
	})

	t.Run("missing client ca file", func(t *testing.T) {
		certs := writeGeneratedCertificateFiles(t)
		viper.Set("server.grpc.mtls.enable", true)
		viper.Set("server.grpc.tls.certFile", certs.serverCertFile)
		viper.Set("server.grpc.tls.keyFile", certs.serverKeyFile)

		_, err := resolveTLSConfig()
		if err == nil || err.Error() != "server.grpc.mtls.clientCAFile is required" {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
	})
}

func TestResolveTLSConfigTLSAndMTLS(t *testing.T) {
	resetServerGRPCTestState(t)
	certs := writeGeneratedCertificateFiles(t)

	t.Run("tls", func(t *testing.T) {
		viper.Set("server.grpc.tls.enable", true)
		viper.Set("server.grpc.tls.certFile", certs.serverCertFile)
		viper.Set("server.grpc.tls.keyFile", certs.serverKeyFile)
		viper.Set("server.grpc.tls.version", "tlsv13")

		config, err := resolveTLSConfig()
		if err != nil {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
		if config == nil {
			t.Fatal("resolveTLSConfig() returned nil config")
		}
		if config.MinVersion != tls.VersionTLS13 {
			t.Fatalf("MinVersion = %v, want %v", config.MinVersion, tls.VersionTLS13)
		}
		if len(config.Certificates) != 1 {
			t.Fatalf("Certificates len = %d, want 1", len(config.Certificates))
		}
	})

	t.Run("mtls", func(t *testing.T) {
		viper.Set("server.grpc.tls.enable", true)
		viper.Set("server.grpc.mtls.enable", true)
		viper.Set("server.grpc.tls.certFile", certs.serverCertFile)
		viper.Set("server.grpc.tls.keyFile", certs.serverKeyFile)
		viper.Set("server.grpc.mtls.clientCAFile", certs.caCertFile)
		viper.Set("server.grpc.mtls.clientAuth", "verify_client_cert_if_given")

		config, err := resolveTLSConfig()
		if err != nil {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
		if config.ClientCAs == nil {
			t.Fatal("ClientCAs = nil, want populated pool")
		}
		if config.ClientAuth != tls.VerifyClientCertIfGiven {
			t.Fatalf("ClientAuth = %v, want %v", config.ClientAuth, tls.VerifyClientCertIfGiven)
		}
	})
}

func TestParseTLSVersionAndClientAuth(t *testing.T) {
	if got := parseTLSVersion("tlsv10"); got != tls.VersionTLS10 {
		t.Fatalf("parseTLSVersion(tlsv10) = %v, want %v", got, tls.VersionTLS10)
	}
	if got := parseTLSVersion("unknown"); got != tls.VersionTLS12 {
		t.Fatalf("parseTLSVersion(unknown) = %v, want %v", got, tls.VersionTLS12)
	}

	if got := parseClientAuth("request_client_cert"); got != tls.RequestClientCert {
		t.Fatalf("parseClientAuth(request_client_cert) = %v, want %v", got, tls.RequestClientCert)
	}
	if got := parseClientAuth("require_any_client_cert"); got != tls.RequireAnyClientCert {
		t.Fatalf("parseClientAuth(require_any_client_cert) = %v, want %v", got, tls.RequireAnyClientCert)
	}
	if got := parseClientAuth("verify_client_cert_if_given"); got != tls.VerifyClientCertIfGiven {
		t.Fatalf("parseClientAuth(verify_client_cert_if_given) = %v, want %v", got, tls.VerifyClientCertIfGiven)
	}
	if got := parseClientAuth("no_client_cert"); got != tls.NoClientCert {
		t.Fatalf("parseClientAuth(no_client_cert) = %v, want %v", got, tls.NoClientCert)
	}
	if got := parseClientAuth("unknown"); got != tls.RequireAndVerifyClientCert {
		t.Fatalf("parseClientAuth(unknown) = %v, want %v", got, tls.RequireAndVerifyClientCert)
	}
}

func TestServeWithTLSAndMTLS(t *testing.T) {
	t.Run("tls", func(t *testing.T) {
		resetServerGRPCTestState(t)
		certs := writeGeneratedCertificateFiles(t)
		viper.Set("server.grpc.tls.enable", true)
		viper.Set("server.grpc.tls.certFile", certs.serverCertFile)
		viper.Set("server.grpc.tls.keyFile", certs.serverKeyFile)

		listener := bufconn.Listen(1024 * 1024)
		srv := NewIConfig(nil, nil)
		srv.SetListener(listener)
		if err := srv.Register(func(r grpc.ServiceRegistrar) {
			pb.RegisterGreeterServer(r, greeterService{})
		}); err != nil {
			t.Fatalf("Register() failed: %v", err)
		}

		errCh := make(chan error, 1)
		go func() {
			errCh <- srv.Serve()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}),
			grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				RootCAs:    certs.caPool,
				ServerName: "localhost",
			})),
		)
		if err != nil {
			t.Fatalf("grpc.NewClient() failed: %v", err)
		}
		defer conn.Close()

		client := pb.NewGreeterClient(conn)
		resp, err := client.SayHello(ctx, &pb.HelloRequest{Name: "TLS"})
		if err != nil {
			t.Fatalf("SayHello() failed: %v", err)
		}
		if resp.GetMessage() != "hello TLS" {
			t.Fatalf("SayHello() response = %q", resp.GetMessage())
		}

		srv.GracefulStop()
		select {
		case serveErr := <-errCh:
			if serveErr != nil {
				t.Fatalf("Serve() returned error: %v", serveErr)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Serve() did not stop after GracefulStop()")
		}
	})

	t.Run("mtls", func(t *testing.T) {
		resetServerGRPCTestState(t)
		certs := writeGeneratedCertificateFiles(t)
		viper.Set("server.grpc.tls.enable", true)
		viper.Set("server.grpc.tls.certFile", certs.serverCertFile)
		viper.Set("server.grpc.tls.keyFile", certs.serverKeyFile)
		viper.Set("server.grpc.mtls.enable", true)
		viper.Set("server.grpc.mtls.clientCAFile", certs.caCertFile)

		listener := bufconn.Listen(1024 * 1024)
		srv := NewIConfig(nil, nil)
		srv.SetListener(listener)
		if err := srv.Register(func(r grpc.ServiceRegistrar) {
			pb.RegisterGreeterServer(r, greeterService{})
		}); err != nil {
			t.Fatalf("Register() failed: %v", err)
		}

		errCh := make(chan error, 1)
		go func() {
			errCh <- srv.Serve()
		}()

		clientCertificate, err := tls.LoadX509KeyPair(certs.clientCertFile, certs.clientKeyFile)
		if err != nil {
			t.Fatalf("tls.LoadX509KeyPair() failed: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return listener.Dial()
			}),
			grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				RootCAs:      certs.caPool,
				Certificates: []tls.Certificate{clientCertificate},
				ServerName:   "localhost",
			})),
		)
		if err != nil {
			t.Fatalf("grpc.NewClient() failed: %v", err)
		}
		defer conn.Close()

		client := pb.NewGreeterClient(conn)
		resp, err := client.SayHello(ctx, &pb.HelloRequest{Name: "mTLS"})
		if err != nil {
			t.Fatalf("SayHello() failed: %v", err)
		}
		if resp.GetMessage() != "hello mTLS" {
			t.Fatalf("SayHello() response = %q", resp.GetMessage())
		}

		srv.GracefulStop()
		select {
		case serveErr := <-errCh:
			if serveErr != nil {
				t.Fatalf("Serve() returned error: %v", serveErr)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Serve() did not stop after GracefulStop()")
		}
	})
}
