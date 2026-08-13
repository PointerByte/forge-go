// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

//go:generate mockgen -source=config.go -destination=./mocksConfig_test.go -package=grpc

package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PointerByte/forge-go/logger/builder"
	loggerGRPCMiddlewares "github.com/PointerByte/forge-go/logger/middlewares/grpc"
	"github.com/PointerByte/forge-go/tools/utilities"
	"github.com/PointerByte/forge-go/tools/utilities/traces"
	"github.com/spf13/viper"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

var listenTCP = net.Listen
var loadX509KeyPairFn = tls.LoadX509KeyPair
var readFileFn = os.ReadFile
var newCertPoolFn = x509.NewCertPool
var quit chan os.Signal
var logServerInfoFn = func(message string) {
	builder.New(context.Background()).Info(message)
}
var logServerErrorFn = func(err error) {
	builder.New(context.Background()).Error(err)
}
var loadEnv = utilities.LoadEnv
var initLogger = builder.InitLogger
var initOtel = traces.InitOtel
var runAsyncFn = func(fn func()) {
	go fn()
}
var waitForShutdownSignalFn = waitForShutdownSignal

type handlerShutdown func(ctx context.Context) error

const timeout = 30 * time.Second

func init() {
	quit = make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
}

// RegisterServiceFunc allows registering any generated gRPC service from the proto package.
// Example:
//
//	srv.Register(func(r grpc.ServiceRegistrar) {
//	  proto.RegisterGreeterServer(r, handler)
//	})
type RegisterServiceFunc func(grpc.ServiceRegistrar)

// IConfig defines the basic operations required to configure and run a unary gRPC server.
//
// The implementation is transport-oriented and does not depend on a specific proto service.
// Generated registrations from the proto package can be injected through Register.
type IConfig interface {
	// SetAddress defines the TCP address that will be used when Serve needs to create its own listener.
	SetAddress(address string)

	// SetListener defines an external listener. If present, Serve uses it instead of creating a new one.
	SetListener(listener net.Listener)

	// Register injects one generated registration function against the underlying grpc.Server.
	Register(register RegisterServiceFunc) error

	// Serve starts the gRPC server using the configured listener or address.
	Serve() error

	// GracefulStop stops the server gracefully.
	GracefulStop()

	// Stop stops the server immediately.
	Stop()

	// GetServer returns the underlying grpc.Server.
	GetServer() *grpc.Server

	// GetListener returns the currently configured listener.
	GetListener() net.Listener
}

type Config struct {
	mocks              IConfig
	server             *grpc.Server
	serverErr          error
	listener           net.Listener
	address            string
	shutdownList       []handlerShutdown
	unaryInterceptors  []grpc.UnaryServerInterceptor
	streamInterceptors []grpc.StreamServerInterceptor
	mux                sync.RWMutex
}

var tlsConfig *tls.Config

// ConfigOption customizes internally created gRPC servers.
type ConfigOption func(*Config)

// WithUnaryInterceptors appends unary interceptors to the default traces and
// logger interceptor chain.
func WithUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) ConfigOption {
	return func(config *Config) {
		for _, interceptor := range interceptors {
			if interceptor != nil {
				config.unaryInterceptors = append(config.unaryInterceptors, interceptor)
			}
		}
	}
}

// WithStreamInterceptors appends stream interceptors to the default traces and
// logger interceptor chain.
func WithStreamInterceptors(interceptors ...grpc.StreamServerInterceptor) ConfigOption {
	return func(config *Config) {
		for _, interceptor := range interceptors {
			if interceptor != nil {
				config.streamInterceptors = append(config.streamInterceptors, interceptor)
			}
		}
	}
}

// SetTLSConfig sets the TLS configuration that NewIConfig should attach to
// internally created gRPC servers.
//
// When a custom grpc.Server is injected into NewIConfig, this configuration is
// ignored because the server has already been created by the caller.
func SetTLSConfig(config *tls.Config) {
	tlsConfig = config
}

// NewIConfig creates a new unary gRPC server wrapper.
//
// The server parameter lets callers inject an already constructed
// *grpc.Server when they need explicit control over server options before
// handing execution to this package.
//
// If server is nil, the function creates a default grpc.Server with the
// package interceptors for traces and logging.
//
// If server is not nil, that instance is used as-is and its existing
// configuration is preserved.
//
// If mocks is provided, all operations delegate to it, which is useful for
// tests generated with mockgen.
//
// Common usage:
//
//	srv := unitary.NewIConfig(nil, nil)
//	srv.SetAddress(":50051")
//	err := srv.Register(func(r grpc.ServiceRegistrar) {
//		proto.RegisterGreeterServer(r, handler)
//	})
//	if err != nil {
//		return err
//	}
//	return srv.Serve()
//
// Example with a custom gRPC server:
//
//	custom := grpc.NewServer()
//	srv := unitary.NewIConfig(nil, custom)
func NewIConfig(mocks IConfig, server *grpc.Server, options ...ConfigOption) IConfig {
	config := &Config{
		mocks:  mocks,
		server: server,
	}

	for _, option := range options {
		if option != nil {
			option(config)
		}
	}
	if mocks != nil {
		return config
	}

	dir, err := os.Getwd()
	if err != nil {
		config.serverErr = err
	} else {
		shutdownList, loadErr := loadConfig(dir)
		config.shutdownList = onceShutdownHandlers(shutdownList)
		config.serverErr = loadErr
	}
	return config
}

func (su *Config) SetAddress(address string) {
	su.mux.Lock()
	defer su.mux.Unlock()
	su.address = address
}

func (su *Config) SetListener(listener net.Listener) {
	su.mux.Lock()
	defer su.mux.Unlock()
	su.listener = listener
}

func (su *Config) Register(register RegisterServiceFunc) error {
	if su.mocks != nil {
		return su.mocks.Register(register)
	}
	if err := su.ensureServer(); err != nil {
		return errors.Join(err, su.shutdown())
	}
	if register == nil {
		return fmt.Errorf("register function is required")
	}
	register(su.server)
	return nil
}

func (su *Config) Serve() (resultErr error) {
	if su.mocks != nil {
		return su.mocks.Serve()
	}

	if err := su.ensureServer(); err != nil {
		return errors.Join(err, su.shutdown())
	}

	su.mux.Lock()
	if su.listener == nil {
		if su.address == "" {
			su.address = strings.TrimSpace(viper.GetString("server.grpc.port"))
		}
		if su.address == "" {
			su.mux.Unlock()
			return errors.Join(
				fmt.Errorf("address or listener is required"),
				su.shutdown(),
			)
		}

		listener, err := listenTCP("tcp", su.address)
		if err != nil {
			su.mux.Unlock()
			return errors.Join(
				fmt.Errorf("problem creating tcp listener: %w", err),
				su.shutdown(),
			)
		}
		su.listener = listener
	}
	listener := su.listener
	server := su.server
	shutdownList := append([]handlerShutdown(nil), su.shutdownList...)
	su.mux.Unlock()

	address := listener.Addr().String()
	logServerInfoFn(fmt.Sprintf("gRPC server started on %s", address))
	done := make(chan struct{})
	waiterDone := make(chan struct{})
	waitFn := waitForShutdownSignalFn
	defer func() {
		close(done)
		<-waiterDone
		resultErr = errors.Join(resultErr, su.shutdown())
	}()
	runAsyncFn(func() {
		defer close(waiterDone)
		waitFn(server, shutdownList, done)
	})

	if err := server.Serve(listener); err != nil {
		logServerErrorFn(fmt.Errorf("gRPC server stopped with error: %w", err))
		return err
	}

	logServerInfoFn("gRPC server stopped successfully")
	return nil
}

func loadConfigDefaultGRPC() {
	viper.SetDefault("server.grpc.rate.limit", 1000)
	viper.SetDefault("server.grpc.rate.burst", 2000)
}

func loadConfig(prefixPath string) ([]handlerShutdown, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := loadEnv(prefixPath); err != nil {
		return nil, err
	}
	loadConfigDefaultGRPC()

	path := filepath.Join(prefixPath, viper.GetString("logger.dir"))
	lp, err := initLogger(ctx, path)
	if err != nil {
		return nil, err
	}

	shutdownList := []handlerShutdown{lp.Shutdown}
	shutdownOtel, err := initOtel(ctx)
	if err != nil {
		return nil, errors.Join(err, lp.Shutdown(ctx))
	}
	shutdownList = append(shutdownList, shutdownOtel)
	return shutdownList, nil
}

func onceShutdownHandlers(shutdownList []handlerShutdown) []handlerShutdown {
	wrapped := make([]handlerShutdown, 0, len(shutdownList))
	for _, shutdown := range shutdownList {
		if shutdown == nil {
			continue
		}
		var (
			once sync.Once
			err  error
		)
		handler := shutdown
		wrapped = append(wrapped, func(ctx context.Context) error {
			once.Do(func() {
				err = handler(ctx)
			})
			return err
		})
	}
	return wrapped
}

func (su *Config) shutdown() error {
	su.mux.RLock()
	shutdownList := append([]handlerShutdown(nil), su.shutdownList...)
	su.mux.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var shutdownErr error
	for _, shutdown := range shutdownList {
		shutdownErr = errors.Join(shutdownErr, shutdown(ctx))
	}
	return shutdownErr
}

func (su *Config) logShutdownError() {
	if err := su.shutdown(); err != nil {
		logServerErrorFn(err)
	}
}

func waitForShutdownSignal(server *grpc.Server, shutdownList []handlerShutdown, done <-chan struct{}) {
	select {
	case <-quit:
	case <-done:
		return
	}
	logServerInfoFn("Signal received, turning off gRPC server...")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for _, shutdown := range shutdownList {
		if err := shutdown(ctx); err != nil {
			logServerErrorFn(err)
		}
	}
	server.GracefulStop()
}

func (su *Config) GracefulStop() {
	if su.mocks != nil {
		su.mocks.GracefulStop()
		return
	}
	su.mux.RLock()
	server := su.server
	su.mux.RUnlock()
	if server != nil {
		server.GracefulStop()
		su.logShutdownError()
		return
	}
	if err := su.ensureServer(); err != nil {
		logServerErrorFn(errors.Join(
			fmt.Errorf("gRPC server initialization: %w", err),
			su.shutdown(),
		))
		return
	}
	su.server.GracefulStop()
	su.logShutdownError()
}

func (su *Config) Stop() {
	if su.mocks != nil {
		su.mocks.Stop()
		return
	}
	su.mux.RLock()
	server := su.server
	su.mux.RUnlock()
	if server != nil {
		server.Stop()
		su.logShutdownError()
		return
	}
	if err := su.ensureServer(); err != nil {
		logServerErrorFn(errors.Join(
			fmt.Errorf("gRPC server initialization: %w", err),
			su.shutdown(),
		))
		return
	}
	su.server.Stop()
	su.logShutdownError()
}

func (su *Config) GetServer() *grpc.Server {
	if su.mocks != nil {
		return su.mocks.GetServer()
	}
	su.mux.RLock()
	server := su.server
	su.mux.RUnlock()
	if server != nil {
		return server
	}
	if err := su.ensureServer(); err != nil {
		logServerErrorFn(errors.Join(
			fmt.Errorf("gRPC server initialization: %w", err),
			su.shutdown(),
		))
		return nil
	}
	return su.server
}

func (su *Config) GetListener() net.Listener {
	if su.mocks != nil {
		return su.mocks.GetListener()
	}

	su.mux.RLock()
	defer su.mux.RUnlock()
	return su.listener
}

func (su *Config) ensureServer() error {
	su.mux.Lock()
	defer su.mux.Unlock()
	return su.ensureServerLocked()
}

func (su *Config) ensureServerLocked() error {
	if su.server != nil || su.serverErr != nil {
		return su.serverErr
	}

	options, err := su.defaultServerOptions()
	if err != nil {
		su.serverErr = err
		return err
	}
	su.server = grpc.NewServer(options...)
	return nil
}

func (su *Config) defaultServerOptions() ([]grpc.ServerOption, error) {
	rateLimiter := newGRPCRateLimiter()
	unaryInterceptors := []grpc.UnaryServerInterceptor{
		rateLimitUnaryInterceptor(rateLimiter),
		traces.MiddlewareOtelGRPCUnary(),
		loggerGRPCMiddlewares.InitLoggerUnaryServerInterceptor(),
		loggerGRPCMiddlewares.LoggerWithConfigUnaryServerInterceptor(),
		loggerGRPCMiddlewares.CaptureBodyUnaryServerInterceptor(),
	}
	unaryInterceptors = append(unaryInterceptors, su.unaryInterceptors...)

	streamInterceptors := []grpc.StreamServerInterceptor{
		rateLimitStreamInterceptor(rateLimiter),
		traces.MiddlewareOtelGRPCStream(),
		loggerGRPCMiddlewares.InitLoggerStreamServerInterceptor(),
		loggerGRPCMiddlewares.LoggerWithConfigStreamServerInterceptor(),
		loggerGRPCMiddlewares.CaptureBodyStreamServerInterceptor(),
	}
	streamInterceptors = append(streamInterceptors, su.streamInterceptors...)

	options := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(streamInterceptors...),
	}

	config, err := resolveTLSConfig()
	if err != nil {
		return nil, err
	}
	if config != nil {
		options = append(options, grpc.Creds(credentials.NewTLS(config)))
	}
	return options, nil
}

func newGRPCRateLimiter() *rate.Limiter {
	rateLimit := viper.GetFloat64("server.grpc.rate.limit")
	if rateLimit == 0 {
		return nil
	}

	burst := viper.GetInt("server.grpc.rate.burst")
	if burst <= 0 {
		burst = int(rateLimit)
		if burst <= 0 {
			burst = 1
		}
	}
	return rate.NewLimiter(rate.Limit(rateLimit), burst)
}

func rateLimitUnaryInterceptor(limiter *rate.Limiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if limiter != nil && !limiter.Allow() {
			return nil, status.Error(codes.ResourceExhausted, "too many requests, please try again later")
		}
		return handler(ctx, req)
	}
}

func rateLimitStreamInterceptor(limiter *rate.Limiter) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if limiter != nil && !limiter.Allow() {
			return status.Error(codes.ResourceExhausted, "too many requests, please try again later")
		}
		return handler(srv, stream)
	}
}

func resolveTLSConfig() (*tls.Config, error) {
	if tlsConfig != nil {
		return tlsConfig, nil
	}

	tlsEnabled := viper.GetBool("server.grpc.tls.enable")
	mtlsEnabled := viper.GetBool("server.grpc.mtls.enable")
	if !tlsEnabled && !mtlsEnabled {
		return nil, nil
	}

	certFile := strings.TrimSpace(viper.GetString("server.grpc.tls.certFile"))
	keyFile := strings.TrimSpace(viper.GetString("server.grpc.tls.keyFile"))
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("server.grpc.tls.certFile and server.grpc.tls.keyFile are required")
	}

	certificate, err := loadX509KeyPairFn(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("problem loading server tls certificate: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   parseTLSVersion(viper.GetString("server.grpc.tls.version")),
	}

	if mtlsEnabled {
		clientCAFile := strings.TrimSpace(viper.GetString("server.grpc.mtls.clientCAFile"))
		if clientCAFile == "" {
			return nil, fmt.Errorf("server.grpc.mtls.clientCAFile is required")
		}

		caPEM, err := readFileFn(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("problem reading client ca file: %w", err)
		}

		pool := newCertPoolFn()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("problem parsing client ca file")
		}
		config.ClientCAs = pool
		config.ClientAuth = parseClientAuth(viper.GetString("server.grpc.mtls.clientAuth"))
	}

	return config, nil
}

func parseTLSVersion(raw string) uint16 {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "tlsv10":
		return tls.VersionTLS10
	case "tlsv11":
		return tls.VersionTLS11
	case "tlsv13":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

func parseClientAuth(raw string) tls.ClientAuthType {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "requestclientcert", "request_client_cert":
		return tls.RequestClientCert
	case "requireanyclientcert", "require_any_client_cert":
		return tls.RequireAnyClientCert
	case "verifyclientcertifgiven", "verify_client_cert_if_given":
		return tls.VerifyClientCertIfGiven
	case "noclientcert", "no_client_cert":
		return tls.NoClientCert
	default:
		return tls.RequireAndVerifyClientCert
	}
}
