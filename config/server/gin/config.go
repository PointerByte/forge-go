// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package gin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PointerByte/forge-go/logger/builder"
	httpMiddlewaresLogger "github.com/PointerByte/forge-go/logger/middlewares/http"
	"github.com/PointerByte/forge-go/security/middlewares"
	"github.com/PointerByte/forge-go/tools/utilities"
	"github.com/PointerByte/forge-go/tools/utilities/traces"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/time/rate"
)

var quit chan os.Signal

func init() {
	quit = make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
}

func loadConfigDefaultGin() {
	gin.SetMode(viper.GetString("server.gin.mode"))
	viper.SetDefault("server.gin.UseH2C", true)
	viper.SetDefault("server.gin.rate.Limit", 1000)
	viper.SetDefault("server.gin.rate.burst", 2000)
	viper.SetDefault("server.gin.readHeaderTimeout", "5s")
	viper.SetDefault("jwt.transport", "header")
}

var sleepFn = time.Sleep
var listenAndServeFn = func(srv *http.Server) error {
	return srv.ListenAndServe()
}
var listenAndServeTLSFn = func(srv *http.Server) error {
	return srv.ListenAndServeTLS("", "")
}
var shutdownServerFn = func(srv *http.Server, ctx context.Context) error {
	return srv.Shutdown(ctx)
}
var loadX509KeyPairFn = tls.LoadX509KeyPair
var readFileFn = os.ReadFile
var newCertPoolFn = x509.NewCertPool
var builderNewFn = builder.New
var logServerErrorFn = func(err error) {
	builder.New(context.Background()).Error(err)
}
var stopFn = Stop
var waitForShutdownSignalFn = waitForShutdownSignal
var runAsyncFn = func(fn func()) {
	go fn()
}

var initLogger = builder.InitLogger

var initOtel = traces.InitOtel

type handlerShutdown func(ctx context.Context) error

var shutdownList []handlerShutdown
var shutdownMu sync.RWMutex
var loadEnv = utilities.LoadEnv

func loadConfig(prefixPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := loadEnv(prefixPath); err != nil {
		return err
	}
	path := filepath.Join(prefixPath, viper.GetString("logger.dir"))

	lp, err := initLogger(ctx, path)
	if err != nil {
		return err
	}
	handlers := []handlerShutdown{lp.Shutdown}

	shutdownOtel, err := initOtel(ctx)
	if err != nil {
		return errors.Join(err, lp.Shutdown(ctx))
	}
	handlers = append(handlers, shutdownOtel)

	shutdownMu.Lock()
	shutdownList = handlers
	shutdownMu.Unlock()
	return nil
}

func limiter() gin.HandlerFunc {
	rateLimit := viper.GetFloat64("server.gin.rate.limit")
	if rateLimit == 0 {
		return func(c *gin.Context) {
			c.Next()
		}
	}
	bursts := viper.GetInt("server.gin.rate.burst")
	rateLimiter := rate.NewLimiter(rate.Limit(rateLimit), bursts)
	return func(c *gin.Context) {
		if !rateLimiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many requests, please try again later",
			})
			return
		}
		c.Next()
	}
}

var engine *gin.Engine

// GetEngine returns the shared Gin engine initialized by CreateApp.
//
// Its main purpose is to expose the configured router after package startup so
// application code can keep registering routes, groups, middleware, or test
// requests against the same engine instance that the HTTP server will use.
//
// Typical usage is:
//   - call CreateApp to load configuration and build the server
//   - call GetEngine to access the initialized router
//   - register endpoints directly or through groups returned by GetRoute
//   - pass the returned server to Start
//
// It returns nil until CreateApp finishes successfully.
func GetEngine() *gin.Engine {
	return engine
}

var tlsConfig *tls.Config

// SetTLSsConfig sets the TLS configuration that CreateApp should attach to the
// returned http.Server.
//
// It can be used to inject a custom TLS configuration before starting the
// server. If automatic TLS is also enabled, the auto-generated configuration
// may replace the previously assigned value.
func SetTLSsConfig(config *tls.Config) {
	tlsConfig = config
}

// resolveTLSAutoConfig configures a TLS setup backed by autocert when the related
// `server.gin.autotls.*` settings are enabled.
func resolveTLSAutoConfig() {
	if !viper.GetBool("server.gin.autotls.enable") {
		return
	}

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(viper.GetString("server.gin.autotls.domain")),
		Cache:      autocert.DirCache(viper.GetString("server.gin.autotls.dirCache")),
	}
	var versionTLS uint16
	switch viper.GetString("server.gin.autotls.version") {
	case "tlsv10":
		versionTLS = tls.VersionTLS10
	case "tlsv11":
		versionTLS = tls.VersionTLS11
	case "tlsv12":
		versionTLS = tls.VersionTLS12
	case "tlsv13":
		versionTLS = tls.VersionTLS13
	}
	tlsConfig = &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     versionTLS,
	}
}

func resolveTLSConfig() error {
	tlsEnabled := viper.GetBool("server.gin.tls.enable")
	mtlsEnabled := viper.GetBool("server.gin.mtls.enable")
	if !tlsEnabled && !mtlsEnabled {
		return nil
	}

	if tlsConfig != nil && !tlsEnabled {
		if tlsConfig.MinVersion == 0 {
			tlsConfig.MinVersion = parseTLSVersion(viper.GetString("server.gin.tls.version"))
		}
		return nil
	}

	certFile := strings.TrimSpace(viper.GetString("server.gin.tls.certFile"))
	keyFile := strings.TrimSpace(viper.GetString("server.gin.tls.keyFile"))
	if certFile == "" || keyFile == "" {
		return fmt.Errorf("server.gin.tls.certFile and server.gin.tls.keyFile are required")
	}

	certificate, err := loadX509KeyPairFn(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("problem loading gin server tls certificate: %w", err)
	}

	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   parseTLSVersion(viper.GetString("server.gin.tls.version")),
	}
	return nil
}

func resolvemTLSConfig() error {
	if !viper.GetBool("server.gin.mtls.enable") {
		return nil
	}
	if tlsConfig == nil {
		return fmt.Errorf("server.gin.tls.enable or a custom TLS config is required when server.gin.mtls.enable is true")
	}

	clientCAFile := strings.TrimSpace(viper.GetString("server.gin.mtls.clientCAFile"))
	if clientCAFile == "" {
		return fmt.Errorf("server.gin.mtls.clientCAFile is required")
	}

	caPEM, err := readFileFn(clientCAFile)
	if err != nil {
		return fmt.Errorf("problem reading gin client ca file: %w", err)
	}

	pool := newCertPoolFn()
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("problem parsing gin client ca file")
	}
	tlsConfig.ClientCAs = pool
	tlsConfig.ClientAuth = parseClientAuth(viper.GetString("server.gin.mtls.clientAuth"))
	return nil
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

// CreateApp builds the configured HTTP server for the application.
//
// It loads configuration files and environment overrides, initializes logging
// and OpenTelemetry, sets up the Gin engine, registers shared middleware, and
// creates the route groups declared in configuration.
func CreateApp() (*http.Server, error) {
	// Load default config.
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	if err := loadConfig(dir); err != nil {
		return nil, err
	}

	// Configure env defaults.
	loadConfigDefaultGin()

	// Initialize engine.
	engine = gin.New()
	engine.Use(cors.Default())
	engine.HandleMethodNotAllowed = true
	engine.NoRoute(notFound())
	engine.NoMethod(noMethod())
	engine.Use(
		gin.Recovery(),
		limiter(),
		middlewares.SecurityHeaders(),
		traces.MiddlewareOtel(),
		httpMiddlewaresLogger.InitLogger(),
		httpMiddlewaresLogger.LoggerWithConfig(),
		httpMiddlewaresLogger.CaptureBody(),
	)
	engine.UseH2C = viper.GetBool("server.gin.UseH2C")

	// Create API route groups.
	routes := make(map[string]*gin.RouterGroup)
	groups := viper.GetStringSlice("server.gin.groups")
	for _, g := range groups {
		routes[g] = engine.Group(g)
		routes[g].GET("/health", healthGin())
	}
	setRoute(routes)
	resolveTLSAutoConfig()
	if err := resolveTLSConfig(); err != nil {
		return nil, err
	}
	if err := resolvemTLSConfig(); err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              viper.GetString("server.gin.port"),
		Handler:           engine,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: viper.GetDuration("server.gin.readHeaderTimeout"),
	}, nil
}

const timeout = 30 * time.Second

// Start runs the provided HTTP server and coordinates the shutdown workflow.
//
// It starts the listener, logs the configured port, and then executes the
// registered shutdown handlers before stopping the server.
func Start(srv *http.Server) {
	if srv == nil {
		logServerErrorFn(errors.New("http server is required"))
		return
	}

	ctx := context.Background()
	ctxLogger := builderNewFn(ctx)

	// Start server.
	runAsyncFn(func() {
		if srv.TLSConfig != nil {
			if err := listenAndServeTLSFn(srv); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logServerErrorFn(fmt.Errorf("https listener: %w", err))
				stopFn()
			}
			return
		}
		if err := listenAndServeFn(srv); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logServerErrorFn(fmt.Errorf("http listener: %w", err))
			stopFn()
		}
	})

	port := viper.GetString("server.gin.port")
	ctxLogger.Info(fmt.Sprintf("Server started on port %s", port))
	shutdownFn(srv)
}

func shutdownFn(srv *http.Server) {
	// Graceful shutdown.
	waitForShutdownSignalFn()

	ctx := context.Background()
	ctxLogger := builderNewFn(ctx)

	// Execute shutdown handlers.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	shutdownMu.RLock()
	handlers := append([]handlerShutdown(nil), shutdownList...)
	shutdownMu.RUnlock()
	for _, s := range handlers {
		if err := s(ctx); err != nil {
			ctxLogger.Error(fmt.Errorf("shutdown handler: %w", err))
		}
	}

	if err := shutdownServerFn(srv, ctx); err != nil {
		ctxLogger.Error(fmt.Errorf("shutdown force: %v", err))
		return
	}
	ctxLogger.Info("Server stopped successfully")
}

func waitForShutdownSignal() {
	<-quit

	ctx := context.Background()
	ctxLogger := builderNewFn(ctx)
	ctxLogger.Info("Signal received, turning off...")
}

// Stop triggers the package shutdown signal used by the graceful-stop flow.
//
// It sends a SIGTERM-like signal through the internal channel after a short
// delay so the same shutdown path can be used from runtime code and tests.
func Stop() {
	sleepFn(time.Second)
	select {
	case quit <- syscall.SIGTERM:
	default:
	}
}
