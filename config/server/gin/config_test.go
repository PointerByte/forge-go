// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package gin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/PointerByte/forge-go/logger/builder"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	jwtservice "github.com/PointerByte/forge-go/security/auth/jwt"
	"github.com/PointerByte/forge-go/security/middlewares"
	"github.com/PointerByte/forge-go/tools/utilities"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

func resetServerTestState(t *testing.T) {
	t.Helper()

	origLoadEnv := loadEnv
	origInitLogger := initLogger
	origInitOtel := initOtel
	origSleepFn := sleepFn
	origListenAndServeFn := listenAndServeFn
	origListenAndServeTLSFn := listenAndServeTLSFn
	origShutdownServerFn := shutdownServerFn
	origLoadX509KeyPairFn := loadX509KeyPairFn
	origReadFileFn := readFileFn
	origNewCertPoolFn := newCertPoolFn
	origBuilderNewFn := builderNewFn
	origLogServerErrorFn := logServerErrorFn
	origStartJobsFn := startJobsFn
	origStopFn := stopFn
	origWaitForShutdownSignalFn := waitForShutdownSignalFn
	origRunAsyncFn := runAsyncFn
	origQuit := quit
	origEngine := engine
	origTLSConfig := tlsConfig
	origShutdownList := shutdownList
	origGlobalRoute := globalRoute
	origGinMode := gin.Mode()

	viper.Reset()
	viperdata.ResetViperDataSingleton()
	engine = nil
	tlsConfig = nil
	shutdownList = nil
	globalRoute = nil
	quit = make(chan os.Signal, 1)
	loadEnv = utilitiesLoadEnvNoop
	initLogger = builder.InitLogger
	initOtel = tracesInitNoop
	sleepFn = time.Sleep
	listenAndServeFn = func(srv *http.Server) error { return srv.ListenAndServe() }
	listenAndServeTLSFn = func(srv *http.Server) error { return srv.ListenAndServeTLS("", "") }
	shutdownServerFn = func(srv *http.Server, ctx context.Context) error { return srv.Shutdown(ctx) }
	loadX509KeyPairFn = tls.LoadX509KeyPair
	readFileFn = os.ReadFile
	newCertPoolFn = x509.NewCertPool
	builderNewFn = builder.New
	logServerErrorFn = func(error) {}
	startJobsFn = func() {}
	stopFn = Stop
	waitForShutdownSignalFn = waitForShutdownSignal
	runAsyncFn = func(fn func()) { go fn() }
	gin.SetMode(gin.TestMode)
	viper.Set("app.name", "test-app")
	viper.Set("app.version", "1.0.0")
	builder.EnableModeTest()

	t.Cleanup(func() {
		loadEnv = origLoadEnv
		initLogger = origInitLogger
		initOtel = origInitOtel
		sleepFn = origSleepFn
		listenAndServeFn = origListenAndServeFn
		listenAndServeTLSFn = origListenAndServeTLSFn
		shutdownServerFn = origShutdownServerFn
		loadX509KeyPairFn = origLoadX509KeyPairFn
		readFileFn = origReadFileFn
		newCertPoolFn = origNewCertPoolFn
		builderNewFn = origBuilderNewFn
		logServerErrorFn = origLogServerErrorFn
		startJobsFn = origStartJobsFn
		stopFn = origStopFn
		waitForShutdownSignalFn = origWaitForShutdownSignalFn
		runAsyncFn = origRunAsyncFn
		quit = origQuit
		engine = origEngine
		tlsConfig = origTLSConfig
		shutdownList = origShutdownList
		globalRoute = origGlobalRoute
		gin.SetMode(origGinMode)
		viper.Reset()
		viperdata.ResetViperDataSingleton()
	})
}

func utilitiesLoadEnvNoop(string) error {
	return nil
}

func tracesInitNoop(context.Context) (func(context.Context) error, error) {
	return func(context.Context) error { return nil }, nil
}

func writeApplicationJSON(t *testing.T, dir string, data map[string]any) {
	t.Helper()

	payload, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "application.json"), payload, 0o600); err != nil {
		t.Fatalf("write application.json: %v", err)
	}
}

func newLoggerProviderNoop(context.Context, string) (*sdklog.LoggerProvider, error) {
	return sdklog.NewLoggerProvider(), nil
}

func TestLoadConfigDefaultGin(t *testing.T) {
	resetServerTestState(t)
	viper.Set("server.gin.mode", gin.ReleaseMode)

	loadConfigDefaultGin()

	if got := gin.Mode(); got != gin.ReleaseMode {
		t.Fatalf("expected release mode, got %q", got)
	}
	if !viper.GetBool("server.gin.UseH2C") {
		t.Fatal("expected server.gin.UseH2C default true")
	}
	if got := viper.GetInt("server.gin.rate.limit"); got != 1000 {
		t.Fatalf("expected limit 1000, got %d", got)
	}
	if got := viper.GetInt("server.gin.rate.burst"); got != 2000 {
		t.Fatalf("expected burst 2000, got %d", got)
	}
	if got := viper.GetDuration("server.gin.readHeaderTimeout"); got != 5*time.Second {
		t.Fatalf("expected read header timeout 5s, got %s", got)
	}
}

func TestLoadConfig(t *testing.T) {
	t.Run("load env error", func(t *testing.T) {
		resetServerTestState(t)
		wantErr := errors.New("load env")
		loadEnv = func(string) error { return wantErr }

		err := loadConfig(t.TempDir())
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected %v, got %v", wantErr, err)
		}
	})

	t.Run("init logger error", func(t *testing.T) {
		resetServerTestState(t)
		dir := t.TempDir()
		writeApplicationJSON(t, dir, map[string]any{"logger": map[string]any{"dir": "logs"}})
		wantErr := errors.New("logger")
		initLogger = func(context.Context, string) (*sdklog.LoggerProvider, error) {
			return nil, wantErr
		}

		err := loadConfig(dir)
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected %v, got %v", wantErr, err)
		}
	})

	t.Run("init otel error", func(t *testing.T) {
		resetServerTestState(t)
		dir := t.TempDir()
		writeApplicationJSON(t, dir, map[string]any{"logger": map[string]any{"dir": "logs"}})
		wantErr := errors.New("otel")
		initLogger = newLoggerProviderNoop
		initOtel = func(context.Context) (func(context.Context) error, error) {
			return nil, wantErr
		}

		err := loadConfig(dir)
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected %v, got %v", wantErr, err)
		}
	})

	t.Run("success", func(t *testing.T) {
		resetServerTestState(t)
		dir := t.TempDir()
		writeApplicationJSON(t, dir, map[string]any{
			"app":    map[string]any{"name": "svc"},
			"logger": map[string]any{"dir": "logs"},
		})
		initLogger = newLoggerProviderNoop
		initOtel = tracesInitNoop

		if err := loadConfig(dir); err != nil {
			t.Fatalf("loadConfig returned error: %v", err)
		}
		if len(shutdownList) != 2 {
			t.Fatalf("expected 2 shutdown handlers, got %d", len(shutdownList))
		}
	})
}

func TestLimiter(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		resetServerTestState(t)
		viper.Set("server.gin.rate.limit", 0)

		router := gin.New()
		router.Use(limiter())
		router.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", rec.Code)
		}
	})

	t.Run("rate limited", func(t *testing.T) {
		resetServerTestState(t)
		viper.Set("server.gin.rate.limit", 1)
		viper.Set("server.gin.rate.burst", 1)

		router := gin.New()
		router.Use(limiter())
		router.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

		rec1 := httptest.NewRecorder()
		router.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec1.Code != http.StatusNoContent {
			t.Fatalf("expected first request 204, got %d", rec1.Code)
		}

		rec2 := httptest.NewRecorder()
		router.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec2.Code != http.StatusTooManyRequests {
			t.Fatalf("expected second request 429, got %d", rec2.Code)
		}
	})
}

func TestHandlersAndRoutes(t *testing.T) {
	t.Run("default health handler", func(t *testing.T) {
		resetServerTestState(t)
		viper.Set("app.name", "svc")
		viper.Set("app.version", "1.0.0")

		router := gin.New()
		router.GET("/health", healthGin())

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if body := rec.Body.String(); body == "" {
			t.Fatal("expected body")
		}
	})

	t.Run("set and get route", func(t *testing.T) {
		resetServerTestState(t)
		router := gin.New()
		group := router.Group("/api")
		setRoute(map[string]*gin.RouterGroup{"/api": group})
		if got := GetRoute("/api"); got != group {
			t.Fatal("expected same route group")
		}
		if got := GetRoute("/missing"); got != nil {
			t.Fatalf("expected nil missing route, got %#v", got)
		}
	})
}

func TestCreateApp(t *testing.T) {
	t.Run("load config error", func(t *testing.T) {
		resetServerTestState(t)
		wantErr := errors.New("config error")
		loadEnv = func(string) error { return wantErr }

		srv, err := CreateApp()
		if !errors.Is(err, wantErr) || srv != nil {
			t.Fatalf("expected config error, got srv=%v err=%v", srv, err)
		}
	})

	t.Run("success builds server and routes", func(t *testing.T) {
		resetServerTestState(t)
		loadEnv = func(string) error {
			viper.Set("logger.dir", "logs")
			viper.Set("server.port", ":8080")
			viper.Set("server.gin.port", ":8080")
			viper.Set("server.gin.groups", []string{"/api/v1"})
			viper.Set("server.gin.UseH2C", true)
			viper.Set("jwt.enable", false)
			viper.Set("app.name", "svc")
			viper.Set("app.version", "1.0.0")
			return nil
		}
		initLogger = newLoggerProviderNoop
		initOtel = tracesInitNoop

		srv, err := CreateApp()
		if err != nil {
			t.Fatalf("createApp returned error: %v", err)
		}
		if srv == nil || srv.Handler == nil {
			t.Fatal("expected configured server")
		}
		if srv.Addr != ":8080" {
			t.Fatalf("expected :8080, got %q", srv.Addr)
		}
		if srv.ReadHeaderTimeout != 5*time.Second {
			t.Fatalf("expected read header timeout 5s, got %s", srv.ReadHeaderTimeout)
		}
		if GetEngine() == nil {
			t.Fatal("expected engine to be set")
		}
		if !GetEngine().UseH2C {
			t.Fatal("expected UseH2C enabled")
		}
		if GetRoute("/api/v1") == nil {
			t.Fatal("expected route group to exist")
		}

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		GetEngine().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected health endpoint 200, got %d", rec.Code)
		}
	})

	t.Run("uses preconfigured tls config when auto tls disabled", func(t *testing.T) {
		resetServerTestState(t)
		loadEnv = func(string) error {
			viper.Set("logger.dir", "logs")
			viper.Set("server.port", ":8443")
			viper.Set("server.gin.port", ":8443")
			viper.Set("server.gin.groups", []string{"/api/v1"})
			viper.Set("server.gin.autotls.enable", false)
			return nil
		}
		initLogger = newLoggerProviderNoop
		initOtel = tracesInitNoop

		expectedTLS := &tls.Config{MinVersion: tls.VersionTLS12}
		SetTLSsConfig(expectedTLS)

		srv, err := CreateApp()
		if err != nil {
			t.Fatalf("createApp returned error: %v", err)
		}
		if srv.TLSConfig != expectedTLS {
			t.Fatal("expected custom tls config to be preserved")
		}
	})

	t.Run("supports jwt cookie transport", func(t *testing.T) {
		resetServerTestState(t)
		loadEnv = func(string) error {
			viper.Set("logger.dir", "logs")
			viper.Set("server.port", ":8080")
			viper.Set("server.gin.port", ":8080")
			viper.Set("server.gin.groups", []string{"/api/v1"})
			viper.Set("server.gin.UseH2C", true)
			viper.Set("jwt.enable", true)
			viper.Set("jwt.transport", "cookie")
			viper.Set("jwt.algorithm", "HS256")
			viper.Set("jwt.hmac.secret", "cookie-secret")
			viper.Set("jwt.cookie.name", "session_token")
			viper.Set("app.name", "svc")
			viper.Set("app.version", "1.0.0")
			return nil
		}
		initLogger = newLoggerProviderNoop
		initOtel = tracesInitNoop

		srv, err := CreateApp()
		if err != nil {
			t.Fatalf("createApp returned error: %v", err)
		}
		if srv == nil || srv.Handler == nil {
			t.Fatal("expected configured server")
		}

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		GetEngine().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected health endpoint without global jwt middleware 200, got %d", rec.Code)
		}
	})
}

func TestAuthMiddleware(t *testing.T) {
	t.Run("supports jwt cookie transport", func(t *testing.T) {
		resetServerTestState(t)
		viper.Set("jwt.enable", true)
		viper.Set("jwt.transport", "cookie")
		viper.Set("jwt.algorithm", "HS256")
		viper.Set("jwt.hmac.secret", "cookie-secret")
		viper.Set("jwt.cookie.name", "session_token")

		router := gin.New()
		protected := router.Group("/api")
		protected.Use(middlewares.RequireJWTCookie())
		protected.GET("/health", healthGin())

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected missing cookie request 401, got %d", rec.Code)
		}

		jwtService, err := jwtservice.NewConfiguredService(nil)
		if err != nil {
			t.Fatalf("expected jwt service without error, got %v", err)
		}
		token, err := jwtService.Create(map[string]any{"user_id": "42"})
		if err != nil {
			t.Fatalf("expected token without error, got %v", err)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/api/health", nil)
		req.AddCookie(&http.Cookie{Name: "session_token", Value: token})
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected cookie-authenticated health endpoint 200, got %d", rec.Code)
		}
	})
}

func TestTLSConfigurationHelpers(t *testing.T) {
	t.Run("SetTLSsConfig", func(t *testing.T) {
		resetServerTestState(t)

		expected := &tls.Config{MinVersion: tls.VersionTLS13}
		SetTLSsConfig(expected)

		if tlsConfig != expected {
			t.Fatal("expected tlsConfig to match injected config")
		}
	})

	tests := []struct {
		name       string
		enabled    bool
		version    string
		wantNil    bool
		wantMinTLS uint16
	}{
		{name: "disabled", enabled: false, wantNil: true},
		{name: "tls10", enabled: true, version: "tlsv10", wantMinTLS: tls.VersionTLS10},
		{name: "tls11", enabled: true, version: "tlsv11", wantMinTLS: tls.VersionTLS11},
		{name: "tls12", enabled: true, version: "tlsv12", wantMinTLS: tls.VersionTLS12},
		{name: "tls13", enabled: true, version: "tlsv13", wantMinTLS: tls.VersionTLS13},
		{name: "unknown version", enabled: true, version: "unknown", wantMinTLS: 0},
	}

	for _, tt := range tests {
		t.Run("enableAutoTLS "+tt.name, func(t *testing.T) {
			resetServerTestState(t)
			viper.Set("server.gin.autotls.enable", tt.enabled)
			viper.Set("server.gin.autotls.version", tt.version)
			viper.Set("server.gin.autotls.domain", "example.com")
			viper.Set("server.gin.autotls.dirCache", t.TempDir())

			resolveTLSAutoConfig()

			if tt.wantNil {
				if tlsConfig != nil {
					t.Fatalf("expected nil tlsConfig, got %#v", tlsConfig)
				}
				return
			}

			if tlsConfig == nil {
				t.Fatal("expected tlsConfig to be initialized")
			}
			if tlsConfig.GetCertificate == nil {
				t.Fatal("expected GetCertificate to be configured")
			}
			if tlsConfig.MinVersion != tt.wantMinTLS {
				t.Fatalf("expected MinVersion %d, got %d", tt.wantMinTLS, tlsConfig.MinVersion)
			}
		})
	}

	t.Run("resolve tls disabled", func(t *testing.T) {
		resetServerTestState(t)

		if err := resolveTLSConfig(); err != nil {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
		if tlsConfig != nil {
			t.Fatalf("tlsConfig = %#v, want nil", tlsConfig)
		}
	})

	t.Run("resolve tls requires cert and key", func(t *testing.T) {
		resetServerTestState(t)
		viper.Set("server.gin.tls.enable", true)

		err := resolveTLSConfig()
		if err == nil || err.Error() != "server.gin.tls.certFile and server.gin.tls.keyFile are required" {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
	})

	t.Run("resolve tls from config", func(t *testing.T) {
		resetServerTestState(t)
		loadX509KeyPairFn = func(certFile, keyFile string) (tls.Certificate, error) {
			if certFile != "server-cert.pem" || keyFile != "server-key.pem" {
				t.Fatalf("loadX509KeyPairFn(%q, %q)", certFile, keyFile)
			}
			return tls.Certificate{Certificate: [][]byte{{1}}}, nil
		}
		viper.Set("server.gin.tls.enable", true)
		viper.Set("server.gin.tls.certFile", "server-cert.pem")
		viper.Set("server.gin.tls.keyFile", "server-key.pem")
		viper.Set("server.gin.tls.version", "tlsv13")

		if err := resolveTLSConfig(); err != nil {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
		if tlsConfig == nil {
			t.Fatal("tlsConfig = nil, want configured TLS")
		}
		if tlsConfig.MinVersion != tls.VersionTLS13 {
			t.Fatalf("MinVersion = %v, want %v", tlsConfig.MinVersion, tls.VersionTLS13)
		}
		if len(tlsConfig.Certificates) != 1 {
			t.Fatalf("Certificates len = %d, want 1", len(tlsConfig.Certificates))
		}
	})

	t.Run("resolve mtls requires ca", func(t *testing.T) {
		resetServerTestState(t)
		tlsConfig = &tls.Config{}
		viper.Set("server.gin.mtls.enable", true)

		err := resolvemTLSConfig()
		if err == nil || err.Error() != "server.gin.mtls.clientCAFile is required" {
			t.Fatalf("resolvemTLSConfig() error = %v", err)
		}
	})

	t.Run("resolve mtls from config", func(t *testing.T) {
		resetServerTestState(t)
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer ts.Close()
		caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})

		tlsConfig = &tls.Config{}
		readFileFn = func(path string) ([]byte, error) {
			if path != "ca.pem" {
				t.Fatalf("readFileFn(%q)", path)
			}
			return caPEM, nil
		}
		viper.Set("server.gin.mtls.enable", true)
		viper.Set("server.gin.mtls.clientCAFile", "ca.pem")
		viper.Set("server.gin.mtls.clientAuth", "verify_client_cert_if_given")

		if err := resolvemTLSConfig(); err != nil {
			t.Fatalf("resolvemTLSConfig() error = %v", err)
		}
		if tlsConfig.ClientCAs == nil {
			t.Fatal("ClientCAs = nil, want populated pool")
		}
		if tlsConfig.ClientAuth != tls.VerifyClientCertIfGiven {
			t.Fatalf("ClientAuth = %v, want %v", tlsConfig.ClientAuth, tls.VerifyClientCertIfGiven)
		}
	})

	if got := parseTLSVersion("tlsv10"); got != tls.VersionTLS10 {
		t.Fatalf("parseTLSVersion(tlsv10) = %v, want %v", got, tls.VersionTLS10)
	}
	if got := parseTLSVersion("unknown"); got != tls.VersionTLS12 {
		t.Fatalf("parseTLSVersion(unknown) = %v, want %v", got, tls.VersionTLS12)
	}
	if got := parseClientAuth("request_client_cert"); got != tls.RequestClientCert {
		t.Fatalf("parseClientAuth(request_client_cert) = %v, want %v", got, tls.RequestClientCert)
	}
}

func TestStartAndShutdown(t *testing.T) {
	t.Run("start without tls", func(t *testing.T) {
		resetServerTestState(t)
		var listenCalls int32
		var jobsCalls int32
		var stopCalls int32
		var shutdownCalls int32

		runAsyncFn = func(fn func()) { go fn() }
		listenAndServeFn = func(*http.Server) error {
			atomic.AddInt32(&listenCalls, 1)
			return http.ErrServerClosed
		}
		startJobsFn = func() {
			atomic.AddInt32(&jobsCalls, 1)
		}
		waitForShutdownSignalFn = func() {
			atomic.AddInt32(&stopCalls, 1)
		}
		shutdownServerFn = func(*http.Server, context.Context) error {
			atomic.AddInt32(&shutdownCalls, 1)
			return nil
		}

		viper.Set("server.gin.port", ":7070")
		Start(&http.Server{})

		if atomic.LoadInt32(&jobsCalls) != 1 {
			t.Fatalf("expected 1 jobs start, got %d", jobsCalls)
		}
		if atomic.LoadInt32(&stopCalls) != 1 {
			t.Fatalf("expected 1 stop call, got %d", stopCalls)
		}
		if atomic.LoadInt32(&shutdownCalls) != 1 {
			t.Fatalf("expected 1 shutdown call, got %d", shutdownCalls)
		}

		time.Sleep(20 * time.Millisecond)
		if atomic.LoadInt32(&listenCalls) != 1 {
			t.Fatalf("expected 1 listen call, got %d", listenCalls)
		}
	})

	t.Run("start with tls uses tls listener", func(t *testing.T) {
		resetServerTestState(t)
		var listenCalls int32
		var listenTLSCalls int32

		runAsyncFn = func(fn func()) { fn() }
		listenAndServeFn = func(*http.Server) error {
			atomic.AddInt32(&listenCalls, 1)
			return http.ErrServerClosed
		}
		listenAndServeTLSFn = func(*http.Server) error {
			atomic.AddInt32(&listenTLSCalls, 1)
			return http.ErrServerClosed
		}
		startJobsFn = func() {}
		waitForShutdownSignalFn = func() {}
		shutdownServerFn = func(*http.Server, context.Context) error { return nil }

		Start(&http.Server{TLSConfig: &tls.Config{}})

		if atomic.LoadInt32(&listenTLSCalls) != 1 {
			t.Fatalf("expected 1 tls listen call, got %d", listenTLSCalls)
		}
		if atomic.LoadInt32(&listenCalls) != 0 {
			t.Fatalf("expected 0 plain listen calls, got %d", listenCalls)
		}
	})

	t.Run("shutdown server error path", func(t *testing.T) {
		resetServerTestState(t)
		waitForShutdownSignalFn = func() {}
		wantErr := errors.New("shutdown")
		shutdownServerFn = func(*http.Server, context.Context) error {
			return wantErr
		}

		shutdownFn(&http.Server{})
	})

	t.Run("shutdown handler errors do not stop remaining cleanup", func(t *testing.T) {
		resetServerTestState(t)
		var handlerCalls int32
		var shutdownCalls int32

		waitForShutdownSignalFn = func() {}
		shutdownList = []handlerShutdown{
			func(context.Context) error {
				atomic.AddInt32(&handlerCalls, 1)
				return errors.New("handler failed")
			},
			func(context.Context) error {
				atomic.AddInt32(&handlerCalls, 1)
				return nil
			},
		}
		shutdownServerFn = func(*http.Server, context.Context) error {
			atomic.AddInt32(&shutdownCalls, 1)
			return nil
		}

		shutdownFn(&http.Server{})

		if atomic.LoadInt32(&handlerCalls) != 2 {
			t.Fatalf("expected 2 shutdown handlers, got %d", handlerCalls)
		}
		if atomic.LoadInt32(&shutdownCalls) != 1 {
			t.Fatalf("expected server shutdown to run once, got %d", shutdownCalls)
		}
	})
}

func TestStartLogsUnexpectedListenErrorAndTriggersShutdown(t *testing.T) {
	resetServerTestState(t)

	waitForShutdownSignalFn = func() {}
	startJobsFn = func() {}
	shutdownServerFn = func(*http.Server, context.Context) error { return nil }
	runAsyncFn = func(fn func()) { fn() }
	var logged error
	logServerErrorFn = func(err error) {
		logged = err
	}
	stopCalls := 0
	stopFn = func() {
		stopCalls++
	}
	listenAndServeFn = func(*http.Server) error {
		return errors.New("boom")
	}

	Start(&http.Server{})
	if logged == nil || !strings.Contains(logged.Error(), "boom") {
		t.Fatalf("expected listener error to be logged, got %v", logged)
	}
	if stopCalls != 1 {
		t.Fatalf("expected shutdown trigger once, got %d", stopCalls)
	}
}

func TestStartRejectsNilServerWithoutPanic(t *testing.T) {
	resetServerTestState(t)

	var logged error
	logServerErrorFn = func(err error) {
		logged = err
	}
	Start(nil)
	if logged == nil || logged.Error() != "http server is required" {
		t.Fatalf("logged error = %v", logged)
	}
}

func TestLoadConfigReplacesShutdownHandlersAndCleansPartialInitialization(t *testing.T) {
	resetServerTestState(t)

	shutdownCalls := 0
	initLogger = func(context.Context, string) (*sdklog.LoggerProvider, error) {
		provider := sdklog.NewLoggerProvider()
		return provider, nil
	}
	initOtel = func(context.Context) (func(context.Context) error, error) {
		return func(context.Context) error {
			shutdownCalls++
			return nil
		}, nil
	}

	if err := loadConfig(t.TempDir()); err != nil {
		t.Fatalf("first loadConfig() error = %v", err)
	}
	if err := loadConfig(t.TempDir()); err != nil {
		t.Fatalf("second loadConfig() error = %v", err)
	}
	if len(shutdownList) != 2 {
		t.Fatalf("shutdown handlers accumulated: got %d, want 2", len(shutdownList))
	}

	initOtel = func(context.Context) (func(context.Context) error, error) {
		return nil, errors.New("otel failed")
	}
	if err := loadConfig(t.TempDir()); err == nil {
		t.Fatal("expected partial initialization error")
	}
	if shutdownCalls != 0 {
		t.Fatalf("unexpected retained OTEL shutdown call count %d", shutdownCalls)
	}
}

func TestStopAndSetModeTest(t *testing.T) {
	t.Run("stop sends signal", func(t *testing.T) {
		resetServerTestState(t)
		sleepFn = func(time.Duration) {}
		quit = make(chan os.Signal, 1)

		Stop()

		select {
		case sig := <-quit:
			if sig != syscall.SIGTERM {
				t.Fatalf("expected SIGTERM, got %v", sig)
			}
		default:
			t.Fatal("expected signal to be sent")
		}

		returned := make(chan struct{})
		go func() {
			Stop()
			close(returned)
		}()
		select {
		case <-returned:
		case <-time.After(time.Second):
			t.Fatal("repeated Stop blocked with shutdown already pending")
		}
	})

	t.Run("set mode test", func(t *testing.T) {
		resetServerTestState(t)
		utilities.SetModeTest()

		if got := gin.Mode(); got != gin.TestMode {
			t.Fatalf("expected gin test mode, got %q", got)
		}
		if !viper.GetBool("server.modeTest") {
			t.Fatal("expected server.modeTest true")
		}
	})
}
