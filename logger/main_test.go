// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

func TestLoadEnv(t *testing.T) {
	originalReadInConfig := readInConfig
	defer func() {
		readInConfig = originalReadInConfig
		viper.Reset()
	}()

	t.Run("success", func(t *testing.T) {
		called := false
		readInConfig = func() error {
			called = true
			return nil
		}

		err := loadEnv()
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if !called {
			t.Fatal("expected readInConfig to be called")
		}
	})

	t.Run("error", func(t *testing.T) {
		expectedErr := errors.New("read config error")
		readInConfig = func() error {
			return expectedErr
		}

		err := loadEnv()
		if !errors.Is(err, expectedErr) {
			t.Fatalf("expected %v, got %v", expectedErr, err)
		}
	})
}

func TestLoadConfig(t *testing.T) {
	originalReadInConfig := readInConfig
	originalInitLogger := initLogger

	defer func() {
		readInConfig = originalReadInConfig
		initLogger = originalInitLogger
		viper.Reset()
	}()

	t.Run("loadEnv error", func(t *testing.T) {
		expectedErr := errors.New("env error")

		readInConfig = func() error {
			return expectedErr
		}

		lp, err := loadConfig(context.Background())

		if lp != nil {
			t.Fatal("expected nil logger provider when loadEnv fails")
		}

		if !errors.Is(err, expectedErr) {
			t.Fatalf("expected %v, got %v", expectedErr, err)
		}
	})

	t.Run("initLogger error", func(t *testing.T) {
		expectedErr := errors.New("init logger error")

		readInConfig = func() error { return nil }

		initLogger = func(ctx context.Context, dir string) (*sdklog.LoggerProvider, error) {
			return nil, expectedErr
		}

		lp, err := loadConfig(context.Background())

		if lp != nil {
			t.Fatal("expected nil logger provider")
		}

		if !errors.Is(err, expectedErr) {
			t.Fatalf("expected %v, got %v", expectedErr, err)
		}
	})

	t.Run("success", func(t *testing.T) {
		readInConfig = func() error { return nil }

		var gotCtx context.Context
		var gotDir string
		initCalled := false

		wantLP := sdklog.NewLoggerProvider()

		initLogger = func(ctx context.Context, dir string) (*sdklog.LoggerProvider, error) {
			initCalled = true
			gotCtx = ctx
			gotDir = dir
			return wantLP, nil
		}

		type contextKey string

		const testContextKey contextKey = "k"

		ctx := context.WithValue(context.Background(), testContextKey, "v")

		lp, err := loadConfig(ctx)

		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}

		if lp != wantLP {
			t.Fatal("expected same logger provider returned by initLogger")
		}

		if !initCalled {
			t.Fatal("expected initLogger to be called")
		}

		if gotCtx != ctx {
			t.Fatal("expected same context passed to initLogger")
		}

		expectedPath := filepath.Join(".", "logs")

		if gotDir != expectedPath {
			t.Fatalf("expected path %q, got %q", expectedPath, gotDir)
		}
		if got := viper.GetDuration("server.gin.readHeaderTimeout"); got != 5*time.Second {
			t.Fatalf("readHeaderTimeout = %s, want 5s", got)
		}
	})
}

func TestShutdown(t *testing.T) {
	t.Run("shutdown otel error", func(t *testing.T) {
		quit = make(chan os.Signal, 1)

		srv := &http.Server{}
		called := false

		go func() {
			time.Sleep(10 * time.Millisecond)
			quit <- syscall.SIGTERM
		}()

		shutdown(srv, func(context.Context) error {
			called = true
			return errors.New("otel shutdown error")
		})

		if !called {
			t.Fatal("expected shutdownOtel to be called")
		}
	})

	t.Run("success", func(t *testing.T) {
		quit = make(chan os.Signal, 1)

		srv := &http.Server{}
		called := false

		go func() {
			time.Sleep(10 * time.Millisecond)
			quit <- syscall.SIGTERM
		}()

		shutdown(srv, func(context.Context) error {
			called = true
			return nil
		})

		if !called {
			t.Fatal("expected shutdownOtel to be called")
		}
	})
}

func TestMain(t *testing.T) {
	originalReadInConfig := readInConfig
	originalInitLogger := initLogger
	defer func() {
		readInConfig = originalReadInConfig
		initLogger = originalInitLogger
		viper.Reset()
	}()

	readInConfig = func() error { return nil }

	var gotDir string
	initLogger = func(ctx context.Context, dir string) (*sdklog.LoggerProvider, error) {
		gotDir = dir
		return sdklog.NewLoggerProvider(), nil
	}

	viper.Set("server.groups", []string{"/"})
	viper.Set("server.gin.port", ":0")

	quit = make(chan os.Signal, 1)

	done := make(chan struct{})
	go func() {
		defer close(done)
		main()
	}()

	go func() {
		time.Sleep(50 * time.Millisecond)
		quit <- syscall.SIGTERM
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("main did not finish in time")
	}

	expectedDir := filepath.Join(".", "logs")
	if gotDir != expectedDir {
		t.Fatalf("initLogger dir = %q, want %q", gotDir, expectedDir)
	}
}

func Test_endpointExample(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := endpointExample()
	if handler == nil {
		t.Fatal("endpointExample() returned nil")
	}

	engine := gin.New()
	engine.GET("/example", handler)

	req, err := http.NewRequest(http.MethodGet, "/example", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not valid json: %v", err)
	}

	if body["message"] != "Hello, World!" {
		t.Fatalf("message = %#v, want %#v", body["message"], "Hello, World!")
	}
}
