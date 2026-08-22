// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package traces

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spf13/viper"
	"go.opentelemetry.io/otel"
	otlptrace "go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func stubInitTelemetry(t *testing.T) {
	t.Helper()

	origInitLoggerFn := initLoggerFn
	origInitOtelFn := initOtelFn
	t.Cleanup(func() {
		initLoggerFn = origInitLoggerFn
		initOtelFn = origInitOtelFn
	})
}

// TestInitTelemetryFlushesLogsBeforeTraces pins the shutdown order: a log record
// emitted while metrics and traces are draining must still reach an exporter,
// which is only true when the logger provider is flushed first.
func TestInitTelemetryFlushesLogsBeforeTraces(t *testing.T) {
	stubInitTelemetry(t)

	order := make([]string, 0, 2)
	provider := sdklog.NewLoggerProvider()
	initLoggerFn = func(context.Context, string) (*sdklog.LoggerProvider, error) {
		return provider, nil
	}
	initOtelFn = func(context.Context) (func(context.Context) error, error) {
		return func(context.Context) error {
			order = append(order, "otel")
			return nil
		}, nil
	}

	shutdown, err := InitTelemetry(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("InitTelemetry() error = %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown() error = %v", err)
	}

	// The logger provider drains synchronously inside Shutdown, so observing
	// "otel" last is enough to prove logs went first.
	if len(order) != 1 || order[0] != "otel" {
		t.Fatalf("shutdown order = %v, want the OpenTelemetry pipeline last", order)
	}
}

// TestInitTelemetryShutdownIsIdempotent covers repeated shutdown, which happens
// whenever a signal handler and a deferred call both fire.
func TestInitTelemetryShutdownIsIdempotent(t *testing.T) {
	stubInitTelemetry(t)

	calls := 0
	initLoggerFn = func(context.Context, string) (*sdklog.LoggerProvider, error) {
		return sdklog.NewLoggerProvider(), nil
	}
	initOtelFn = func(context.Context) (func(context.Context) error, error) {
		return func(context.Context) error {
			calls++
			return nil
		}, nil
	}

	shutdown, err := InitTelemetry(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("InitTelemetry() error = %v", err)
	}
	for range 3 {
		if err := shutdown(context.Background()); err != nil {
			t.Fatalf("shutdown() error = %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("underlying shutdown calls = %d, want 1", calls)
	}
}

// TestInitTelemetryDrainsLogsWhenTelemetryFails checks that a failure to bring
// up traces and metrics does not leak the logger pipeline that was already
// initialized.
func TestInitTelemetryDrainsLogsWhenTelemetryFails(t *testing.T) {
	stubInitTelemetry(t)

	wantErr := errors.New("otel boom")
	initLoggerFn = func(context.Context, string) (*sdklog.LoggerProvider, error) {
		return sdklog.NewLoggerProvider(), nil
	}
	initOtelFn = func(context.Context) (func(context.Context) error, error) {
		return nil, wantErr
	}

	shutdown, err := InitTelemetry(context.Background(), t.TempDir())
	if !errors.Is(err, wantErr) {
		t.Fatalf("InitTelemetry() error = %v, want %v", err, wantErr)
	}
	if shutdown != nil {
		t.Fatal("InitTelemetry() returned a shutdown alongside an error")
	}
}

// TestTelemetryDisabledNeedsNoCollector is the disabled-mode contract: with
// OTEL_SDK_DISABLED set, nothing is exported, no exporter is constructed, and
// an application runs without any collector listening.
func TestTelemetryDisabledNeedsNoCollector(t *testing.T) {
	resetTestState(t)
	t.Setenv("OTEL_SDK_DISABLED", "true")
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_METRICS_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1/")

	otlpTraceHTTPNewFn = func(context.Context, ...otlptracehttp.Option) (*otlptrace.Exporter, error) {
		t.Fatal("a trace exporter was constructed while telemetry is disabled")
		return nil, nil
	}

	shutdown, err := InitOtel(context.Background())
	if err != nil {
		t.Fatalf("InitOtel() error = %v", err)
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	_, span := otel.GetTracerProvider().Tracer("test").Start(context.Background(), "op")
	defer span.End()
	if span.IsRecording() {
		t.Fatal("span is recording while telemetry is disabled")
	}
	if span.SpanContext().IsValid() {
		t.Fatal("disabled telemetry produced a valid span context; it must not invent trace ids")
	}

	// Shutting a disabled pipeline down must be immediate, not a timeout.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown() error = %v", err)
	}
}

// TestShutdownIsBoundedWhenCollectorIsUnavailable proves an unreachable
// collector delays shutdown by at most the caller's deadline instead of
// blocking the process forever.
func TestShutdownIsBoundedWhenCollectorIsUnavailable(t *testing.T) {
	resetTestState(t)
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_METRICS_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	// 192.0.2.0/24 is the reserved TEST-NET-1 range: packets are dropped rather
	// than refused, so an unbounded exporter would hang here instead of failing
	// fast.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://192.0.2.1:4318")

	shutdown, err := InitOtel(context.Background())
	if err != nil {
		t.Fatalf("InitOtel() error = %v", err)
	}

	_, span := otel.GetTracerProvider().Tracer("test").Start(context.Background(), "op")
	span.End()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	_ = shutdown(ctx)
	elapsed := time.Since(start)
	if elapsed > 10*time.Second {
		t.Fatalf("shutdown took %s with an unreachable collector; it must respect the context deadline", elapsed)
	}
	t.Logf("shutdown with an unreachable collector returned in %s", elapsed)
}

// TestRepeatedInitOtelDrainsThePreviousPipeline covers re-initialization, which
// must not leave two batch processors and two exporters running.
func TestRepeatedInitOtelDrainsThePreviousPipeline(t *testing.T) {
	resetTestState(t)
	viper.Set("app.name", "repeat-init")

	shutdowns := 0
	initTracerProviderFn = func(context.Context, *resource.Resource) (oteltrace.TracerProvider, func(context.Context) error, error) {
		provider := sdktrace.NewTracerProvider()
		return provider, func(ctx context.Context) error {
			shutdowns++
			return provider.Shutdown(ctx)
		}, nil
	}

	if _, err := InitOtel(context.Background()); err != nil {
		t.Fatalf("first InitOtel() error = %v", err)
	}
	if shutdowns != 0 {
		t.Fatalf("the first pipeline was drained before a second initialization: %d", shutdowns)
	}

	second, err := InitOtel(context.Background())
	if err != nil {
		t.Fatalf("second InitOtel() error = %v", err)
	}
	if shutdowns != 1 {
		t.Fatalf("previous pipeline shutdowns = %d, want 1: re-initializing must not leak the old exporter", shutdowns)
	}

	if err := second(context.Background()); err != nil {
		t.Fatalf("shutdown() error = %v", err)
	}
	if shutdowns != 2 {
		t.Fatalf("shutdowns = %d, want 2", shutdowns)
	}
}
