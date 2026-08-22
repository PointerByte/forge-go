// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/PointerByte/forge-go/logger/common"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/spf13/viper"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func resetCorrelationState(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		viper.Reset()
		viperdata.ResetViperDataSingleton()
	})
	viper.Reset()
	viperdata.ResetViperDataSingleton()
	viper.Set("app.name", "correlation-test")
	viper.Set("app.version", "1.0.0")
}

// TestContextAdoptsTheActiveTraceIdentifiers is the log/trace correlation
// contract: when a span is active, a structured log must be reachable from that
// span, which means carrying its trace id and span id rather than an
// independent identifier.
func TestContextAdoptsTheActiveTraceIdentifiers(t *testing.T) {
	resetCorrelationState(t)

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	ctx, span := provider.Tracer("test").Start(context.Background(), "operation")
	defer span.End()

	logCtx := New(ctx)

	if got, want := logCtx.TraceID(), span.SpanContext().TraceID().String(); got != want {
		t.Fatalf("TraceID() = %q, want the active trace %q", got, want)
	}
	if got, want := logCtx.SpanID(), span.SpanContext().SpanID().String(); got != want {
		t.Fatalf("SpanID() = %q, want the active span %q", got, want)
	}
}

// TestContextFallsBackToACorrelationIDWithoutASpan keeps the logger usable with
// telemetry disabled. The fallback is a correlation id, and it must be
// recognizable as one rather than pass for a trace id that no exporter has seen:
// with no span there is no span id at all.
func TestContextFallsBackToACorrelationIDWithoutASpan(t *testing.T) {
	resetCorrelationState(t)

	logCtx := New(context.Background())

	if logCtx.TraceID() == "" {
		t.Fatal("TraceID() is empty; the logger must still correlate its own records")
	}
	if got := logCtx.SpanID(); got != "" {
		t.Fatalf("SpanID() = %q, want empty: no span was active", got)
	}
}

// TestContextIgnoresAnInvalidSpanContext covers telemetry-disabled mode, where a
// no-op tracer hands back an all-zero span context. Adopting it would put a
// zeroed trace id in every log line.
func TestContextIgnoresAnInvalidSpanContext(t *testing.T) {
	resetCorrelationState(t)

	ctx := oteltrace.ContextWithSpanContext(context.Background(), oteltrace.SpanContext{})
	logCtx := New(ctx)

	if logCtx.TraceID() == "00000000000000000000000000000000" {
		t.Fatal("TraceID() adopted an all-zero span context")
	}
	if logCtx.TraceID() == "" {
		t.Fatal("TraceID() is empty")
	}
}

// TestStructuredLogCarriesTheTraceIdentifiers proves the identifiers reach the
// emitted JSON, which is what an operator correlates against a trace.
func TestStructuredLogCarriesTheTraceIdentifiers(t *testing.T) {
	resetCorrelationState(t)
	viper.Set("logger.formatter", "json")

	provider := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	ctx, span := provider.Tracer("test").Start(context.Background(), "operation")
	defer span.End()

	var buffer bytes.Buffer
	handler := newHandler(slog.LevelInfo, &buffer)
	logger := slog.New(handler)
	logger.InfoContext(New(ctx), "hello")

	var entry struct {
		TraceID string `json:"traceID"`
		SpanID  string `json:"spanID"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(buffer.Bytes()), &entry); err != nil {
		t.Fatalf("decode log entry: %v (%s)", err, buffer.String())
	}
	if entry.TraceID != span.SpanContext().TraceID().String() {
		t.Fatalf("log traceID = %q, want %q", entry.TraceID, span.SpanContext().TraceID())
	}
	if entry.SpanID != span.SpanContext().SpanID().String() {
		t.Fatalf("log spanID = %q, want %q", entry.SpanID, span.SpanContext().SpanID())
	}
}

// TestExplicitCorrelationIDStillWins keeps the legacy X-Trace-Id contract
// working for deployments that carry their own correlation id.
func TestExplicitCorrelationIDStillWins(t *testing.T) {
	resetCorrelationState(t)

	logCtx := New(context.Background())
	logCtx.SetTraceID("explicit-correlation-id")

	if got := logCtx.TraceID(); got != "explicit-correlation-id" {
		t.Fatalf("TraceID() = %q, want the explicitly set value", got)
	}
	if _, ok := logCtx.Get(common.TraceIDKey); !ok {
		t.Fatalf("the common correlation key was not populated")
	}
}
