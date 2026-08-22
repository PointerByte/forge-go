// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package trace

import (
	"context"
	"errors"
	"testing"

	"github.com/PointerByte/forge-go/logger/builder"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/spf13/viper"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// newRecordingProvider installs an in-memory span exporter as the global
// OpenTelemetry provider so the spans emitted by builder can be inspected, and
// disables logger test mode so TraceInit/TraceEnd actually record spans.
func newRecordingProvider(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))

	prevTP := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)

	viper.Set(string(viperdata.LoggerModeTestAtribute), false)
	viperdata.ResetViperDataSingleton()

	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		viper.Reset()
		viperdata.ResetViperDataSingleton()
	})

	return exporter
}

func TestStart_NoBuilderContextIsNoop(t *testing.T) {
	// context.Background() does not carry a *builder.Context, so Start must
	// return a no-op closure that ignores both nil and non-nil errors.
	end := Start(context.Background(), "aws-kms/EncryptAES")
	if end == nil {
		t.Fatal("Start() returned nil closure")
	}

	// Neither call must panic nor have observable effects.
	end(nil)
	end(errors.New("boom"))
}

func TestStart_NilContextIsNoop(t *testing.T) {
	// A nil context must be treated like a missing builder context.
	var nilCtx context.Context
	end := Start(nilCtx, "local/HMAC")
	end(nil)
}

func TestStart_SuccessRecordsSpan(t *testing.T) {
	exporter := newRecordingProvider(t)

	ctx := builder.New(context.Background())

	end := Start(ctx, "aws-kms/EncryptAES")
	end(nil)

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(spans))
	}

	span := spans[0]
	if span.Name != "aws-kms/EncryptAES" {
		t.Fatalf("span name = %q, want %q", span.Name, "aws-kms/EncryptAES")
	}

	attrs := attrMap(span.Attributes)
	if got := attrs["system"]; got != system {
		t.Fatalf("system attribute = %q, want %q", got, system)
	}
	if got := attrs["status"]; got != "SUCCESS" {
		t.Fatalf("status attribute = %q, want SUCCESS", got)
	}
}

func TestStart_ErrorRecordsErrorStatus(t *testing.T) {
	exporter := newRecordingProvider(t)

	ctx := builder.New(context.Background())

	end := Start(ctx, "gcp-kms/SignRSA")
	end(errors.New("backend failure"))

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(spans))
	}

	if got := attrMap(spans[0].Attributes)["status"]; got != "ERROR" {
		t.Fatalf("status attribute = %q, want ERROR", got)
	}
}

func attrMap(attrs []attribute.KeyValue) map[string]string {
	out := make(map[string]string, len(attrs))
	for _, a := range attrs {
		out[string(a.Key)] = a.Value.AsString()
	}
	return out
}
