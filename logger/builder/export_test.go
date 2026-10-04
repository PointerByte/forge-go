// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PointerByte/forge-go/logger/formatter"
	"github.com/PointerByte/forge-go/logger/sanitizer"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/spf13/viper"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	lognoop "go.opentelemetry.io/otel/log/noop"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

// recordingExporter keeps every exported log record in memory.
type recordingExporter struct {
	mux     sync.Mutex
	records []sdklog.Record
}

func (e *recordingExporter) Export(_ context.Context, records []sdklog.Record) error {
	e.mux.Lock()
	defer e.mux.Unlock()
	for _, record := range records {
		e.records = append(e.records, record.Clone())
	}
	return nil
}

func (e *recordingExporter) Shutdown(context.Context) error   { return nil }
func (e *recordingExporter) ForceFlush(context.Context) error { return nil }

func (e *recordingExporter) Records() []sdklog.Record {
	e.mux.Lock()
	defer e.mux.Unlock()
	return append([]sdklog.Record(nil), e.records...)
}

func newRecordingProvider(t *testing.T) (*sdklog.LoggerProvider, *recordingExporter) {
	t.Helper()
	exporter := &recordingExporter{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(exporter)))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return provider, exporter
}

// newExportingHandler returns a handler writing to w and exporting every entry
// to an in-memory OpenTelemetry pipeline.
func newExportingHandler(t *testing.T, w io.Writer) (*jsonHandler, *recordingExporter) {
	t.Helper()
	provider, exporter := newRecordingProvider(t)
	handler := newHandler(slog.LevelDebug, w)
	handler.exporter = provider.Logger(instrumentationName)
	return handler, exporter
}

// installExportingHandler configures a JSON logger and installs an exporting
// handler as the slog default, which is what *Context logging methods use.
func installExportingHandler(t *testing.T) (*bytes.Buffer, *recordingExporter) {
	t.Helper()
	resetBuilderViper()
	t.Cleanup(resetBuilderViper)
	viper.Set(string(viperdata.AppAtribute), "export-test")
	viper.Set(string(viperdata.AppVersionAtribute), "1.0.0")
	viper.Set(string(viperdata.LoggerFormatterAtribute), "json")
	viper.Set(string(viperdata.LoggerModeTestAtribute), false)

	local := &bytes.Buffer{}
	handler, exporter := newExportingHandler(t, local)
	previous := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return local, exporter
}

// bodyInterface converts an exported body into plain Go values.
func bodyInterface(value attribute.Value) any {
	switch value.Type() {
	case attribute.MAP:
		out := make(map[string]any)
		for _, kv := range value.AsMap() {
			out[string(kv.Key)] = bodyInterface(kv.Value)
		}
		return out
	case attribute.SLICE:
		out := make([]any, 0)
		for _, child := range value.AsSlice() {
			out = append(out, bodyInterface(child))
		}
		return out
	case attribute.EMPTY:
		return nil
	default:
		return value.AsInterface()
	}
}

// localEntries decodes every JSON line written locally into the same plain Go
// values bodyInterface produces.
func localEntries(t *testing.T, local *bytes.Buffer) []map[string]any {
	t.Helper()
	var entries []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(local.String()), "\n") {
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.UseNumber()
		var decoded any
		if err := decoder.Decode(&decoded); err != nil {
			t.Fatalf("local line is not JSON: %v (%s)", err, line)
		}
		entries = append(entries, plainJSON(decoded).(map[string]any))
	}
	return entries
}

func plainJSON(value any) any {
	switch cast := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(cast))
		for key, child := range cast {
			out[key] = plainJSON(child)
		}
		return out
	case []any:
		out := make([]any, 0, len(cast))
		for _, child := range cast {
			out = append(out, plainJSON(child))
		}
		return out
	case json.Number:
		if integer, err := cast.Int64(); err == nil {
			return integer
		}
		float, _ := cast.Float64()
		return float
	default:
		return cast
	}
}

func exportedAttributes(record sdklog.Record) map[string]attribute.Value {
	attributes := make(map[string]attribute.Value)
	record.WalkAttributes(func(kv attribute.KeyValue) bool {
		attributes[string(kv.Key)] = kv.Value
		return true
	})
	return attributes
}

func requireOneEach(t *testing.T, local *bytes.Buffer, exporter *recordingExporter) (map[string]any, sdklog.Record) {
	t.Helper()
	entries := localEntries(t, local)
	records := exporter.Records()
	if len(entries) != 1 || len(records) != 1 {
		t.Fatalf("local entries = %d, exported records = %d, want 1 each", len(entries), len(records))
	}
	return entries[0], records[0]
}

// T1 and T2.
func TestExportedBodyIsTheLocalEntry(t *testing.T) {
	local, exporter := installExportingHandler(t)

	ctx := newTestCtx()
	ctx.Details.Headers = map[string][]string{"Accept": {"application/json"}}
	ctx.Set(detailsKey, ctx.Details)
	process := &formatter.Process{System: "billing", Process: "charge card", Protocol: "HTTP", Method: "POST", Path: "/charges", Code: 201}
	ctx.TraceInit(process)
	ctx.TraceEnd(process)
	ctx.Info("payment accepted")

	entry, record := requireOneEach(t, local, exporter)
	body := record.Body()
	if body.Type() != attribute.MAP {
		t.Fatalf("exported body type = %s, want MAP", body.Type())
	}
	if got := bodyInterface(body); !reflect.DeepEqual(got, any(entry)) {
		t.Fatalf("exported body differs from the local entry\n got: %#v\nwant: %#v", got, entry)
	}
	for _, key := range []string{"details", "latency", "level", "line", "message", "method", "process", "timestamp", "traceID"} {
		if _, ok := entry[key]; !ok {
			t.Fatalf("entry is missing %q: %#v", key, entry)
		}
	}
	if record.Severity().String() != "INFO" || record.SeverityText() != "INFO" {
		t.Fatalf("severity = %s/%s, want INFO", record.Severity(), record.SeverityText())
	}
}

// T3.
func TestExportedBodyIsSanitizedLikeTheLocalEntry(t *testing.T) {
	local, exporter := installExportingHandler(t)
	viper.Set(string(viperdata.LoggerSensibleKeysAtribute), []string{"cardNumber"})
	viperdata.ResetViperDataSingleton()

	ctx := newTestCtx()
	ctx.Details.Request = map[string]any{"cardNumber": "4111111111111111", "amount": 10}
	ctx.Set(detailsKey, ctx.Details)
	ctx.Info("password=hunter2")

	entry, record := requireOneEach(t, local, exporter)
	exported, err := json.Marshal(bodyInterface(record.Body()))
	if err != nil {
		t.Fatalf("encode exported body: %v", err)
	}
	for name, output := range map[string]string{"local": local.String(), "exported": string(exported)} {
		for _, secret := range []string{"4111111111111111", "hunter2"} {
			if strings.Contains(output, secret) {
				t.Fatalf("%s output leaked %q: %s", name, secret, output)
			}
		}
		if !strings.Contains(output, sanitizer.RedactedValue) {
			t.Fatalf("%s output has no redaction marker: %s", name, output)
		}
	}
	if !reflect.DeepEqual(bodyInterface(record.Body()), any(entry)) {
		t.Fatalf("sanitized body differs from the sanitized local entry")
	}
}

// T4.
func TestExportedRecordUsesTheRequestSpanNotTheLiveOne(t *testing.T) {
	local, exporter := installExportingHandler(t)

	provider := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	tracer := provider.Tracer("test")

	requestCtx, request := tracer.Start(context.Background(), "request")
	defer request.End()
	ctx := New(requestCtx)
	ctx.tracer = tracer

	outer := &formatter.Process{System: "export-test", Process: "outer"}
	ctx.TraceInit(outer)
	inner := &formatter.Process{System: "export-test", Process: "inner"}
	ctx.TraceInit(inner)
	live := trace.SpanContextFromContext(ctx)
	if live.SpanID() == request.SpanContext().SpanID() {
		t.Fatal("test setup: the live span must be a descendant of the request span")
	}
	ctx.Info("nested work")
	ctx.TraceEnd(inner)
	ctx.TraceEnd(outer)

	entry, record := requireOneEach(t, local, exporter)
	wantTrace := request.SpanContext().TraceID().String()
	wantSpan := request.SpanContext().SpanID().String()
	if entry["traceID"] != wantTrace || entry["spanID"] != wantSpan {
		t.Fatalf("local ids = %v/%v, want the request span %s/%s", entry["traceID"], entry["spanID"], wantTrace, wantSpan)
	}
	if got := record.TraceID().String(); got != wantTrace {
		t.Fatalf("exported trace_id = %s, want %s", got, wantTrace)
	}
	if got := record.SpanID().String(); got != wantSpan {
		t.Fatalf("exported span_id = %s, want %s (live span was %s)", got, wantSpan, live.SpanID())
	}
	if !record.TraceFlags().IsSampled() {
		t.Fatal("exported trace flags lost the sampled bit of the request trace")
	}
}

func TestExportedRecordCarriesNoTraceForAFallbackCorrelationID(t *testing.T) {
	local, exporter := installExportingHandler(t)

	provider := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	liveCtx, live := provider.Tracer("test").Start(context.Background(), "unrelated")
	defer live.End()

	ctx := New(context.Background())
	ctx.Context = liveCtx
	ctx.Info("no request span")

	entry, record := requireOneEach(t, local, exporter)
	if _, ok := entry["spanID"]; ok {
		t.Fatalf("test setup: entry must have no spanID: %#v", entry)
	}
	if record.TraceID().IsValid() || record.SpanID().IsValid() {
		t.Fatalf("exported ids = %s/%s, want none for a fallback correlation id", record.TraceID(), record.SpanID())
	}
}

func logFromHere(ctx *Context) (string, int) {
	pc, _, line, _ := runtime.Caller(0)
	ctx.Info("located")
	return runtime.FuncForPC(pc).Name(), line + 1
}

func logfFromHere(ctx *Context) (string, int) {
	pc, _, line, _ := runtime.Caller(0)
	ctx.Infof("located %d", 1)
	return runtime.FuncForPC(pc).Name(), line + 1
}

// T5.
func TestExportedSourceIsTheCaller(t *testing.T) {
	for name, logAt := range map[string]func(*Context) (string, int){
		"Info":  logFromHere,
		"Infof": logfFromHere,
	} {
		t.Run(name, func(t *testing.T) {
			local, exporter := installExportingHandler(t)
			wantFunction, wantLine := logAt(newTestCtx())

			entry, record := requireOneEach(t, local, exporter)
			if entry["method"] != wantFunction || entry["line"] != int64(wantLine) {
				t.Fatalf("local method/line = %v:%v, want %s:%d", entry["method"], entry["line"], wantFunction, wantLine)
			}
			attributes := exportedAttributes(record)
			if got := attributes[string(semconv.CodeFunctionNameKey)].AsString(); got != wantFunction {
				t.Fatalf("exported %s = %q, want %q", semconv.CodeFunctionNameKey, got, wantFunction)
			}
			if got := attributes[string(semconv.CodeLineNumberKey)].AsInt64(); got != int64(wantLine) {
				t.Fatalf("exported %s = %d, want %d", semconv.CodeLineNumberKey, got, wantLine)
			}
			if path, ok := attributes[string(semconv.CodeFilePathKey)]; ok {
				t.Fatalf("exported %s = %q, want it omitted", semconv.CodeFilePathKey, path.AsString())
			}
		})
	}
}

// T6.
func TestExportedProcessesAreSentOnce(t *testing.T) {
	local, exporter := installExportingHandler(t)

	ctx := newTestCtx()
	for _, name := range []string{"query database", "write audit record"} {
		process := &formatter.Process{System: "export-test", Process: name, Code: 200}
		ctx.TraceInit(process)
		ctx.TraceEnd(process)
	}
	ctx.Info("first")
	ctx.Info("second")

	entries := localEntries(t, local)
	records := exporter.Records()
	if len(entries) != 2 || len(records) != 2 {
		t.Fatalf("local entries = %d, exported records = %d, want 2 each", len(entries), len(records))
	}
	first := bodyInterface(records[0].Body()).(map[string]any)
	processes, ok := first["process"].([]any)
	if !ok || len(processes) != 2 {
		t.Fatalf("first exported process = %#v, want both traces", first["process"])
	}
	if !reflect.DeepEqual(first["process"], entries[0]["process"]) {
		t.Fatalf("exported process = %#v, want the local one %#v", first["process"], entries[0]["process"])
	}
	second := bodyInterface(records[1].Body()).(map[string]any)
	if _, ok := second["process"]; ok {
		t.Fatalf("second exported record repeated processes: %#v", second["process"])
	}
	if _, ok := entries[1]["process"]; ok {
		t.Fatalf("second local entry repeated processes: %#v", entries[1]["process"])
	}
}

func TestExportedProcessesAreClearedWhenOnlyTheExportSucceeded(t *testing.T) {
	resetBuilderViper()
	t.Cleanup(resetBuilderViper)
	viper.Set(string(viperdata.AppAtribute), "export-test")
	viper.Set(string(viperdata.LoggerFormatterAtribute), "json")

	handler, exporter := newExportingHandler(t, &errWriter{err: io.ErrClosedPipe})
	ctx := newTestCtx()
	process := &formatter.Process{System: "export-test", Process: "charge"}
	ctx.TraceInit(process)
	ctx.TraceEnd(process)

	for range 2 {
		if err := handler.Handle(ctx, slog.NewRecord(time.Now(), slog.LevelInfo, "local sink down", 0)); err == nil {
			t.Fatal("Handle() error = nil, want the local write error")
		}
	}
	records := exporter.Records()
	if len(records) != 2 {
		t.Fatalf("exported records = %d, want 2", len(records))
	}
	if _, ok := bodyInterface(records[1].Body()).(map[string]any)["process"]; ok {
		t.Fatal("second exported record repeated the process already exported")
	}
}

// T7.
func TestDisabledExportEmitsNothing(t *testing.T) {
	resetBuilderViper()
	t.Cleanup(resetBuilderViper)
	viper.Set(string(viperdata.AppAtribute), "export-test")
	viper.Set(string(viperdata.LoggerFormatterAtribute), "json")

	provider, exporter := newRecordingProvider(t)
	originalFactory := _newCofigLoggerProvider
	t.Cleanup(func() { _newCofigLoggerProvider = originalFactory })
	_newCofigLoggerProvider = func(context.Context) (*sdklog.LoggerProvider, bool, error) {
		return provider, false, nil
	}
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	if _, err := InitLogger(context.Background(), filepath.Join(t.TempDir(), "logs")); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}
	handler := installedHandler(t)
	if handler.exporter != nil {
		t.Fatalf("exporter = %T, want none with export disabled", handler.exporter)
	}
	var local bytes.Buffer
	handler.w = &local

	newTestCtx().Info("not exported")

	if local.Len() == 0 {
		t.Fatal("local output is empty")
	}
	if records := exporter.Records(); len(records) != 0 {
		t.Fatalf("exported records = %d, want 0 with export disabled", len(records))
	}
}

func TestEnabledExportReachesTheProvider(t *testing.T) {
	resetBuilderViper()
	t.Cleanup(resetBuilderViper)
	viper.Set(string(viperdata.AppAtribute), "export-test")
	viper.Set(string(viperdata.LoggerFormatterAtribute), "json")

	provider, exporter := newRecordingProvider(t)
	originalFactory := _newCofigLoggerProvider
	originalSetProvider := setLoggerProvider
	t.Cleanup(func() {
		_newCofigLoggerProvider = originalFactory
		setLoggerProvider = originalSetProvider
	})
	_newCofigLoggerProvider = func(context.Context) (*sdklog.LoggerProvider, bool, error) {
		return provider, true, nil
	}
	setLoggerProvider = func(otellog.LoggerProvider) {}
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	if _, err := InitLogger(context.Background(), filepath.Join(t.TempDir(), "logs")); err != nil {
		t.Fatalf("InitLogger() error = %v", err)
	}
	installedHandler(t).w = io.Discard

	newTestCtx().Info("exported")

	if records := exporter.Records(); len(records) != 1 {
		t.Fatalf("exported records = %d, want 1", len(records))
	}
}

// R10.
func TestModeTestEmitsNothingToEitherSink(t *testing.T) {
	local, exporter := installExportingHandler(t)
	EnableModeTest()

	newTestCtx().Info("suppressed")

	if local.Len() != 0 {
		t.Fatalf("local output = %q, want none in test mode", local.String())
	}
	if records := exporter.Records(); len(records) != 0 {
		t.Fatalf("exported records = %d, want 0 in test mode", len(records))
	}
}

// R8.
func TestFormatDateAppliesToBothSinks(t *testing.T) {
	for name, layout := range map[string]string{
		"default":   "",
		"no-offset": "2006-01-02T15:04:05.000",
	} {
		t.Run(name, func(t *testing.T) {
			local, exporter := installExportingHandler(t)
			viper.Set(string(viperdata.LoggerFormatDateAtribute), layout)
			viperdata.ResetViperDataSingleton()
			isDefault := layout == ""
			if isDefault {
				layout = viperdata.DefaultFormatDate
			}

			newTestCtx().Info("dated")

			entry, record := requireOneEach(t, local, exporter)
			timestamp, _ := entry["timestamp"].(string)
			parsed, err := time.ParseInLocation(layout, timestamp, time.Local)
			if err != nil {
				t.Fatalf("timestamp %q does not use layout %q: %v", timestamp, layout, err)
			}
			if _, err := time.Parse(time.RFC3339Nano, timestamp); isDefault && err != nil {
				t.Fatalf("default timestamp %q is not RFC 3339: %v", timestamp, err)
			}
			if !parsed.Equal(record.Timestamp().Truncate(time.Millisecond)) {
				t.Fatalf("timestamp %s, want the exported record time %s", parsed, record.Timestamp())
			}
			if body := bodyInterface(record.Body()).(map[string]any); body["timestamp"] != timestamp {
				t.Fatalf("exported timestamp = %v, want %q", body["timestamp"], timestamp)
			}
		})
	}
}

func TestEntryBodyKeepsEveryJSONKind(t *testing.T) {
	body, err := entryBody(formatter.LogFormat{Attributes: map[string]any{
		"ratio":   0.5,
		"count":   int64(9007199254740993),
		"nothing": nil,
		"ok":      true,
		"list":    []any{"a", 1},
	}})
	if err != nil {
		t.Fatalf("entryBody() error = %v", err)
	}
	var attributes attribute.Value
	for _, kv := range body.AsMap() {
		if kv.Key == "attributes" {
			attributes = kv.Value
		}
	}
	want := map[string]attribute.Type{
		"ratio":   attribute.FLOAT64,
		"count":   attribute.INT64,
		"nothing": attribute.EMPTY,
		"ok":      attribute.BOOL,
		"list":    attribute.SLICE,
	}
	got := make(map[string]attribute.Type)
	for _, kv := range attributes.AsMap() {
		got[string(kv.Key)] = kv.Value.Type()
		if kv.Key == "count" && kv.Value.AsInt64() != 9007199254740993 {
			t.Fatalf("count = %d, want the exact integer", kv.Value.AsInt64())
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("attribute kinds = %v, want %v", got, want)
	}
}

func TestExportSkipsRecordsTheProviderDoesNotWant(t *testing.T) {
	resetBuilderViper()
	t.Cleanup(resetBuilderViper)
	viper.Set(string(viperdata.AppAtribute), "export-test")
	viper.Set(string(viperdata.LoggerFormatterAtribute), "json")

	handler := newHandler(slog.LevelDebug, &errWriter{err: io.ErrClosedPipe})
	handler.exporter = lognoop.NewLoggerProvider().Logger(instrumentationName)
	ctx := newTestCtx()
	process := &formatter.Process{System: "export-test", Process: "kept"}
	ctx.TraceInit(process)
	ctx.TraceEnd(process)

	if err := handler.Handle(ctx, slog.NewRecord(time.Time{}, slog.LevelInfo, "nowhere", 0)); err == nil {
		t.Fatal("Handle() error = nil, want the local write error")
	}
	if remaining := ctx.Processes(); len(remaining) != 1 {
		t.Fatalf("processes = %d, want 1 kept for an entry no sink received", len(remaining))
	}
}
