// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PointerByte/forge-go/logger/formatter"
	"github.com/PointerByte/forge-go/logger/sanitizer"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/spf13/viper"
)

type errWriter struct {
	err error
}

func (w *errWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

type failOnNthWrite struct {
	n     int
	count int
	err   error
	buf   bytes.Buffer
}

func (w *failOnNthWrite) Write(p []byte) (int, error) {
	w.count++
	if w.count == w.n {
		return 0, w.err
	}
	return w.buf.Write(p)
}

type yieldingBuffer struct {
	mux sync.Mutex
	buf bytes.Buffer
}

type errorHandler struct {
	err error
}

func (h errorHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h errorHandler) Handle(context.Context, slog.Record) error {
	return h.err
}

func (h errorHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

func (h errorHandler) WithGroup(string) slog.Handler {
	return h
}

func (w *yieldingBuffer) Write(p []byte) (int, error) {
	w.mux.Lock()
	n, err := w.buf.Write(p)
	w.mux.Unlock()
	time.Sleep(time.Microsecond)
	return n, err
}

func (w *yieldingBuffer) String() string {
	w.mux.Lock()
	defer w.mux.Unlock()
	return w.buf.String()
}

func resetBuilderViper() {
	viper.Reset()
	viperdata.ResetViperDataSingleton()
}

func newTestCtx() *Context {
	ctx := New(context.Background())

	ctx.Set(traceIDKey, "trace-123")
	ctx.Set(detailsKey, formatter.Details{
		System:   "loan-service",
		Client:   "mobile-app",
		Method:   "POST",
		Protocol: "HTTP",
		Path:     "/loan/simulate",
	})
	services := make([]formatter.Process, 0)
	ctx.Set(servicesKey, &services)

	return ctx
}

func TestNewHandler(t *testing.T) {
	h1 := newHandler(slog.LevelInfo, &bytes.Buffer{})
	if h1 == nil {
		t.Fatal("newHandler returned nil")
	}
	if h1.level != slog.LevelInfo {
		t.Fatalf("level = %v, want %v", h1.level, slog.LevelInfo)
	}
	if h1.w == nil {
		t.Fatal("writer is nil")
	}
	if h1.mux == nil {
		t.Fatal("mutex is nil")
	}
	if len(h1.handlers) != 0 {
		t.Fatalf("handlers len = %d, want 0", len(h1.handlers))
	}

	dummy := slog.NewTextHandler(&bytes.Buffer{}, nil)
	h2 := newHandler(slog.LevelDebug, &bytes.Buffer{}, dummy)
	if len(h2.handlers) != 1 {
		t.Fatalf("handlers len = %d, want 1", len(h2.handlers))
	}
}

func TestJSONHandler_Enabled(t *testing.T) {
	h := newHandler(slog.LevelInfo, &bytes.Buffer{})

	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("Enabled(debug) = true, want false")
	}
	if !h.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("Enabled(info) = false, want true")
	}
	if !h.Enabled(context.Background(), slog.LevelWarn) {
		t.Fatal("Enabled(warn) = false, want true")
	}
}

func TestJSONHandler_Handle_JSON(t *testing.T) {
	resetBuilderViper()
	t.Cleanup(resetBuilderViper)

	viper.Set(string(viperdata.LoggerFormatDateAtribute), "2006-01-02T15:04:05.000")
	viper.Set(string(viperdata.LoggerFormatterAtribute), "json")
	viper.Set(string(viperdata.AppAtribute), "test-app")

	buf := &bytes.Buffer{}
	h := newHandler(slog.LevelDebug, buf)
	ctx := newTestCtx()

	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "hello-json", 0)

	if err := h.Handle(ctx, rec); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("output must end with newline, got %q", out)
	}

	line := strings.TrimSpace(out)

	var decoded map[string]any
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("invalid json output: %v\noutput=%s", err, line)
	}

	if decoded["message"] != "hello-json" {
		t.Fatalf("message = %#v, want %#v", decoded["message"], "hello-json")
	}
	if decoded["traceID"] != "trace-123" {
		t.Fatalf("traceID = %#v, want %#v", decoded["traceID"], "trace-123")
	}

	detailsAny, ok := decoded["details"]
	if !ok {
		t.Fatal("details field not found")
	}

	details, ok := detailsAny.(map[string]any)
	if !ok {
		t.Fatalf("details has unexpected type %T", detailsAny)
	}

	if details["system"] != "loan-service" {
		t.Fatalf("details.system = %#v, want %#v", details["system"], "loan-service")
	}
	if details["client"] != "mobile-app" {
		t.Fatalf("details.client = %#v, want %#v", details["client"], "mobile-app")
	}
	if details["method"] != "POST" {
		t.Fatalf("details.method = %#v, want %#v", details["method"], "POST")
	}
	if details["protocol"] != "HTTP" {
		t.Fatalf("details.protocol = %#v, want %#v", details["protocol"], "HTTP")
	}
	if details["path"] != "/loan/simulate" {
		t.Fatalf("details.path = %#v, want %#v", details["path"], "/loan/simulate")
	}

	servicesAny, ok := decoded["process"]
	if !ok {
		t.Fatal("process field not found")
	}
	services, ok := servicesAny.([]any)
	if !ok {
		t.Fatalf("services has unexpected type %T", servicesAny)
	}
	if len(services) != 0 {
		t.Fatalf("services len = %d, want 0", len(services))
	}
}

func TestJSONHandler_HandleNormalizesMissingOrInvalidProcessCollection(t *testing.T) {
	resetBuilderViper()
	t.Cleanup(resetBuilderViper)

	viper.Set(string(viperdata.LoggerFormatDateAtribute), "2006-01-02T15:04:05.000")
	viper.Set(string(viperdata.LoggerFormatterAtribute), "json")
	viper.Set(string(viperdata.AppAtribute), "test-app")

	buf := &bytes.Buffer{}
	h := newHandler(slog.LevelDebug, buf)
	ctx := New(context.Background())
	ctx.fields.Delete(servicesKey)

	if err := h.Handle(ctx, slog.NewRecord(time.Now(), slog.LevelInfo, "no traces", 0)); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	process, ok := decoded["process"].([]any)
	if !ok {
		t.Fatalf("process = %T, want []any", decoded["process"])
	}
	if len(process) != 0 {
		t.Fatalf("process = %#v, want []", process)
	}
	if _, exists := decoded["pro"+"ccess"]; exists {
		t.Fatalf("unexpected legacy process field in %#v", decoded)
	}
}

func TestJSONHandler_HandleSerializesCompletedTracesInOrder(t *testing.T) {
	resetBuilderViper()
	t.Cleanup(resetBuilderViper)

	viper.Set(string(viperdata.LoggerFormatDateAtribute), "2006-01-02T15:04:05.000")
	viper.Set(string(viperdata.LoggerFormatterAtribute), "json")
	viper.Set(string(viperdata.AppAtribute), "test-service")
	viper.Set(string(viperdata.LoggerModeTestAtribute), false)

	buf := &bytes.Buffer{}
	h := newHandler(slog.LevelDebug, buf)
	ctx := New(context.Background())

	for _, name := range []string{"query database", "write audit record"} {
		process := &formatter.Process{System: "test-service", Process: name}
		ctx.TraceInit(process)
		ctx.TraceEnd(process)
	}

	if err := h.Handle(ctx, slog.NewRecord(time.Now(), slog.LevelInfo, "request completed", 0)); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	processes, ok := decoded["process"].([]any)
	if !ok || len(processes) != 2 {
		t.Fatalf("process = %#v, want two completed traces", decoded["process"])
	}
	for index, want := range []string{"query database", "write audit record"} {
		process, ok := processes[index].(map[string]any)
		if !ok {
			t.Fatalf("process[%d] = %T, want object", index, processes[index])
		}
		if process["system"] != "test-service" || process["process"] != want || process["status"] != "SUCCESS" {
			t.Fatalf("process[%d] = %#v, want completed %q trace", index, process, want)
		}
	}
	if remaining := ctx.Processes(); len(remaining) != 0 {
		t.Fatalf("process collection was not cleared after final serialization: %#v", remaining)
	}
}

func TestJSONHandler_Handle_TextFallback(t *testing.T) {
	resetBuilderViper()
	t.Cleanup(resetBuilderViper)

	viper.Set(string(viperdata.LoggerFormatDateAtribute), "2006-01-02T15:04:05.000")
	viper.Set(string(viperdata.LoggerFormatterAtribute), "text")
	viper.Set(string(viperdata.AppAtribute), "test-app")

	buf := &bytes.Buffer{}
	h := newHandler(slog.LevelDebug, buf)
	ctx := newTestCtx()

	rec := slog.NewRecord(time.Now(), slog.LevelWarn, "hello-text", 0)

	if err := h.Handle(ctx, rec); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("output must end with newline, got %q", out)
	}
	line := strings.TrimSpace(out)

	if !strings.Contains(line, "hello-text") {
		t.Fatalf("output missing message: %s", line)
	}
	if !strings.Contains(line, "trace-123") {
		t.Fatalf("output missing trace id: %s", line)
	}
}

func TestJSONHandler_Handle_SanitizesConfiguredKeysBeforeFormatting(t *testing.T) {
	tests := []struct {
		name      string
		formatter string
	}{
		{name: "json", formatter: "json"},
		{name: "text", formatter: "text"},
		{name: "custom template", formatter: `{{json .}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetBuilderViper()
			t.Cleanup(resetBuilderViper)

			viper.Set(string(viperdata.LoggerFormatDateAtribute), "2006-01-02T15:04:05.000")
			viper.Set(string(viperdata.LoggerFormatterAtribute), tt.formatter)
			viper.Set(string(viperdata.LoggerSensibleKeysAtribute), []string{"password", "email"})
			viper.Set(string(viperdata.AppAtribute), "test-app")

			buf := &bytes.Buffer{}
			h := newHandler(slog.LevelDebug, buf)
			ctx := newTestCtx()
			ctx.Set(detailsKey, formatter.Details{
				System:          "loan-service",
				Request:         map[string]any{"password": "secret", "token": "visible"},
				Response:        `{"email":"person@example.com`,
				ResponseCapture: &formatter.BodyCaptureMetadata{Truncated: true, CapturedBytes: 29, LimitBytes: 29},
			})
			rec := slog.NewRecord(time.Now(), slog.LevelInfo, "password=message-secret", 0)

			if err := h.Handle(ctx, rec); err != nil {
				t.Fatalf("Handle() error = %v", err)
			}

			out := buf.String()
			for _, secret := range []string{"secret", "message-secret", "person@example.com"} {
				if strings.Contains(out, secret) {
					t.Fatalf("output still contains %q: %s", secret, out)
				}
			}
			if !strings.Contains(out, sanitizer.RedactedValue) {
				t.Fatalf("output missing redaction marker: %s", out)
			}
			if !strings.Contains(out, "visible") {
				t.Fatalf("disabled sensitive key was redacted unexpectedly: %s", out)
			}
		})
	}
}

func TestJSONHandler_HandleReturnsFormatterError(t *testing.T) {
	resetBuilderViper()
	t.Cleanup(resetBuilderViper)

	viper.Set(string(viperdata.LoggerFormatDateAtribute), "2006-01-02T15:04:05.000")
	viper.Set(string(viperdata.LoggerFormatterAtribute), "{{if}")
	viper.Set(string(viperdata.AppAtribute), "test-app")

	h := newHandler(slog.LevelDebug, &bytes.Buffer{})
	ctx := newTestCtx()
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "boom", 0)

	if err := h.Handle(ctx, rec); err == nil || !strings.Contains(err.Error(), "format entry") {
		t.Fatalf("Handle() error = %v, want formatter error", err)
	}
}

func TestJSONHandler_HandleReturnsAttributeEncodingError(t *testing.T) {
	resetBuilderViper()
	t.Cleanup(resetBuilderViper)

	viper.Set(string(viperdata.LoggerFormatterAtribute), "json")
	viper.Set(string(viperdata.AppAtribute), "test-app")

	handler := newHandler(slog.LevelDebug, io.Discard)
	record := slog.NewRecord(time.Now(), slog.LevelInfo, "bad attribute", 0)
	record.AddAttrs(slog.Any("unsupported", make(chan int)))

	if err := handler.Handle(newTestCtx(), record); err == nil || !strings.Contains(err.Error(), "format entry") {
		t.Fatalf("Handle() error = %v, want attribute encoding error", err)
	}
}

func TestJSONHandler_HandleReturnsWriteErrorJSON(t *testing.T) {
	resetBuilderViper()
	t.Cleanup(resetBuilderViper)

	viper.Set(string(viperdata.LoggerFormatDateAtribute), "2006-01-02T15:04:05.000")
	viper.Set(string(viperdata.LoggerFormatterAtribute), "json")
	viper.Set(string(viperdata.AppAtribute), "test-app")

	wantErr := errors.New("write failed")
	h := newHandler(slog.LevelDebug, &errWriter{err: wantErr})
	ctx := newTestCtx()
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "write-json", 0)

	if err := h.Handle(ctx, rec); !errors.Is(err, wantErr) {
		t.Fatalf("Handle() error = %v, want %v", err, wantErr)
	}
}

func TestJSONHandler_HandleReturnsWriteErrorText(t *testing.T) {
	resetBuilderViper()
	t.Cleanup(resetBuilderViper)

	viper.Set(string(viperdata.LoggerFormatDateAtribute), "2006-01-02T15:04:05.000")
	viper.Set(string(viperdata.LoggerFormatterAtribute), "text")
	viper.Set(string(viperdata.AppAtribute), "test-app")

	wantErr := errors.New("write failed")
	h := newHandler(slog.LevelDebug, &errWriter{err: wantErr})
	ctx := newTestCtx()
	rec := slog.NewRecord(time.Now(), slog.LevelWarn, "write-text", 0)

	if err := h.Handle(ctx, rec); !errors.Is(err, wantErr) {
		t.Fatalf("Handle() error = %v, want %v", err, wantErr)
	}
}

func TestJSONHandler_writeData(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		buf := &bytes.Buffer{}
		h := &jsonHandler{w: buf}

		if err := h.writeData([]byte(`{"ok":true}`)); err != nil {
			t.Fatalf("writeData() error = %v", err)
		}
		if got := buf.String(); got != "{\"ok\":true}\n" {
			t.Fatalf("writeData() = %q, want %q", got, "{\"ok\":true}\n")
		}
	})

	t.Run("first write error", func(t *testing.T) {
		h := &jsonHandler{w: &errWriter{err: errors.New("first write")}}

		if err := h.writeData([]byte(`{"ok":true}`)); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("nil writer", func(t *testing.T) {
		h := &jsonHandler{}
		if err := h.writeData([]byte(`{"ok":true}`)); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("single write includes newline", func(t *testing.T) {
		w := &failOnNthWrite{n: 2, err: errors.New("newline write")}
		h := &jsonHandler{w: w}

		if err := h.writeData([]byte(`{"ok":true}`)); err != nil {
			t.Fatalf("writeData() error = %v", err)
		}
		if got := w.buf.String(); got != "{\"ok\":true}\n" {
			t.Fatalf("writeData() = %q, want %q", got, "{\"ok\":true}\n")
		}
	})
}

func TestJSONHandler_writeDataConcurrentWritesCompleteLines(t *testing.T) {
	w := &yieldingBuffer{}
	h := newHandler(slog.LevelDebug, w)

	const writes = 200
	var wg sync.WaitGroup
	wg.Add(writes)
	for i := 0; i < writes; i++ {
		i := i
		go func() {
			defer wg.Done()
			if err := h.writeData(fmt.Appendf(nil, `{"n":%d}`, i)); err != nil {
				t.Errorf("writeData() error = %v", err)
			}
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSuffix(w.String(), "\n"), "\n")
	if len(lines) != writes {
		t.Fatalf("line count = %d, want %d", len(lines), writes)
	}
	for _, line := range lines {
		if line == "" {
			t.Fatal("output contains a blank line")
		}
		if strings.Contains(line, "}{") {
			t.Fatalf("output contains joined log entries: %q", line)
		}
		if !json.Valid([]byte(line)) {
			t.Fatalf("output contains invalid json line: %q", line)
		}
	}
}

func TestJSONHandlerPreservesGroupsAndSanitizesEverySink(t *testing.T) {
	resetBuilderViper()
	t.Cleanup(resetBuilderViper)

	viper.Set(string(viperdata.LoggerFormatDateAtribute), time.RFC3339Nano)
	viper.Set(string(viperdata.LoggerFormatterAtribute), "json")
	viper.Set(string(viperdata.LoggerSensibleKeysAtribute), []string{"password", "email"})
	viper.Set(string(viperdata.AppAtribute), "test-app")

	var local bytes.Buffer
	var secondary bytes.Buffer
	root := newHandler(slog.LevelDebug, &local, slog.NewJSONHandler(&secondary, nil))
	derived := root.
		WithAttrs([]slog.Attr{
			slog.String("component", "api"),
			slog.String("password", "bound-secret"),
		}).
		WithGroup("request").
		WithAttrs([]slog.Attr{slog.Int("attempt", 2)})

	record := slog.NewRecord(time.Unix(1, 0), slog.LevelInfo, "password=message-secret", 0)
	record.AddAttrs(
		slog.String("email", "record@example.com"),
		slog.Group("nested",
			slog.String("password", "nested-secret"),
			slog.String("public", "visible"),
		),
		slog.Group(""),
	)

	if err := derived.Handle(newTestCtx(), record); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if len(root.operations) != 0 {
		t.Fatalf("root operations = %d, want 0", len(root.operations))
	}

	var localEntry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(local.Bytes()), &localEntry); err != nil {
		t.Fatalf("local output is invalid JSON: %v", err)
	}
	attributes, ok := localEntry["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("local attributes = %T, want object", localEntry["attributes"])
	}
	if attributes["component"] != "api" || attributes["password"] != sanitizer.RedactedValue {
		t.Fatalf("root attributes = %#v", attributes)
	}
	request, ok := attributes["request"].(map[string]any)
	if !ok {
		t.Fatalf("request attributes = %T, want object", attributes["request"])
	}
	nested, ok := request["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested attributes = %T, want object", request["nested"])
	}
	if request["attempt"] != float64(2) ||
		request["email"] != sanitizer.RedactedValue ||
		nested["password"] != sanitizer.RedactedValue ||
		nested["public"] != "visible" {
		t.Fatalf("request attributes = %#v", request)
	}

	for name, output := range map[string]string{
		"local":     local.String(),
		"secondary": secondary.String(),
	} {
		for _, secret := range []string{"bound-secret", "message-secret", "record@example.com", "nested-secret"} {
			if strings.Contains(output, secret) {
				t.Fatalf("%s output leaked %q: %s", name, secret, output)
			}
		}
		if !strings.Contains(output, sanitizer.RedactedValue) || !strings.Contains(output, "visible") {
			t.Fatalf("%s output missing expected sanitized attributes: %s", name, output)
		}
	}
}

func TestJSONHandlerReturnsSecondaryHandlerError(t *testing.T) {
	resetBuilderViper()
	t.Cleanup(resetBuilderViper)
	viper.Set(string(viperdata.LoggerFormatterAtribute), "json")
	viper.Set(string(viperdata.AppAtribute), "test-app")

	wantErr := errors.New("secondary failed")
	handler := newHandler(slog.LevelDebug, io.Discard, errorHandler{err: wantErr})
	if err := handler.Handle(newTestCtx(), slog.NewRecord(time.Now(), slog.LevelInfo, "message", 0)); !errors.Is(err, wantErr) {
		t.Fatalf("Handle() error = %v, want %v", err, wantErr)
	}
}

func TestJSONHandlerEmptyAttrsAndGroupsAreNoOps(t *testing.T) {
	handler := newHandler(slog.LevelInfo, io.Discard)
	if got := handler.WithAttrs(nil); got != handler {
		t.Fatal("WithAttrs(nil) must return the receiver")
	}
	if got := handler.WithGroup(""); got != handler {
		t.Fatal("WithGroup(\"\") must return the receiver")
	}

	attributes := handler.
		WithGroup("request").
		WithAttrs([]slog.Attr{slog.Group("empty")}).(*jsonHandler).
		recordAttributes(slog.NewRecord(time.Now(), slog.LevelInfo, "message", 0))
	if attributes != nil {
		t.Fatalf("empty group attributes = %#v, want nil", attributes)
	}
}

func BenchmarkJSONHandlerWithAttributes(b *testing.B) {
	resetBuilderViper()
	b.Cleanup(resetBuilderViper)
	viper.Set(string(viperdata.LoggerFormatterAtribute), "json")
	viper.Set(string(viperdata.AppAtribute), "benchmark")
	viper.Set(string(viperdata.LoggerSensibleKeysAtribute), []string{"password"})

	handler := newHandler(slog.LevelInfo, io.Discard).
		WithAttrs([]slog.Attr{slog.String("component", "api")}).
		WithGroup("request")
	ctx := newTestCtx()
	record := slog.NewRecord(time.Unix(1, 0), slog.LevelInfo, "completed", 0)
	record.AddAttrs(slog.Int("attempt", 1), slog.String("password", "secret"))

	b.ReportAllocs()

	for b.Loop() {
		if err := handler.Handle(ctx, record); err != nil {
			b.Fatal(err)
		}
	}
}
