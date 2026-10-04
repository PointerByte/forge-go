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
	"maps"
	"sync"
	"time"

	"log/slog"

	"github.com/PointerByte/forge-go/logger/formatter"
	"github.com/PointerByte/forge-go/logger/sanitizer"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

type handlerOperation struct {
	group string
	attrs []slog.Attr
}

func (o handlerOperation) isGroup() bool {
	return o.group != ""
}

type jsonHandler struct {
	level      slog.Level
	w          io.Writer
	mux        *sync.Mutex
	operations []handlerOperation
	// exporter receives every entry as an OpenTelemetry log record. It is nil
	// when log export is disabled, which skips the export path entirely.
	exporter otellog.Logger
}

func newHandler(level slog.Level, w io.Writer) *jsonHandler {
	return &jsonHandler{
		level: level,
		w:     w,
		mux:   &sync.Mutex{},
	}
}

func (h *jsonHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// Handle builds the structured entry once and delivers that same entry to the
// local writer and, when export is enabled, to OpenTelemetry.
func (h *jsonHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Time.IsZero() {
		record.Time = time.Now()
	}
	ctxLogger := New(ctx)
	entry, err := h.buildEntry(ctxLogger, record, sanitizer.FromViper())
	if err != nil {
		return err
	}

	localErr := h.writeEntry(entry)
	exported, exportErr := h.exportEntry(ctx, record, entry)

	// Clear the traces carried by an entry once it reached a sink, after every
	// sink has seen it, so no later entry repeats them.
	if localErr == nil || exported {
		ctxLogger.clearProcesses(len(entry.Process))
	}
	return errors.Join(localErr, exportErr)
}

// buildEntry assembles and sanitizes the entry shared by every sink. It must be
// called directly from Handle: customLogFormat resolves the caller by stack
// depth.
func (h *jsonHandler) buildEntry(ctxLogger *Context, record slog.Record, logSanitizer sanitizer.Sanitizer) (formatter.LogFormat, error) {
	data := make(map[string]any)
	maps.Copy(data, ctxLogger.customLogFormat())

	layout, _ := viperdata.GetViperData(string(viperdata.LoggerFormatDateAtribute)).(string)
	data[string(timestampAtribute)] = record.Time.Format(layout)
	data[string(loggerMessage)] = record.Message
	data[string(levelAtribute)] = record.Level.String()

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return formatter.LogFormat{}, fmt.Errorf("logger: encode structured entry: %w", err)
	}

	var logObj formatter.LogFormat
	if err = json.Unmarshal(jsonBytes, &logObj); err != nil {
		return formatter.LogFormat{}, fmt.Errorf("logger: decode structured entry: %w", err)
	}
	logObj.Attributes = h.recordAttributes(record)
	logObj.Latency = ctxLogger.GetLatency()
	return logSanitizer.LogFormat(logObj), nil
}

func (h *jsonHandler) writeEntry(entry formatter.LogFormat) error {
	formatterName, _ := viperdata.GetViperData(string(viperdata.LoggerFormatterAtribute)).(string)
	jsonBytes, err := formatter.New(formatterName).Format(entry)
	if err != nil {
		return fmt.Errorf("logger: format entry: %w", err)
	}
	if err = h.writeData(jsonBytes); err != nil {
		return fmt.Errorf("logger: write entry: %w", err)
	}
	return nil
}

// exportEntry emits entry as the structured body of one OpenTelemetry log
// record and reports whether the record was emitted.
func (h *jsonHandler) exportEntry(ctx context.Context, record slog.Record, entry formatter.LogFormat) (bool, error) {
	if h.exporter == nil {
		return false, nil
	}

	const sevOffset = slog.Level(otellog.SeverityDebug) - slog.LevelDebug
	severity := otellog.Severity(record.Level + sevOffset)
	ctx = exportContext(ctx, entry)
	if !h.exporter.Enabled(ctx, otellog.EnabledParameters{Severity: severity}) {
		return false, nil
	}

	body, err := entryBody(entry)
	if err != nil {
		return false, fmt.Errorf("logger: encode exported entry: %w", err)
	}

	var exported otellog.Record
	exported.SetTimestamp(record.Time)
	exported.SetSeverity(severity)
	exported.SetSeverityText(record.Level.String())
	exported.SetBody(body)
	exported.AddAttributes(sourceAttributes(entry)...)
	h.exporter.Emit(ctx, exported)
	return true, nil
}

// exportContext sets the span context the exported record is correlated with
// to the trace and span ids printed in entry. Those ids are stored once per
// request, while the span live in ctx is usually a descendant started by
// nested TraceInit calls. When entry carries no span id, its trace id is a
// fallback correlation id rather than a trace id, and nothing is exported.
func exportContext(ctx context.Context, entry formatter.LogFormat) context.Context {
	traceID, traceErr := trace.TraceIDFromHex(entry.TraceID)
	spanID, spanErr := trace.SpanIDFromHex(entry.SpanID)
	if traceErr != nil || spanErr != nil {
		return trace.ContextWithSpanContext(ctx, trace.SpanContext{})
	}

	config := trace.SpanContextConfig{TraceID: traceID, SpanID: spanID}
	if live := trace.SpanContextFromContext(ctx); live.TraceID() == traceID {
		config.TraceFlags = live.TraceFlags()
	}
	return trace.ContextWithSpanContext(ctx, trace.NewSpanContext(config))
}

// sourceAttributes reports the call site printed in entry. The slog record PC
// cannot be used because it is captured inside the logger itself.
func sourceAttributes(entry formatter.LogFormat) []attribute.KeyValue {
	if entry.Method == "" || entry.Line <= 0 {
		return nil
	}
	return []attribute.KeyValue{
		attribute.String(string(semconv.CodeFunctionNameKey), entry.Method),
		attribute.Int(string(semconv.CodeLineNumberKey), entry.Line),
	}
}

// entryBody converts entry into a structured log body. It goes through the
// JSON encoding of entry so the body has the same keys, omissions and nesting
// as the JSON line written locally. Integral numbers stay integers.
func entryBody(entry formatter.LogFormat) (attribute.Value, error) {
	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		return attribute.Value{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(jsonBytes))
	decoder.UseNumber()
	var decoded any
	if err = decoder.Decode(&decoded); err != nil {
		return attribute.Value{}, err
	}
	return bodyValue(decoded), nil
}

func bodyValue(value any) attribute.Value {
	switch cast := value.(type) {
	case map[string]any:
		kvs := make([]attribute.KeyValue, 0, len(cast))
		for key, child := range cast {
			kvs = append(kvs, attribute.KeyValue{Key: attribute.Key(key), Value: bodyValue(child)})
		}
		return attribute.MapValue(kvs...)
	case []any:
		values := make([]attribute.Value, 0, len(cast))
		for _, child := range cast {
			values = append(values, bodyValue(child))
		}
		return attribute.SliceValue(values...)
	case string:
		return attribute.StringValue(cast)
	case bool:
		return attribute.BoolValue(cast)
	case json.Number:
		if integer, err := cast.Int64(); err == nil {
			return attribute.Int64Value(integer)
		}
		float, _ := cast.Float64()
		return attribute.Float64Value(float)
	default:
		// JSON null.
		return attribute.Value{}
	}
}

func (h *jsonHandler) recordAttributes(record slog.Record) map[string]any {
	attributes := make(map[string]any)
	groups := make([]string, 0)
	for _, operation := range h.operations {
		if operation.isGroup() {
			groups = append(groups, operation.group)
			continue
		}
		addSlogAttrs(attributes, groups, operation.attrs)
	}
	record.Attrs(func(attr slog.Attr) bool {
		addSlogAttrs(attributes, groups, []slog.Attr{attr})
		return true
	})
	if len(attributes) == 0 {
		return nil
	}
	return attributes
}

func addSlogAttrs(root map[string]any, groups []string, attrs []slog.Attr) {
	if !hasSlogAttrs(attrs) {
		return
	}
	target := root
	for _, group := range groups {
		target = ensureAttributeGroup(target, group)
	}
	for _, attr := range attrs {
		addSlogAttr(target, attr)
	}
}

func hasSlogAttrs(attrs []slog.Attr) bool {
	for _, attr := range attrs {
		if attr.Equal(slog.Attr{}) {
			continue
		}
		value := attr.Value.Resolve()
		if value.Kind() != slog.KindGroup || hasSlogAttrs(value.Group()) {
			return true
		}
	}
	return false
}

func addSlogAttr(target map[string]any, attr slog.Attr) {
	if attr.Equal(slog.Attr{}) {
		return
	}
	value := attr.Value.Resolve()
	if value.Kind() == slog.KindGroup {
		children := value.Group()
		if attr.Key == "" {
			for _, child := range children {
				addSlogAttr(target, child)
			}
			return
		}
		group := ensureAttributeGroup(target, attr.Key)
		for _, child := range children {
			addSlogAttr(group, child)
		}
		if len(group) == 0 {
			delete(target, attr.Key)
		}
		return
	}
	target[attr.Key] = slogValue(value)
}

func ensureAttributeGroup(target map[string]any, name string) map[string]any {
	if existing, ok := target[name].(map[string]any); ok {
		return existing
	}
	group := make(map[string]any)
	target[name] = group
	return group
}

func slogValue(value slog.Value) any {
	if value.Kind() == slog.KindAny {
		if err, ok := value.Any().(error); ok {
			return fmt.Sprint(err)
		}
	}
	return value.Any()
}

func (h *jsonHandler) writeData(jsonBytes []byte) error {
	if h.w == nil {
		return errors.New("nil writer")
	}

	line := make([]byte, 0, len(jsonBytes)+1)
	line = append(line, jsonBytes...)
	line = append(line, '\n')

	if h.mux != nil {
		h.mux.Lock()
		defer h.mux.Unlock()
	}

	_, err := h.w.Write(line)
	return err
}

func (h *jsonHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	clone := *h
	clone.operations = append([]handlerOperation(nil), h.operations...)
	clone.operations = append(clone.operations, handlerOperation{
		attrs: append([]slog.Attr(nil), attrs...),
	})
	return &clone
}

func (h *jsonHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	clone := *h
	clone.operations = append([]handlerOperation(nil), h.operations...)
	clone.operations = append(clone.operations, handlerOperation{group: name})
	return &clone
}
