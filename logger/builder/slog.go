// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package builder

import (
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
	handlers   []slog.Handler
}

func newHandler(level slog.Level, w io.Writer, handlers ...slog.Handler) *jsonHandler {
	return &jsonHandler{
		level:    level,
		w:        w,
		mux:      &sync.Mutex{},
		handlers: append([]slog.Handler(nil), handlers...),
	}
}

func (h *jsonHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *jsonHandler) Handle(ctx context.Context, record slog.Record) error {
	logSanitizer := sanitizer.FromViper()
	localErr := h.writeRecord(ctx, record, logSanitizer)
	secondaryErr := h.forwardRecord(ctx, record, logSanitizer)
	return errors.Join(localErr, secondaryErr)
}

func (h *jsonHandler) writeRecord(ctx context.Context, record slog.Record, logSanitizer sanitizer.Sanitizer) error {
	data := make(map[string]any)
	ctxLogger := New(ctx)
	maps.Copy(data, ctxLogger.customLogFormat())

	recordTime := record.Time
	if recordTime.IsZero() {
		recordTime = time.Now()
	}
	layout, _ := viperdata.GetViperData(string(viperdata.LoggerFormatDateAtribute)).(string)
	data[string(timestampAtribute)] = recordTime.Format(layout)
	data[string(loggerMessage)] = record.Message
	data[string(levelAtribute)] = record.Level.String()

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("logger: encode structured entry: %w", err)
	}

	var logObj formatter.LogFormat
	if err = json.Unmarshal(jsonBytes, &logObj); err != nil {
		return fmt.Errorf("logger: decode structured entry: %w", err)
	}
	logObj.Attributes = h.recordAttributes(record)
	logObj.Latency = ctxLogger.GetLatency()
	logObj = logSanitizer.LogFormat(logObj)

	formatterName, _ := viperdata.GetViperData(string(viperdata.LoggerFormatterAtribute)).(string)
	jsonBytes, err = formatter.New(formatterName).Format(logObj)
	if err != nil {
		return fmt.Errorf("logger: format entry: %w", err)
	}
	if err = h.writeData(jsonBytes); err != nil {
		return fmt.Errorf("logger: write entry: %w", err)
	}

	// Clear only traces included in an entry that reached the local sink.
	ctxLogger.clearProcesses(len(logObj.Process))
	return nil
}

func (h *jsonHandler) forwardRecord(ctx context.Context, record slog.Record, logSanitizer sanitizer.Sanitizer) error {
	if len(h.handlers) == 0 {
		return nil
	}

	message := record.Message
	if logSanitizer.Enabled() {
		if sanitized, ok := logSanitizer.Value(message).(string); ok {
			message = sanitized
		}
	}
	forwarded := slog.NewRecord(record.Time, record.Level, message, record.PC)
	record.Attrs(func(attr slog.Attr) bool {
		forwarded.AddAttrs(sanitizeSlogAttr(attr, logSanitizer))
		return true
	})

	var handlerErrors []error
	for index, rootHandler := range h.handlers {
		if rootHandler == nil {
			continue
		}
		derived := rootHandler
		for _, operation := range h.operations {
			if operation.isGroup() {
				derived = derived.WithGroup(operation.group)
				continue
			}
			attrs := make([]slog.Attr, 0, len(operation.attrs))
			for _, attr := range operation.attrs {
				attrs = append(attrs, sanitizeSlogAttr(attr, logSanitizer))
			}
			derived = derived.WithAttrs(attrs)
		}
		if !derived.Enabled(ctx, record.Level) {
			continue
		}
		if err := derived.Handle(ctx, forwarded); err != nil {
			handlerErrors = append(handlerErrors, fmt.Errorf("logger: secondary handler %d: %w", index, err))
		}
	}
	return errors.Join(handlerErrors...)
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

func sanitizeSlogAttr(attr slog.Attr, logSanitizer sanitizer.Sanitizer) slog.Attr {
	if !logSanitizer.Enabled() || attr.Equal(slog.Attr{}) {
		return attr
	}

	value := attr.Value.Resolve()
	if value.Kind() == slog.KindGroup && attr.Key == "" {
		children := value.Group()
		sanitized := make([]slog.Attr, 0, len(children))
		for _, child := range children {
			sanitized = append(sanitized, sanitizeSlogAttr(child, logSanitizer))
		}
		return slog.Attr{Value: slog.GroupValue(sanitized...)}
	}

	wrapped := map[string]any{attr.Key: slogAttrValue(attr)}
	sanitized, ok := logSanitizer.Value(wrapped).(map[string]any)
	if !ok {
		return slog.String(attr.Key, sanitizer.RedactedValue)
	}
	return slog.Any(attr.Key, sanitized[attr.Key])
}

func slogAttrValue(attr slog.Attr) any {
	value := attr.Value.Resolve()
	if value.Kind() != slog.KindGroup {
		return slogValue(value)
	}
	group := make(map[string]any)
	for _, child := range value.Group() {
		addSlogAttr(group, child)
	}
	return group
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
