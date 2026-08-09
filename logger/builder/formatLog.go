// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/PointerByte/forge-go/logger/common"
	"github.com/PointerByte/forge-go/logger/formatter"
	"github.com/PointerByte/forge-go/logger/utilities"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"go.opentelemetry.io/otel/attribute"
)

func (c *Context) getMethodLine(skip int) (funcName string, line int) {
	if c.Method != "" && c.Line != 0 {
		return c.Method, c.Line
	}
	return utilities.TraceCaller(skip + 1)
}

func (c *Context) customLogFormat() map[string]any {
	// ---------- Get Line ----------
	if c.tracerCallerSkip == 0 {
		c.SetTraceCallerSkip(8)
	}
	funcName, line := c.getMethodLine(c.GetTraceCallerSkip())

	// ---------- TraceID ----------
	traceID := c.TraceID()

	// ---------- Details ----------
	var details formatter.Details
	if v, ok := c.Get(detailsKey); ok {
		if storedDetails, ok := v.(formatter.Details); ok {
			details = storedDetails
		}
	}
	if details.System == "" {
		details.System = viperdata.GetViperData(string(viperdata.AppAtribute)).(string)
	}

	// ---------- Services ----------
	services := c.Processes()

	// ---------- Format Logger ----------
	entry := formatter.NewLogFormat()
	entry.TraceID = traceID
	entry.Details = details
	entry.Process = services
	entry.Method = funcName
	entry.Line = line
	jsonBytes, _ := json.Marshal(entry)
	var m map[string]any
	_ = json.Unmarshal(jsonBytes, &m)
	return m
}

// Processes returns a snapshot of the request's completed child traces. It is
// safe when an older or user-created context has no process collection.
func (c *Context) Processes() []formatter.Process {
	c.mux.Lock()
	defer c.mux.Unlock()

	services := c.processCollectionLocked()
	result := make([]formatter.Process, len(*services))
	copy(result, *services)
	return result
}

// clearProcesses removes only the traces included in a completed log payload.
// It deliberately runs after formatting so TraceEnd entries remain available
// to the final request log.
func (c *Context) clearProcesses(count int) {
	if count <= 0 {
		return
	}

	c.mux.Lock()
	defer c.mux.Unlock()

	services := c.processCollectionLocked()
	if len(*services) <= count {
		*services = make([]formatter.Process, 0)
		return
	}
	remaining := make([]formatter.Process, len(*services)-count)
	copy(remaining, (*services)[count:])
	*services = remaining
}

// processCollectionLocked returns the collection shared by every derived
// builder.Context. c.mux must be held by the caller.
func (c *Context) processCollectionLocked() *[]formatter.Process {
	if value, ok := c.Get(servicesKey); ok {
		if services, ok := value.(*[]formatter.Process); ok && services != nil {
			if *services == nil {
				*services = make([]formatter.Process, 0)
			}
			return services
		}
	}

	services := make([]formatter.Process, 0)
	c.Set(servicesKey, &services)
	return &services
}

// TraceInit marks the start of tracing for a process or subprocess.
//
// It records the start time in process.TimeInit and, if tracing is
// enabled, creates a span associated with the process.
//
// If the logger is in test mode, it does nothing.
//
// Recommended usage:
//
//	process := &formatter.Services{
//	    System: "PaymentService",
//	    Process: Process Paymaent,
//	}
//	ctx.TraceInit(process)
//	defer ctx.TraceEnd(process)
func (c *Context) TraceInit(process *formatter.Process) {
	if process == nil {
		return
	}
	if IsModeTest() {
		return
	}
	c.mux.Lock()
	defer c.mux.Unlock()
	c.startSpan(process)
	process.TimeInit = time.Now()
}

func (c *Context) startSpan(process *formatter.Process) {
	if c.disableTrace {
		return
	}
	c.Context, process.Span = c.tracer.Start(c.Context, string(process.Process))
	process.Span.SetAttributes(attribute.String(string(systemAtribute), process.System))
}

// TraceEnd completes the measurement started with TraceInit.
//
// This function:
//
//   - assigns the trace ID to the process, if applicable
//   - classifies the status based on the HTTP code
//   - calculates the process latency
//   - adds the process to the context's service list
//   - records attributes in the span and closes it
//
// If the logger is in test mode, it performs no action.
//
// It should normally be used with defer immediately after TraceInit.
func (c *Context) TraceEnd(process *formatter.Process) {
	if process == nil {
		return
	}
	if IsModeTest() {
		return
	}
	c.mux.Lock()
	defer c.mux.Unlock()

	if v, ok := c.Get(common.DisableTraceRequestBodyKey); ok {
		if disable, ok := v.(bool); ok && disable {
			process.Request = nil
		}
	}
	if v, ok := c.Get(common.DisableTraceResponseBodyKey); ok {
		if disable, ok := v.(bool); ok && disable {
			process.Response = nil
		}
	}

	c.setTraceID(process)
	classifyStatus(process)
	ignoreHeaders(process)

	services := c.processCollectionLocked()
	if process.TimeInit.IsZero() {
		process.TimeInit = time.Now()
	}
	process.Latency = time.Since(process.TimeInit).Milliseconds()
	*services = append(*services, *process)

	c.setSpanAttributes(process)
}

func ignoreHeaders(process *formatter.Process) {
	if process.Headers == nil || *process.Headers == nil {
		return
	}

	headers := make(http.Header, len(*process.Headers))
	for key, vv := range *process.Headers {
		if viperdata.IsIgnoredHeader(key) {
			continue
		}
		vvCopy := make([]string, len(vv))
		copy(vvCopy, vv)
		headers[key] = vvCopy
	}
	cloned := headers.Clone()
	process.Headers = &cloned
}

func (c *Context) setSpanAttributes(process *formatter.Process) {
	if c.disableTrace || process.Span == nil {
		return
	}
	defer process.Span.End()
	process.Span.SetAttributes(attribute.String(string(statusAtribute), string(process.Status)))
}

func (c *Context) setTraceID(process *formatter.Process) {
	if c.disableTrace || process.Span == nil {
		return
	}
	sc := process.Span.SpanContext()
	if traceID := sc.TraceID(); traceID.IsValid() {
		process.TraceID = traceID.String()
	}
	if spanID := sc.SpanID(); spanID.IsValid() {
		process.SpanID = spanID.String()
	}
}

func classifyStatus(process *formatter.Process) {
	switch {
	case process.Code == 0:
		if process.Status != "" {
			return
		}
		process.SetStatus(formatter.SUCCESS)
	case process.Code >= 200 && process.Code < 300:
		process.SetStatus(formatter.SUCCESS)
	case process.Code >= 300 && process.Code < 400:
		process.SetStatus(formatter.OTHER)
	case process.Code >= 400 && process.Code < 500:
		process.SetStatus(formatter.CLIENT_ERROR)
	case process.Code >= 500 && process.Code < 600:
		process.SetStatus(formatter.ERROR)
	default:
		if process.Status != "" {
			return
		}
		process.SetStatus(formatter.UNKNOWN)
	}
}

func (c *Context) prepareLog() bool {
	if IsModeTest() {
		return false
	}
	if v, ok := c.Get(detailsKey); ok {
		details := v.(formatter.Details)
		c.Details.System = details.System
		c.Details.Client = details.Client
		c.Details.Method = details.Method
		c.Details.Protocol = details.Protocol
	}
	c.Set(detailsKey, c.Details)
	return true
}

func (c *Context) log(level slog.Level, message string) {
	if !c.prepareLog() {
		return
	}
	slog.Log(c, level, message)
}

func (c *Context) logf(level slog.Level, format string, args ...any) {
	c.log(level, fmt.Sprintf(format, args...))
}

// Info logs an informational message using the current context.
//
// If the context already contains details base information, it copies the System,
// Service, and Client fields from the received data before storing it again.
//
// If the logger is in test mode, it does not generate any output.
//
// This function only logs the message; it does not create spans or measure latency on its own.
func (c *Context) Info(message string) {
	c.log(slog.LevelInfo, message)
}

// Infof logs a formatted informational message using the current context.
func (c *Context) Infof(format string, args ...any) {
	c.logf(slog.LevelInfo, format, args...)
}

// Debug logs a debug-level message using the current context.
//
// If the context already contains details base information, it copies the System,
// Service, and Client fields from the received data before storing it again.
//
// If the logger is in test mode, it does not generate any output.
//
// This function is intended for development or troubleshooting purposes and
// should not be relied upon for critical operational logging in production
// environments unless debug logging is explicitly enabled.
//
// This function only logs the message; it does not create spans or measure latency on its own.
func (c *Context) Debug(message string) {
	c.log(slog.LevelDebug, message)
}

// Debugf logs a formatted debug-level message using the current context.
func (c *Context) Debugf(format string, args ...any) {
	c.logf(slog.LevelDebug, format, args...)
}

// Warn logs a warning message using the current context.
//
// If the context already contains details base information, it copies the System,
// Service, and Client fields from the received data before storing it again.
//
// If the logger is in test mode, it does not generate any output.
//
// This function only logs the message; it does not create spans or measure latency on its own.
func (c *Context) Warn(message string) {
	c.log(slog.LevelWarn, message)
}

// Warnf logs a formatted warning message using the current context.
func (c *Context) Warnf(format string, args ...any) {
	c.logf(slog.LevelWarn, format, args...)
}

// Error logs an error message using `slog` with the current context.
//
// If the context already contains details base information, it copies `System`,
// `Service`, and `Client` to the received details before storing them again.
//
// If the logger is in test mode, it does not generate any output.
//
// This function logs err.Error() and does not modify the execution flow;
// error handling remains the callerâ€™s responsibility.
func (c *Context) Error(err error) {
	c.log(slog.LevelError, err.Error())
}

// Errorf logs a formatted error message using the current context.
func (c *Context) Errorf(format string, args ...any) {
	c.logf(slog.LevelError, format, args...)
}
