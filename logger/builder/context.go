// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/PointerByte/forge-go/logger/common"
	"github.com/PointerByte/forge-go/logger/formatter"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// Context is a custom context similar to gin.Context.
type Context struct {
	context.Context  // hereda Cancel, Deadline, Done, Value
	mux              sync.Mutex
	startTime        time.Time
	fields           *sync.Map
	disableTrace     bool
	tracer           trace.Tracer // Trace from telemetry
	Method           string
	Line             int
	Details          formatter.Details
	tracerCallerSkip int
}

// DisableTrace disables trace logging for a specific process or trace.
func (c *Context) DisableTrace() {
	c.disableTrace = true
}

// private key to store the *logger.Context* within context.Context.
type ctxKey int

const loggerCtxKey ctxKey = iota

// From attempts to extract a *logger.Context* from a context.Context.
// Returns (*Context, true) if it exists; otherwise (nil, false).
func From(parent context.Context) (*Context, bool) {
	if parent == nil {
		return nil, false
	}
	// Case 1: The parent is already a *logger.Context
	if lc, ok := parent.(*Context); ok && lc != nil {
		return lc, true
	}
	// Case 2: The parent has saved the *logger.Context* in the values
	if v := parent.Value(loggerCtxKey); v != nil {
		if lc, ok := v.(*Context); ok && lc != nil {
			return lc, true
		}
	}
	return nil, false
}

// New creates or reuses a *logger.Context*.
//
//   - If the parent context already contains a *logger.Context*, it reuses it.
//   - Otherwise, it creates a new one, initializes the traceID and the list of services,
//     and saves it in the context values for later use.
func New(parent context.Context) *Context {
	if parent == nil {
		parent = context.Background()
	}

	// Reuse the context if it already exists
	if existing, ok := From(parent); ok {
		return existing
	}

	appName := viperdata.GetViperData(string(viperdata.AppAtribute)).(string)
	newContext := &Context{
		Context:   parent,
		startTime: time.Now(),
		fields:    &sync.Map{},
		tracer:    otel.Tracer(appName),
	}

	// Initialize traceID
	traceID := strings.ReplaceAll(uuid.NewString(), "-", "")
	newContext.SetTraceID(traceID)

	// Initialize service collection
	services := make([]formatter.Process, 0)
	newContext.Set(servicesKey, &services)

	// Save the *logger.Context* within the context for future retrieval
	newContext.Context = context.WithValue(parent, loggerCtxKey, newContext)

	// Default disable request and response bodies in traces and process for security and performance reasons.
	newContext.Set(common.DisableTraceRequestBodyKey, true)
	newContext.Set(common.DisableTraceResponseBodyKey, true)
	newContext.Set(common.DisableRequestBodyKey, true)
	newContext.Set(common.DisableResponseBodyKey, true)
	return newContext
}

// SetTraceCallerSkip sets the number of stack frames to skip when determining the caller's method and line number for logging purposes.
func (c *Context) SetTraceCallerSkip(skip int) {
	c.tracerCallerSkip = skip
}

// GetTraceCallerSkip returns the number of stack frames to skip when determining the caller's method and line number for logging purposes.
func (c *Context) GetTraceCallerSkip() int {
	if c.tracerCallerSkip == 0 {
		return 2 // Default value
	}
	return c.tracerCallerSkip
}

// Set adds a key-value pair to the context.
func (c *Context) Set(key any, value any) {
	c.fields.Store(key, value)
}

// SetTraceID stores the correlation trace id used by structured logs and
// fallback propagation headers.
func (c *Context) SetTraceID(id string) {
	if id == "" {
		return
	}
	c.Set(traceIDKey, id)
	c.Set(common.TraceIDKey, id)
}

// TraceID returns the current correlation trace id.
func (c *Context) TraceID() string {
	if v, ok := c.Get(traceIDKey); ok {
		if traceID, ok := v.(string); ok && traceID != "" {
			return traceID
		}
	}
	if v, ok := c.Get(common.TraceIDKey); ok {
		if traceID, ok := v.(string); ok {
			return traceID
		}
	}
	return ""
}

// Get retrieves a value from the context.
func (c *Context) Get(key any) (value any, ok bool) {
	return c.fields.Load(key)
}

// MustGet returns a value or throws an exception if one does not exist.
func (c *Context) MustGet(key string) any {
	if v, ok := c.Get(key); ok {
		return v
	}
	panic(fmt.Sprintf("logger.Context: key '%s' not found", key))
}

// GetLatency returns the elapsed time since the context was created.
// It measures how long the operation associated with this context has been running.
func (c *Context) GetLatency() int64 {
	return time.Since(c.startTime).Milliseconds()
}

// WithCancel creates a copy of logger.Context with support for manual cancellation.
func (c *Context) WithCancel() (*Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(c.Context)
	newCtx := &Context{
		Context:      ctx,
		startTime:    c.startTime,
		fields:       c.fields,
		tracer:       c.tracer,
		disableTrace: c.disableTrace,
		Method:       c.Method,
		Line:         c.Line,
	}
	return newCtx, cancel
}

// WithTimeout creates a copy of logger.Context that automatically expires
// after the specified duration.
func (c *Context) WithTimeout(d time.Duration) (*Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(c.Context, d)
	newCtx := &Context{
		Context:      ctx,
		startTime:    c.startTime,
		fields:       c.fields,
		tracer:       c.tracer,
		disableTrace: c.disableTrace,
		Method:       c.Method,
		Line:         c.Line,
	}
	return newCtx, cancel
}
