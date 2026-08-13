// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"context"
	"testing"
	"time"

	"github.com/PointerByte/forge-go/logger/common"
)

// ---- Helpers ----

func mustPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic, but function did not panic")
		}
	}()
	f()
}

func TestLoggerContext_All(t *testing.T) {
	t.Parallel()

	base := context.Background()
	c := New(base)
	c.Set("user", "alice")

	if v, ok := c.Get("user"); !ok || v != "alice" {
		t.Fatalf("expected Get('user')='alice', got (%v, %v)", v, ok)
	}

	if v := c.MustGet("user"); v != "alice" {
		t.Fatalf("expected MustGet('user')='alice', got %v", v)
	}

	mustPanic(t, func() { _ = c.MustGet("missing") })

	// Latency should grow
	d1 := c.GetLatency()
	time.Sleep(5 * time.Millisecond)
	d2 := c.GetLatency()
	if d2 <= d1 {
		t.Fatalf("expected latency to increase, got %v <= %v", d2, d1)
	}

	// WithCancel
	child, cancel := c.WithCancel()
	defer cancel()
	child.Set("id", 99)
	if _, ok := c.Get("id"); !ok {
		t.Fatalf("expected shared fields between parent and child")
	}
	cancel()
	select {
	case <-child.Done():
	default:
		t.Fatalf("expected cancelled child context")
	}

	// WithTimeout
	child2, cancel2 := c.WithTimeout(5 * time.Millisecond)
	defer cancel2()
	select {
	case <-child2.Done():
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("timeout child did not finish in time")
	}
}

func TestContext_DisableTrace(t *testing.T) {
	c := New(context.Background())
	c.DisableTrace()
}

func TestContextTraceIDAccessors(t *testing.T) {
	c := New(context.Background())
	if got := c.TraceID(); got == "" {
		t.Fatal("TraceID() is empty")
	}

	c.SetTraceID("trace-local")
	if got := c.TraceID(); got != "trace-local" {
		t.Fatalf("TraceID() = %q, want %q", got, "trace-local")
	}
	if got, ok := c.Get(common.TraceIDKey); !ok || got != "trace-local" {
		t.Fatalf("common TraceIDKey = %#v, %t; want trace-local, true", got, ok)
	}
}
