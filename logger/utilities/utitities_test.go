// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package utilities

import (
	"runtime"
	"strings"
	"testing"
)

func captureTraceCaller() (string, int, int) {
	_, _, expectedLine, _ := runtime.Caller(0)
	funcName, line := TraceCaller(1)
	return funcName, line, expectedLine + 1
}

func TestTraceCallerReturnsCallerData(t *testing.T) {
	funcName, line, expectedLine := captureTraceCaller()

	if !strings.HasSuffix(funcName, ".captureTraceCaller") {
		t.Fatalf("funcName = %q, want suffix %q", funcName, ".captureTraceCaller")
	}
	if line != expectedLine {
		t.Fatalf("line = %d, want %d", line, expectedLine)
	}
}

func TestTraceCallerReturnsUnknownWhenSkipIsTooLarge(t *testing.T) {
	funcName, line := TraceCaller(1 << 20)

	if funcName != "unknown" {
		t.Fatalf("funcName = %q, want %q", funcName, "unknown")
	}
	if line != 0 {
		t.Fatalf("line = %d, want %d", line, 0)
	}
}

func TestTraceCallerReturnsUnknownWhenRuntimeFuncIsNil(t *testing.T) {
	originalCaller := runtimeCaller
	originalFuncForPC := runtimeFuncForPC
	t.Cleanup(func() {
		runtimeCaller = originalCaller
		runtimeFuncForPC = originalFuncForPC
	})

	runtimeCaller = func(skip int) (uintptr, string, int, bool) {
		return 123, "fake.go", 77, true
	}
	runtimeFuncForPC = func(pc uintptr) *runtime.Func {
		return nil
	}

	funcName, line := TraceCaller(0)

	if funcName != "unknown" {
		t.Fatalf("funcName = %q, want %q", funcName, "unknown")
	}
	if line != 77 {
		t.Fatalf("line = %d, want %d", line, 77)
	}
}
