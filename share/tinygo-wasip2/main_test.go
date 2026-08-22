package main

import (
	"math"
	"testing"

	"github.com/PointerByte/forge-go/share/tinygo-wasip2/generated/pointerbyte/goforge-poc/operations"
	"go.bytecodealliance.org/cm"
)

func TestPortableOperations(t *testing.T) {
	if got := add(20, 22); got != 42 {
		t.Fatalf("add() = %d, want 42", got)
	}
	if got := greet("Deno"); got != "hello, Deno" {
		t.Fatalf("greet() = %q", got)
	}
	if got := reverseBytes(cm.ToList([]byte{0, 1, 2, 255})).Slice(); string(got) != string([]byte{255, 2, 1, 0}) {
		t.Fatalf("reverseBytes() = %v", got)
	}
}

func TestSummarizeResultCases(t *testing.T) {
	ok, errValue, isErr := summarize(operations.Pair{Left: 20, Right: 22}).Result()
	if isErr || ok.Total != 42 || ok.Label != "sum:42" {
		t.Fatalf("summarize success = (%+v, %+v, %v)", ok, errValue, isErr)
	}

	_, errValue, isErr = summarize(operations.Pair{}).Result()
	if !isErr || errValue.InvalidInput() == nil {
		t.Fatalf("summarize invalid input = (%+v, %v)", errValue, isErr)
	}

	_, errValue, isErr = summarize(operations.Pair{Left: math.MaxUint32, Right: 1}).Result()
	if !isErr || !errValue.Overflow() {
		t.Fatalf("summarize overflow = (%+v, %v)", errValue, isErr)
	}
}
