package export_pointerbyte_goforge_poc_operations

import (
	"math"
	"testing"

	"wit_component/pointerbyte_goforge_poc_operations"
)

func TestOperations(t *testing.T) {
	if got := Add(20, 22); got != 42 {
		t.Fatalf("Add() = %d", got)
	}
	if got := Greet("Deno"); got != "hello, Deno" {
		t.Fatalf("Greet() = %q", got)
	}
	if got := ReverseBytes([]byte{0, 1, 2, 255}); string(got) != string([]byte{255, 2, 1, 0}) {
		t.Fatalf("ReverseBytes() = %v", got)
	}

	ok := Summarize(pointerbyte_goforge_poc_operations.Pair{Left: 20, Right: 22})
	if !ok.IsOk() || ok.Ok().Total != 42 || ok.Ok().Label != "sum:42" {
		t.Fatalf("Summarize() success = %+v", ok)
	}

	invalid := Summarize(pointerbyte_goforge_poc_operations.Pair{})
	if !invalid.IsErr() || invalid.Err().Tag() != pointerbyte_goforge_poc_operations.OperationErrorInvalidInput {
		t.Fatalf("Summarize() invalid = %+v", invalid)
	}

	overflow := Summarize(pointerbyte_goforge_poc_operations.Pair{Left: math.MaxUint32, Right: 1})
	if !overflow.IsErr() || overflow.Err().Tag() != pointerbyte_goforge_poc_operations.OperationErrorOverflow {
		t.Fatalf("Summarize() overflow = %+v", overflow)
	}
}
