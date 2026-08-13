// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/PointerByte/forge-go/logger/common"
	"github.com/PointerByte/forge-go/logger/formatter"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// --- capture accumulator ---

func TestNewGRPCBodyCaptureNormalizesLimit(t *testing.T) {
	for _, limit := range []int{0, -1} {
		if got := newGRPCBodyCapture(limit).limit; got != viperdata.DefaultBodyCaptureMaxBytes {
			t.Fatalf("newGRPCBodyCapture(%d).limit = %d, want %d", limit, got, viperdata.DefaultBodyCaptureMaxBytes)
		}
	}
	if got := newGRPCBodyCapture(7).limit; got != 7 {
		t.Fatalf("newGRPCBodyCapture(7).limit = %d, want 7", got)
	}
}

func TestGRPCBodyCaptureMetadataOnlyWhenTruncated(t *testing.T) {
	capture := newGRPCBodyCapture(16)
	capture.add("ok")
	if capture.metadata() != nil {
		t.Fatalf("metadata() = %#v, want nil while untruncated", capture.metadata())
	}

	capture.add("this message is far beyond the remaining budget")
	metadata := capture.metadata()
	if metadata == nil || !metadata.Truncated {
		t.Fatalf("metadata() = %#v, want truncated metadata", metadata)
	}
	if metadata.LimitBytes != 16 {
		t.Fatalf("metadata().LimitBytes = %d, want 16", metadata.LimitBytes)
	}
	if metadata.CapturedBytes > metadata.LimitBytes {
		t.Fatalf("metadata().CapturedBytes = %d, want <= %d", metadata.CapturedBytes, metadata.LimitBytes)
	}
}

func TestGRPCBodyCaptureNeverExceedsLimitAcrossMessages(t *testing.T) {
	capture := newGRPCBodyCapture(10)
	for range 6 {
		capture.add("abcd")
	}
	if capture.capturedBytes > 10 {
		t.Fatalf("capturedBytes = %d, want <= 10", capture.capturedBytes)
	}
	if !capture.truncated {
		t.Fatal("truncated = false, want true once the aggregate limit is reached")
	}
}

// --- per-value fitting ---

func TestFitGRPCBodyScalars(t *testing.T) {
	text := "abcdef"
	tests := []struct {
		name          string
		value         any
		remaining     int
		wantCaptured  any
		wantSize      int
		wantKeep      bool
		wantTruncated bool
	}{
		{name: "nil is neither kept nor truncated", value: nil, remaining: 8},
		{name: "string fits", value: "abc", remaining: 8, wantCaptured: "abc", wantSize: 3, wantKeep: true},
		{name: "empty string is charged one byte", value: "", remaining: 8, wantCaptured: "", wantSize: 1, wantKeep: true},
		{
			name: "string is truncated to the remaining budget", value: "abcdef", remaining: 3,
			wantCaptured: "abc", wantSize: 3, wantKeep: true, wantTruncated: true,
		},
		{name: "string with no budget is dropped", value: "abc", remaining: 0, wantTruncated: true},
		{
			name: "pointer to string is dereferenced", value: &text, remaining: 8,
			wantCaptured: "abcdef", wantSize: 6, wantKeep: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			captured, size, keep, truncated := fitGRPCBody(tt.value, tt.remaining)
			if keep != tt.wantKeep || truncated != tt.wantTruncated || size != tt.wantSize {
				t.Fatalf("fitGRPCBody() = (%#v, %d, %t, %t), want (_, %d, %t, %t)",
					captured, size, keep, truncated, tt.wantSize, tt.wantKeep, tt.wantTruncated)
			}
			if tt.wantKeep && !reflect.DeepEqual(captured, tt.wantCaptured) {
				t.Fatalf("captured = %#v, want %#v", captured, tt.wantCaptured)
			}
		})
	}
}

func TestFitGRPCBodyBytes(t *testing.T) {
	source := []byte("abcdef")
	captured, size, keep, truncated := fitGRPCBody(source, 3)
	if !keep || !truncated || size != 3 {
		t.Fatalf("fitGRPCBody() = (%#v, %d, %t, %t), want kept truncated 3 bytes", captured, size, keep, truncated)
	}
	clone, ok := captured.([]byte)
	if !ok || string(clone) != "abc" {
		t.Fatalf("captured = %#v, want []byte(\"abc\")", captured)
	}

	// The capture must not alias the caller's backing array.
	source[0] = 'z'
	if string(clone) != "abc" {
		t.Fatalf("captured = %q, want a detached copy", clone)
	}

	if _, size, keep, _ = fitGRPCBody([]byte{}, 8); !keep || size != 1 {
		t.Fatalf("empty []byte size = %d keep = %t, want 1 byte charged", size, keep)
	}
	if _, _, keep, truncated = fitGRPCBody([]byte("abc"), 0); keep || !truncated {
		t.Fatalf("no-budget []byte keep = %t truncated = %t, want dropped and truncated", keep, truncated)
	}
}

func TestFitGRPCBodyProtoMessage(t *testing.T) {
	message := wrapperspb.String("hello")

	if _, _, keep, truncated := fitGRPCBody(message, 2); keep || !truncated {
		t.Fatalf("oversized proto keep = %t truncated = %t, want dropped and truncated", keep, truncated)
	}

	captured, size, keep, truncated := fitGRPCBody(message, 1024)
	if !keep || truncated || size <= 0 {
		t.Fatalf("fitGRPCBody(proto) = (%#v, %d, %t, %t), want kept untruncated", captured, size, keep, truncated)
	}
	if _, isMap := captured.(map[string]any); !isMap {
		t.Fatalf("captured = %T, want a decoded map", captured)
	}
}

func TestFitGRPCBodyStructuredValues(t *testing.T) {
	type payload struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	captured, size, keep, truncated := fitGRPCBody(payload{Name: "ada", Count: 2}, 1024)
	if !keep || truncated {
		t.Fatalf("fitGRPCBody(struct) keep = %t truncated = %t, want kept untruncated", keep, truncated)
	}
	decoded, ok := captured.(map[string]any)
	if !ok {
		t.Fatalf("captured = %T, want map[string]any", captured)
	}
	// UseNumber keeps integers exact instead of widening them to float64.
	if _, isNumber := decoded["count"].(json.Number); !isNumber {
		t.Fatalf("decoded[count] = %T, want json.Number", decoded["count"])
	}
	if size <= 0 {
		t.Fatalf("size = %d, want the encoded length", size)
	}

	if _, _, keep, truncated = fitGRPCBody(payload{Name: "ada", Count: 2}, 4); keep || !truncated {
		t.Fatalf("over-budget struct keep = %t truncated = %t, want dropped and truncated", keep, truncated)
	}

	// Values JSON cannot encode are reported as truncated rather than panicking.
	if _, _, keep, truncated = fitGRPCBody(struct {
		Ch chan int `json:"ch"`
	}{Ch: make(chan int)}, 4096); keep || !truncated {
		t.Fatalf("unencodable struct keep = %t truncated = %t, want dropped and truncated", keep, truncated)
	}
}

// --- scalar dereferencing ---

func TestDereferenceScalarBody(t *testing.T) {
	text := "abc"
	pointer := &text
	data := []byte("xyz")
	var nilPointer *string
	var boxed any = &text

	if got := dereferenceScalarBody(pointer); got != "abc" {
		t.Fatalf("dereferenceScalarBody(*string) = %#v, want \"abc\"", got)
	}
	if got := dereferenceScalarBody(&data); string(got.([]byte)) != "xyz" {
		t.Fatalf("dereferenceScalarBody(*[]byte) = %#v, want []byte(\"xyz\")", got)
	}
	if got := dereferenceScalarBody(nilPointer); got != nil {
		t.Fatalf("dereferenceScalarBody(nil *string) = %#v, want nil", got)
	}
	if got := dereferenceScalarBody(boxed); got != "abc" {
		t.Fatalf("dereferenceScalarBody(any(*string)) = %#v, want \"abc\"", got)
	}
	// Non-scalar kinds are returned untouched for the JSON path to handle.
	structured := struct{ A int }{A: 1}
	if got := dereferenceScalarBody(structured); got != any(structured) {
		t.Fatalf("dereferenceScalarBody(struct) = %#v, want the original value", got)
	}
	if got := dereferenceScalarBody([]int{1, 2}); !reflect.DeepEqual(got, []int{1, 2}) {
		t.Fatalf("dereferenceScalarBody([]int) = %#v, want the original slice", got)
	}
}

// --- retained size walking ---

type sizeNode struct {
	Next  *sizeNode
	Label string
}

func TestRetainedBodySizeBounds(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		budget   int
		wantFits bool
	}{
		{name: "string within budget", value: "abcd", budget: 8, wantFits: true},
		{name: "string over budget", value: "abcdefghi", budget: 4},
		{name: "bytes over budget", value: []byte("abcdefghi"), budget: 4},
		{name: "nil slice costs nothing", value: []string(nil), budget: 1, wantFits: true},
		{name: "nil map costs nothing", value: map[string]string(nil), budget: 1, wantFits: true},
		{name: "nil pointer costs nothing", value: (*sizeNode)(nil), budget: 1, wantFits: true},
		{name: "array of strings within budget", value: [2]string{"ab", "cd"}, budget: 8, wantFits: true},
		{name: "array of strings over budget", value: [2]string{"abcd", "efgh"}, budget: 4},
		{name: "map within budget", value: map[string]string{"a": "b"}, budget: 8, wantFits: true},
		{name: "map over budget", value: map[string]string{"aaaa": "bbbb"}, budget: 4},
		{name: "struct within budget", value: sizeNode{Label: "ab"}, budget: 8, wantFits: true},
		{name: "struct over budget", value: sizeNode{Label: "abcdefghi"}, budget: 4},
		{name: "slice of strings over budget", value: []string{"abcd", "efgh"}, budget: 4},
		{name: "integer uses its machine size", value: 1, budget: 64, wantFits: true},
		{name: "integer over a tiny budget", value: 1, budget: 0},
		{name: "nil interface inside a struct", value: struct{ V any }{}, budget: 8, wantFits: true},
		{name: "boxed string inside a struct", value: struct{ V any }{V: "ab"}, budget: 8, wantFits: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, fits := retainedBodySize(reflect.ValueOf(tt.value), tt.budget); fits != tt.wantFits {
				t.Fatalf("retainedBodySize(%#v, %d) fits = %t, want %t", tt.value, tt.budget, fits, tt.wantFits)
			}
		})
	}
}

func TestRetainedBodySizeRejectsDeepNesting(t *testing.T) {
	// Each node costs two levels (pointer then struct), so 20 nodes exceed the
	// 32-level ceiling and must fail closed rather than recurse without bound.
	head := &sizeNode{}
	cursor := head
	for range 20 {
		cursor.Next = &sizeNode{}
		cursor = cursor.Next
	}
	if _, fits := retainedBodySize(reflect.ValueOf(head), 1<<20); fits {
		t.Fatal("retainedBodySize(deep chain) fits = true, want false")
	}
}

func TestRetainedBodySizeRejectsCycles(t *testing.T) {
	cyclic := &sizeNode{Label: "a"}
	cyclic.Next = cyclic
	if _, fits := retainedBodySize(reflect.ValueOf(cyclic), 1<<20); fits {
		t.Fatal("retainedBodySize(pointer cycle) fits = true, want false")
	}

	selfSlice := make([]any, 1)
	selfSlice[0] = selfSlice
	if _, fits := retainedBodySize(reflect.ValueOf(selfSlice), 1<<20); fits {
		t.Fatal("retainedBodySize(slice cycle) fits = true, want false")
	}

	selfMap := map[string]any{}
	selfMap["self"] = selfMap
	if _, fits := retainedBodySize(reflect.ValueOf(selfMap), 1<<20); fits {
		t.Fatal("retainedBodySize(map cycle) fits = true, want false")
	}
}

// --- context metadata decoding ---

func TestGRPCBodyCaptureMetadataAcceptsBothKeyForms(t *testing.T) {
	source := formatter.BodyCaptureMetadata{Truncated: true, CapturedBytes: 3, LimitBytes: 8}

	ctxLogger := builder.New(context.Background())
	ctxLogger.Set(common.RequestBodyCaptureKey, source)
	metadata, ok := grpcBodyCaptureMetadata(ctxLogger, common.RequestBodyCaptureKey)
	if !ok || metadata == nil || *metadata != source {
		t.Fatalf("grpcBodyCaptureMetadata(typed key) = (%#v, %t), want a copy of the value", metadata, ok)
	}

	// Entries stored under the string form of the key are also resolved.
	stringKeyed := builder.New(context.Background())
	stringKeyed.Set(string(common.ResponseBodyCaptureKey), &source)
	metadata, ok = grpcBodyCaptureMetadata(stringKeyed, common.ResponseBodyCaptureKey)
	if !ok || metadata == nil || *metadata != source {
		t.Fatalf("grpcBodyCaptureMetadata(string key) = (%#v, %t), want a copy of the value", metadata, ok)
	}
	if metadata == &source {
		t.Fatal("grpcBodyCaptureMetadata aliased the stored value")
	}
}

func TestGRPCBodyCaptureMetadataRejectsMissingNilAndForeignValues(t *testing.T) {
	ctxLogger := builder.New(context.Background())
	if metadata, ok := grpcBodyCaptureMetadata(ctxLogger, common.RequestBodyCaptureKey); ok || metadata != nil {
		t.Fatalf("missing key = (%#v, %t), want (nil, false)", metadata, ok)
	}

	ctxLogger.Set(common.RequestBodyCaptureKey, (*formatter.BodyCaptureMetadata)(nil))
	if metadata, ok := grpcBodyCaptureMetadata(ctxLogger, common.RequestBodyCaptureKey); ok || metadata != nil {
		t.Fatalf("nil pointer = (%#v, %t), want (nil, false)", metadata, ok)
	}

	ctxLogger.Set(common.ResponseBodyCaptureKey, "metadata")
	if metadata, ok := grpcBodyCaptureMetadata(ctxLogger, common.ResponseBodyCaptureKey); ok || metadata != nil {
		t.Fatalf("foreign type = (%#v, %t), want (nil, false)", metadata, ok)
	}
}

func TestAlreadyVisitedIgnoresZeroPointers(t *testing.T) {
	visited := make(map[bodyVisit]struct{})
	if alreadyVisited(reflect.ValueOf([]string(nil)), visited) {
		t.Fatal("alreadyVisited(nil slice) = true, want false")
	}
	if len(visited) != 0 {
		t.Fatalf("visited = %d entries, want 0 for a zero pointer", len(visited))
	}

	data := []string{"a"}
	value := reflect.ValueOf(data)
	if alreadyVisited(value, visited) {
		t.Fatal("first visit reported as already visited")
	}
	if !alreadyVisited(value, visited) {
		t.Fatal("second visit not reported as already visited")
	}
}
