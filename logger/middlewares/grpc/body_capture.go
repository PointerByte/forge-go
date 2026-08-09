// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/PointerByte/forge-go/logger/formatter"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"google.golang.org/protobuf/proto"
)

const maxBodySizeWalkDepth = 32

type grpcBodyCapture struct {
	limit         int
	capturedBytes int
	values        []any
	truncated     bool
}

func newGRPCBodyCapture(limit int) *grpcBodyCapture {
	if limit <= 0 {
		limit = viperdata.DefaultBodyCaptureMaxBytes
	}
	return &grpcBodyCapture{limit: limit}
}

func (c *grpcBodyCapture) add(value any) {
	remaining := c.limit - c.capturedBytes
	if remaining < 0 {
		remaining = 0
	}

	captured, size, keep, truncated := fitGRPCBody(value, remaining)
	if keep {
		c.values = append(c.values, captured)
		c.capturedBytes += size
	}
	if truncated {
		c.truncated = true
	}
}

func (c *grpcBodyCapture) value() any {
	return collapseCapturedBodies(c.values)
}

func (c *grpcBodyCapture) metadata() *formatter.BodyCaptureMetadata {
	if !c.truncated {
		return nil
	}
	return &formatter.BodyCaptureMetadata{
		Truncated:     true,
		CapturedBytes: c.capturedBytes,
		LimitBytes:    c.limit,
	}
}

func fitGRPCBody(value any, remaining int) (captured any, size int, keep bool, truncated bool) {
	if value == nil {
		return nil, 0, false, false
	}

	protoValue := false
	if _, ok := value.(proto.Message); !ok {
		value = dereferenceScalarBody(value)
	}
	switch body := value.(type) {
	case string:
		captureSize := len(body)
		if captureSize == 0 {
			captureSize = 1
		}
		if captureSize <= remaining {
			return strings.Clone(body), captureSize, true, false
		}
		if remaining == 0 {
			return nil, 0, false, true
		}
		return strings.Clone(body[:remaining]), remaining, remaining > 0, true
	case []byte:
		captureSize := len(body)
		if captureSize == 0 {
			captureSize = 1
		}
		if captureSize <= remaining {
			return append([]byte(nil), body...), captureSize, true, false
		}
		if remaining == 0 {
			return nil, 0, false, true
		}
		return append([]byte(nil), body[:remaining]...), remaining, remaining > 0, true
	case proto.Message:
		protoValue = true
		bodySize := proto.Size(body)
		if bodySize > remaining {
			return nil, 0, false, true
		}
	}

	if !protoValue {
		if _, fits := retainedBodySize(reflect.ValueOf(value), remaining); !fits {
			return nil, 0, false, true
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > remaining {
		return nil, 0, false, true
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var copy any
	if err := decoder.Decode(&copy); err != nil {
		return nil, 0, false, true
	}
	return copy, len(encoded), true, false
}

func dereferenceScalarBody(value any) any {
	reflected := reflect.ValueOf(value)
	for reflected.IsValid() && (reflected.Kind() == reflect.Pointer || reflected.Kind() == reflect.Interface) {
		if reflected.IsNil() {
			return nil
		}
		reflected = reflected.Elem()
	}
	if !reflected.IsValid() || !reflected.CanInterface() {
		return value
	}
	switch reflected.Kind() {
	case reflect.String:
		return reflected.String()
	case reflect.Slice:
		if reflected.Type().Elem().Kind() == reflect.Uint8 {
			return reflected.Bytes()
		}
	}
	return value
}

type bodyVisit struct {
	kind reflect.Kind
	ptr  uintptr
}

func retainedBodySize(value reflect.Value, budget int) (int, bool) {
	visited := make(map[bodyVisit]struct{})
	size, exceeded := walkRetainedBodySize(value, budget, 0, visited)
	return size, !exceeded
}

func walkRetainedBodySize(value reflect.Value, budget int, depth int, visited map[bodyVisit]struct{}) (int, bool) {
	if !value.IsValid() {
		return 0, false
	}
	if depth > maxBodySizeWalkDepth {
		return budget + 1, true
	}

	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return 0, false
		}
		return walkRetainedBodySize(value.Elem(), budget, depth+1, visited)
	case reflect.Pointer:
		if value.IsNil() {
			return 0, false
		}
		if alreadyVisited(value, visited) {
			return budget + 1, true
		}
		return walkRetainedBodySize(value.Elem(), budget, depth+1, visited)
	case reflect.String:
		size := value.Len()
		return size, size > budget
	case reflect.Slice:
		if value.IsNil() {
			return 0, false
		}
		if alreadyVisited(value, visited) {
			return budget + 1, true
		}
		if value.Type().Elem().Kind() == reflect.Uint8 {
			size := value.Len()
			return size, size > budget
		}
		return walkBodySequence(value, budget, depth, visited)
	case reflect.Array:
		return walkBodySequence(value, budget, depth, visited)
	case reflect.Map:
		if value.IsNil() {
			return 0, false
		}
		if alreadyVisited(value, visited) {
			return budget + 1, true
		}
		total := 0
		iter := value.MapRange()
		for iter.Next() {
			for _, item := range []reflect.Value{iter.Key(), iter.Value()} {
				itemSize, exceeded := walkRetainedBodySize(item, budget-total, depth+1, visited)
				total += itemSize
				if exceeded || total > budget {
					return total, true
				}
			}
		}
		return total, false
	case reflect.Struct:
		total := 0
		for index := 0; index < value.NumField(); index++ {
			fieldSize, exceeded := walkRetainedBodySize(value.Field(index), budget-total, depth+1, visited)
			total += fieldSize
			if exceeded || total > budget {
				return total, true
			}
		}
		return total, false
	default:
		size := int(value.Type().Size())
		return size, size > budget
	}
}

func walkBodySequence(value reflect.Value, budget int, depth int, visited map[bodyVisit]struct{}) (int, bool) {
	total := 0
	for index := 0; index < value.Len(); index++ {
		itemSize, exceeded := walkRetainedBodySize(value.Index(index), budget-total, depth+1, visited)
		total += itemSize
		if exceeded || total > budget {
			return total, true
		}
	}
	return total, false
}

func alreadyVisited(value reflect.Value, visited map[bodyVisit]struct{}) bool {
	pointer := value.Pointer()
	if pointer == 0 {
		return false
	}
	visit := bodyVisit{kind: value.Kind(), ptr: pointer}
	if _, ok := visited[visit]; ok {
		return true
	}
	visited[visit] = struct{}{}
	return false
}
