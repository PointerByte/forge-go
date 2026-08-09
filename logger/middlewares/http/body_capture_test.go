// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PointerByte/forge-go/logger/formatter"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/gin-gonic/gin"
)

// --- bounded buffer ---

func TestNewBoundedBodyCaptureNormalizesLimit(t *testing.T) {
	for _, limit := range []int{0, -1} {
		if got := newBoundedBodyCapture(limit).limit; got != viperdata.DefaultBodyCaptureMaxBytes {
			t.Fatalf("newBoundedBodyCapture(%d).limit = %d, want %d", limit, got, viperdata.DefaultBodyCaptureMaxBytes)
		}
	}
	if got := newBoundedBodyCapture(9).limit; got != 9 {
		t.Fatalf("newBoundedBodyCapture(9).limit = %d, want 9", got)
	}
}

func TestBoundedBodyCaptureWriteTruncatesAtLimit(t *testing.T) {
	capture := newBoundedBodyCapture(4)

	// Write always reports the full payload length so callers relying on the
	// io.Writer contract are not disturbed by the capture limit.
	n, err := capture.Write([]byte("abcdef"))
	if n != 6 || err != nil {
		t.Fatalf("Write() = (%d, %v), want (6, nil)", n, err)
	}
	if capture.body.String() != "abcd" {
		t.Fatalf("captured = %q, want %q", capture.body.String(), "abcd")
	}
	if !capture.truncated {
		t.Fatal("truncated = false, want true")
	}
	if got := capture.remaining(); got != 0 {
		t.Fatalf("remaining() = %d, want 0", got)
	}

	// Further writes are discarded but still accounted as truncation.
	if n, err = capture.Write([]byte("ghi")); n != 3 || err != nil {
		t.Fatalf("Write() after exhaustion = (%d, %v), want (3, nil)", n, err)
	}
	if capture.body.String() != "abcd" {
		t.Fatalf("captured = %q, want the buffer unchanged", capture.body.String())
	}
}

func TestBoundedBodyCaptureWriteWithinLimitIsNotTruncated(t *testing.T) {
	capture := newBoundedBodyCapture(8)
	if _, err := capture.Write([]byte("abc")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if capture.truncated {
		t.Fatal("truncated = true, want false")
	}
	if got := capture.remaining(); got != 5 {
		t.Fatalf("remaining() = %d, want 5", got)
	}
	if capture.metadata() != nil {
		t.Fatalf("metadata() = %#v, want nil while untruncated", capture.metadata())
	}
}

func TestBoundedBodyCaptureMetadataReportsLimits(t *testing.T) {
	capture := newBoundedBodyCapture(4)
	if _, err := capture.Write([]byte("abcdef")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	metadata := capture.metadata()
	if metadata == nil {
		t.Fatal("metadata() = nil, want truncation metadata")
	}
	if !metadata.Truncated || metadata.CapturedBytes != 4 || metadata.LimitBytes != 4 {
		t.Fatalf("metadata() = %#v, want truncated 4/4", metadata)
	}
}

// --- context metadata decoding ---

func TestBodyCaptureMetadataAcceptsValueAndPointer(t *testing.T) {
	source := formatter.BodyCaptureMetadata{Truncated: true, CapturedBytes: 2, LimitBytes: 4}

	fromValue, ok := bodyCaptureMetadata(source)
	if !ok || fromValue == nil || *fromValue != source {
		t.Fatalf("bodyCaptureMetadata(value) = (%#v, %t), want a copy of the value", fromValue, ok)
	}

	fromPointer, ok := bodyCaptureMetadata(&source)
	if !ok || fromPointer == nil || *fromPointer != source {
		t.Fatalf("bodyCaptureMetadata(pointer) = (%#v, %t), want a copy of the value", fromPointer, ok)
	}
	// The result must be detached from the caller's struct.
	if fromPointer == &source {
		t.Fatal("bodyCaptureMetadata(pointer) aliased the caller's value")
	}
}

func TestBodyCaptureMetadataRejectsNilAndForeignTypes(t *testing.T) {
	if metadata, ok := bodyCaptureMetadata((*formatter.BodyCaptureMetadata)(nil)); ok || metadata != nil {
		t.Fatalf("bodyCaptureMetadata(nil pointer) = (%#v, %t), want (nil, false)", metadata, ok)
	}
	for _, value := range []any{nil, "metadata", 42, struct{}{}} {
		if metadata, ok := bodyCaptureMetadata(value); ok || metadata != nil {
			t.Fatalf("bodyCaptureMetadata(%#v) = (%#v, %t), want (nil, false)", value, metadata, ok)
		}
	}
}

// --- response writer ---

func TestResponseBodyWriterCapturesStringsWhenEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, enabled := range []bool{true, false} {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		capture := newBoundedBodyCapture(64)
		writer := responseBodyWriter{
			ResponseWriter: ctx.Writer,
			body:           capture,
			shouldCapture:  func() bool { return enabled },
		}

		if _, err := writer.WriteString("hello"); err != nil {
			t.Fatalf("WriteString() error = %v", err)
		}
		if _, err := writer.Write([]byte("-world")); err != nil {
			t.Fatalf("Write() error = %v", err)
		}

		want := ""
		if enabled {
			want = "hello-world"
		}
		if got := capture.body.String(); got != want {
			t.Fatalf("shouldCapture=%t captured = %q, want %q", enabled, got, want)
		}
		// The wrapped writer always receives the payload regardless of capture.
		if got := recorder.Body.String(); got != "hello-world" {
			t.Fatalf("response body = %q, want %q", got, "hello-world")
		}
	}
}

// --- request reader ---

func TestRequestBodyCaptureFinishFlagsIncompleteReads(t *testing.T) {
	tests := []struct {
		name          string
		payload       string
		readAll       bool
		contentLength int64
		wantTruncated bool
	}{
		{name: "fully read with known length", payload: "abcdef", readAll: true, contentLength: 6},
		{
			name: "partially read with known length", payload: "abcdef", contentLength: 6,
			wantTruncated: true,
		},
		{name: "fully read with unknown length", payload: "abcdef", readAll: true, contentLength: -1},
		{
			name: "partially read with unknown length", payload: "abcdef", contentLength: -1,
			wantTruncated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capture := newBoundedBodyCapture(64)
			reader := &requestBodyCaptureReadCloser{
				ReadCloser:    io.NopCloser(strings.NewReader(tt.payload)),
				body:          capture,
				shouldCapture: func() bool { return true },
			}

			if tt.readAll {
				if _, err := io.ReadAll(reader); err != nil {
					t.Fatalf("ReadAll() error = %v", err)
				}
			} else {
				buffer := make([]byte, 2)
				if _, err := reader.Read(buffer); err != nil {
					t.Fatalf("Read() error = %v", err)
				}
			}

			reader.finish(tt.contentLength)
			if capture.truncated != tt.wantTruncated {
				t.Fatalf("truncated = %t, want %t", capture.truncated, tt.wantTruncated)
			}
		})
	}
}

func TestRequestBodyCaptureFinishFlagsDroppedBytes(t *testing.T) {
	// Reading more bytes than the bounded buffer retained must be reported as
	// truncated even when the request body was consumed completely.
	capture := newBoundedBodyCapture(2)
	reader := &requestBodyCaptureReadCloser{
		ReadCloser:    io.NopCloser(strings.NewReader("abcdef")),
		body:          capture,
		shouldCapture: func() bool { return true },
	}
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}

	reader.finish(6)
	if !capture.truncated {
		t.Fatal("truncated = false, want true when captured bytes are dropped")
	}
	if got := capture.body.String(); got != "ab" {
		t.Fatalf("captured = %q, want %q", got, "ab")
	}
}

func TestRequestBodyCaptureSkipsWhenDisabled(t *testing.T) {
	capture := newBoundedBodyCapture(64)
	reader := &requestBodyCaptureReadCloser{
		ReadCloser:    io.NopCloser(strings.NewReader("abcdef")),
		body:          capture,
		shouldCapture: func() bool { return false },
	}
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if got := capture.body.String(); got != "" {
		t.Fatalf("captured = %q, want empty when capture is disabled", got)
	}
}
