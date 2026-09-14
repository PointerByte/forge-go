// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"go.opentelemetry.io/otel/trace"
)

type LogFormat struct {
	Level      Level          `json:"level"`
	Timestamp  string         `json:"timestamp"`
	TraceID    string         `json:"traceID,omitempty"`
	SpanID     string         `json:"spanID,omitempty"`
	Message    string         `json:"message"`
	Details    Details        `json:"details"`
	Process    []Process      `json:"process,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Method     string         `json:"method"`
	Line       int            `json:"line"`
	Latency    int64          `json:"latency"`
}

// NewLogFormat creates a log payload with the process collection initialized.
func NewLogFormat() LogFormat {
	return LogFormat{Process: make([]Process, 0)}
}

// Normalize returns a log payload safe for serialization.
func (l LogFormat) Normalize() LogFormat {
	if l.Process == nil {
		l.Process = make([]Process, 0)
	}
	return l
}

// MarshalJSON normalizes the payload before direct serialization.
func (l LogFormat) MarshalJSON() ([]byte, error) {
	type logFormatAlias LogFormat
	return json.Marshal(logFormatAlias(l.Normalize()))
}

type Details struct {
	System          string               `json:"system"`
	Client          string               `json:"client,omitempty"`
	Protocol        string               `json:"protocol,omitempty"`
	Method          string               `json:"method,omitempty"`
	Path            string               `json:"path,omitempty"`
	Headers         http.Header          `json:"headers,omitempty"`
	Request         any                  `json:"request,omitempty"`
	Response        any                  `json:"response,omitempty"`
	RequestCapture  *BodyCaptureMetadata `json:"requestCapture,omitempty"`
	ResponseCapture *BodyCaptureMetadata `json:"responseCapture,omitempty"`
}

// BodyCaptureMetadata describes an opt-in request or response body that could
// not be retained completely within logger.bodyCaptureMaxBytes.
type BodyCaptureMetadata struct {
	Truncated     bool `json:"truncated"`
	CapturedBytes int  `json:"capturedBytes"`
	LimitBytes    int  `json:"limitBytes"`
}

var mux sync.Mutex

func (k *Details) SetHeaders(headers http.Header) {
	if headers == nil {
		return
	}
	mux.Lock()
	defer mux.Unlock()

	if k.Headers == nil {
		k.Headers = make(http.Header, len(headers))
	}
	for key, vv := range headers {
		if viperdata.IsIgnoredHeader(key) {
			continue
		}
		vvCopy := make([]string, len(vv))
		copy(vvCopy, vv)
		k.Headers[key] = vvCopy
	}
}

func (k *Details) SetRequest(request any) {
	k.Request = request
}

func (k *Details) SetResponse(response any) {
	k.Response = response
}

type Process struct {
	TraceID string `json:"traceID,omitempty"`
	SpanID  string `json:"spanID,omitempty"`
	System  string `json:"system"`
	Process string `json:"process"`

	Server   string       `json:"server,omitempty"`
	Headers  *http.Header `json:"headers,omitempty"`
	Protocol string       `json:"protocol,omitempty"`
	Method   string       `json:"method,omitempty"`
	Code     int64        `json:"code,omitempty"`
	Path     string       `json:"path,omitempty"`

	DisableBody bool `json:"-"`

	Request         any                  `json:"request,omitempty"`
	Response        any                  `json:"response,omitempty"`
	ResponseCapture *BodyCaptureMetadata `json:"responseCapture,omitempty"`
	Status          Status               `json:"status"`
	Latency         int64                `json:"latency"`

	TimeInit time.Time  `json:"-"`
	Span     trace.Span `json:"-"`
}

func (s *Process) SetStatus(status Status) {
	s.Status = status
}

func (s *Process) SetRequest(request any) {
	s.Request = request
}

func (s *Process) SetResponse(response any) {
	s.Response = response
}
