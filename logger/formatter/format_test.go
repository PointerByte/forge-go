// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/spf13/viper"
)

func TestNew(t *testing.T) {
	f := New("json")
	if f == nil {
		t.Fatal("New() returned nil")
	}
	if f.Template != "json" {
		t.Fatalf("New() template = %q, want %q", f.Template, "json")
	}
}

func TestLogFormatMarshalJSONOmitsEmptyProcess(t *testing.T) {
	got, err := json.Marshal(LogFormat{Message: "no child traces"})
	if err != nil {
		t.Fatalf("json.Marshal(LogFormat) error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, exists := decoded["process"]; exists {
		t.Fatalf("process must be omitted when empty: %s", got)
	}
}

func TestFormatIncludesAttributesAndBodyCaptureMetadata(t *testing.T) {
	log := LogFormat{
		Message: "bounded",
		Details: Details{
			System:          "api",
			Request:         "prefix",
			RequestCapture:  &BodyCaptureMetadata{Truncated: true, CapturedBytes: 6, LimitBytes: 6},
			ResponseCapture: &BodyCaptureMetadata{Truncated: true, CapturedBytes: 0, LimitBytes: 6},
		},
		Attributes: map[string]any{
			"request": map[string]any{"attempt": 2},
		},
	}

	output, err := New("json").Format(log)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(output, &decoded); err != nil {
		t.Fatalf("output is invalid JSON: %v", err)
	}
	if _, ok := decoded["attributes"].(map[string]any); !ok {
		t.Fatalf("attributes = %T, want object", decoded["attributes"])
	}
	details, ok := decoded["details"].(map[string]any)
	if !ok {
		t.Fatalf("details = %T, want object", decoded["details"])
	}
	for _, key := range []string{"requestCapture", "responseCapture"} {
		metadata, ok := details[key].(map[string]any)
		if !ok || metadata["truncated"] != true || metadata["limitBytes"] != float64(6) {
			t.Fatalf("%s = %#v, want truncation metadata", key, details[key])
		}
	}
}

func TestCustomFormatter_Format(t *testing.T) {
	baseLog := LogFormat{
		Timestamp: "2026-03-13T01:10:23.123",
		TraceID:   "8f3a5d9c-9f2a-4e1d-b3a7-7f23d9a1e4aa",
		Message:   "Request processed successfully",
		Method:    "ProcessPayment",
		Line:      142,
		Latency:   155,
	}

	jsonExpected := []byte(`{"timestamp":"2026-03-13T01:10:23.123","traceID":"8f3a5d9c-9f2a-4e1d-b3a7-7f23d9a1e4aa","level":"","message":"Request processed successfully","details":{"system":""},"method":"ProcessPayment","line":142,"latency":155}`)

	textExpectedWithTime := fmt.Appendf(nil,
		"[%s] [%v] [%s] %s:%d - %s latency=%dms",
		baseLog.Timestamp,
		baseLog.Level,
		baseLog.TraceID,
		baseLog.Method,
		baseLog.Line,
		baseLog.Message,
		baseLog.Latency,
	)

	noTimeLog := LogFormat{
		Timestamp: "2026-03-13T01:10:23.123",
		TraceID:   "trace-no-time",
		Message:   "no time log",
		Method:    "NoTimeMethod",
		Line:      10,
		Latency:   0,
	}

	textExpectedNoTime := fmt.Appendf(nil,
		"[%s] [%v] [%s] %s:%d - %s",
		noTimeLog.Timestamp,
		noTimeLog.Level,
		noTimeLog.TraceID,
		noTimeLog.Method,
		noTimeLog.Line,
		noTimeLog.Message,
	)

	templateJSONExpected, err := json.Marshal(baseLog)
	if err != nil {
		t.Fatalf("json.Marshal(baseLog) for template failed: %v", err)
	}

	tests := []struct {
		name     string
		template string
		log      LogFormat
		want     []byte
		wantJSON bool
		wantErr  bool
	}{
		{
			name:     "format json",
			template: "json",
			log:      baseLog,
			want:     jsonExpected,
			wantJSON: true,
			wantErr:  false,
		},
		{
			name:     "format text",
			template: "text",
			log:      baseLog,
			want:     textExpectedWithTime,
			wantErr:  false,
		},
		{
			name:     "format txt alias",
			template: "txt",
			log:      baseLog,
			want:     textExpectedWithTime,
			wantErr:  false,
		},
		{
			name:     "format empty template defaults to text",
			template: "",
			log:      noTimeLog,
			want:     textExpectedNoTime,
			wantErr:  false,
		},
		{
			name:     "format trimmed template defaults to json",
			template: "  json  ",
			log:      baseLog,
			want:     jsonExpected,
			wantJSON: true,
			wantErr:  false,
		},
		{
			name:     "format custom template success",
			template: `{{.Message}}|{{.Method}}|{{.Line}}|{{json .}}`,
			log:      baseLog,
			want: append(
				fmt.Appendf(nil, "%s|%s|%d|", baseLog.Message, baseLog.Method, baseLog.Line),
				templateJSONExpected...,
			),
			wantErr: false,
		},
		{
			name:     "format custom template parse error",
			template: `{{if}`,
			log:      baseLog,
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "format custom template execute error",
			template: `{{range .Date}}{{.}}{{end}}`,
			log:      baseLog,
			want:     nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := New(tt.template)

			got, gotErr := f.Format(tt.log)
			if gotErr != nil {
				if !tt.wantErr {
					t.Fatalf("Format() failed: %v", gotErr)
				}
				return
			}

			if tt.wantErr {
				t.Fatal("Format() succeeded unexpectedly")
			}

			if tt.wantJSON {
				assertJSONEqual(t, got, tt.want)
				return
			}

			if !bytes.Equal(got, tt.want) {
				t.Errorf("Format() = %s, want %s", string(got), string(tt.want))
			}
		})
	}
}

func assertJSONEqual(t *testing.T, got []byte, want []byte) {
	t.Helper()

	var gotValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("Format() returned invalid JSON %s: %v", string(got), err)
	}

	var wantValue any
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("test expected invalid JSON %s: %v", string(want), err)
	}

	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Errorf("Format() = %s, want JSON-equivalent %s", string(got), string(want))
	}
}

func TestFormatJSONAndFormatTemplateDirect(t *testing.T) {
	log := LogFormat{
		Timestamp: "ts",
		TraceID:   "id",
		Level:     ErrorLevel,
		Message:   "msg",
		Method:    "Fn",
		Line:      7,
		Latency:   1,
		Details: Details{
			System: "svc",
		},
	}

	f := New("json")
	got, err := f.FormatJSON(log)
	if err != nil {
		t.Fatalf("FormatJSON() failed: %v", err)
	}
	if !json.Valid(got) {
		t.Fatalf("FormatJSON() returned invalid json: %s", string(got))
	}

	f.Template = `{{json .}}`
	got, err = f.FormatTemplate(log)
	if err != nil {
		t.Fatalf("FormatTemplate() failed: %v", err)
	}
	if !json.Valid(got) {
		t.Fatalf("FormatTemplate() returned invalid json: %s", string(got))
	}
}

func TestExecuteTemplate_TrimSpace(t *testing.T) {
	f := New("")
	got, err := f.executeTemplate("  {{.Message}}  ", LogFormat{Message: "hello"})
	if err != nil {
		t.Fatalf("executeTemplate() failed: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("executeTemplate() = %q, want %q", string(got), "hello")
	}
}

func TestFormatText_WithDetailsAndServices(t *testing.T) {
	log := LogFormat{
		Timestamp: "2026-03-13T01:10:23.123",
		TraceID:   "trace-text",
		Level:     DebugLevel,
		Message:   "detailed log",
		Method:    "DetailedMethod",
		Line:      99,
		Latency:   321,
		Details: Details{
			System:   "loan-service",
			Client:   "mobile-app",
			Protocol: "HTTP",
			Method:   "POST",
			Path:     "/loan/simulate",
			Headers:  http.Header{"Content-Type": {"application/json"}},
			Request:  map[string]any{"amount": 100},
			Response: map[string]any{"ok": true},
		},
		Process: []Process{
			{
				TraceID:  "sat-001",
				SpanID:   "span-001",
				System:   "auth-service",
				Process:  "validate-token",
				Server:   "auth.internal",
				Protocol: "HTTP",
				Method:   "POST",
				Path:     "/auth/validate",
				Code:     200,
				Request:  map[string]any{"token": "abc"},
				Response: map[string]any{"valid": true},
				ResponseCapture: &BodyCaptureMetadata{
					Truncated:     true,
					CapturedBytes: 1024,
					LimitBytes:    1024,
				},
				Status:  SUCCESS,
				Latency: 12,
			},
			{
				System:  "score-engine",
				Process: "calculate-score",
				Status:  ERROR,
			},
		},
	}

	got, err := New("text").FormatText(log)
	if err != nil {
		t.Fatalf("FormatText() failed: %v", err)
	}

	out := string(got)

	mustContain := []string{
		"[2026-03-13T01:10:23.123] [DEBUG] [trace-text] DetailedMethod:99 - detailed log latency=321ms",
		"details={",
		"system=loan-service",
		"client=mobile-app",
		"protocol=HTTP",
		"method=POST",
		"path=/loan/simulate",
		`headers={"Content-Type":["application/json"]}`,
		`request={"amount":100}`,
		`response={"ok":true}`,
		"services=[",
		"traceID=sat-001",
		"spanID=span-001",
		"system=auth-service",
		"process=validate-token",
		"server=auth.internal",
		"code=200",
		`request={"token":"abc"}`,
		`response={"valid":true}`,
		`responseCapture={"truncated":true,"capturedBytes":1024,"limitBytes":1024}`,
		"status=SUCCESS",
		"latency=12ms",
		"system=score-engine",
		"process=calculate-score",
		"status=ERROR",
	}
	for _, part := range mustContain {
		if !strings.Contains(out, part) {
			t.Fatalf("FormatText() output missing %q in %q", part, out)
		}
	}
}

type badJSON struct{}

func (badJSON) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("boom")
}

func TestToJSON(t *testing.T) {
	t.Run("nil returns empty string", func(t *testing.T) {
		if got := toJSON(nil); got != "" {
			t.Fatalf("toJSON(nil) = %q, want empty string", got)
		}
	})

	t.Run("valid value returns json", func(t *testing.T) {
		got := toJSON(map[string]any{"a": 1})
		if got != `{"a":1}` {
			t.Fatalf("toJSON(valid) = %q, want %q", got, `{"a":1}`)
		}
	})

	t.Run("marshal error falls back to fmt", func(t *testing.T) {
		got := toJSON(badJSON{})
		if got != "{}" {
			t.Fatalf("toJSON(badJSON) = %q, want %q", got, "{}")
		}
	})
}

func TestDetails_SetHeaders(t *testing.T) {
	t.Run("nil headers does nothing", func(t *testing.T) {
		viperdata.ResetViperDataSingleton()
		viper.Reset()
		t.Cleanup(func() {
			viper.Reset()
			viperdata.ResetViperDataSingleton()
		})

		k := &Details{}
		k.SetHeaders(nil)

		if k.Headers != nil {
			t.Fatalf("Headers = %#v, want nil", k.Headers)
		}
	})

	t.Run("copies headers, ignores configured ones, and performs deep copy", func(t *testing.T) {
		viperdata.ResetViperDataSingleton()
		viper.Reset()
		t.Cleanup(func() {
			viper.Reset()
			viperdata.ResetViperDataSingleton()
		})

		viper.Set(string(viperdata.LoggerIgnoredHeadersAtribute), []string{
			"authorization",
			"cookie",
		})

		src := http.Header{
			"Content-Type":          {"application/json"},
			"X-Trace-Id":            {"abc-123", "def-456"},
			"Authorization":         {"Bearer secret"},
			"Cookie":                {"session=123"},
			"X-Authorization-Token": {"kept"},
		}

		k := &Details{}
		k.SetHeaders(src)

		if k.Headers == nil {
			t.Fatal("Headers is nil, want initialized header map")
		}

		if got := k.Headers.Get("Content-Type"); got != "application/json" {
			t.Fatalf("Content-Type = %q, want %q", got, "application/json")
		}

		if got := k.Headers.Values("X-Trace-Id"); !reflect.DeepEqual(got, []string{"abc-123", "def-456"}) {
			t.Fatalf("X-Trace-Id = %#v, want %#v", got, []string{"abc-123", "def-456"})
		}

		if got := k.Headers.Get("Authorization"); got != "" {
			t.Fatalf("Authorization = %q, want empty because it must be ignored", got)
		}

		if got := k.Headers.Get("Cookie"); got != "" {
			t.Fatalf("Cookie = %q, want empty because it must be ignored", got)
		}

		if got := k.Headers.Get("X-Authorization-Token"); got != "kept" {
			t.Fatalf("X-Authorization-Token = %q, want %q", got, "kept")
		}

		src["Content-Type"][0] = "text/plain"
		src["X-Trace-Id"][0] = "mutated"

		if got := k.Headers.Get("Content-Type"); got != "application/json" {
			t.Fatalf("after source mutation, Content-Type = %q, want %q", got, "application/json")
		}

		if got := k.Headers.Values("X-Trace-Id"); !reflect.DeepEqual(got, []string{"abc-123", "def-456"}) {
			t.Fatalf("after source mutation, X-Trace-Id = %#v, want %#v", got, []string{"abc-123", "def-456"})
		}
	})

	t.Run("reuses existing header map when already initialized", func(t *testing.T) {
		viperdata.ResetViperDataSingleton()
		viper.Reset()
		t.Cleanup(func() {
			viper.Reset()
			viperdata.ResetViperDataSingleton()
		})

		viper.Set(string(viperdata.LoggerIgnoredHeadersAtribute), []string{"Authorization"})

		existing := make(http.Header)
		existing.Set("Already", "present")

		k := &Details{
			Headers: existing,
		}

		src := http.Header{
			"X-Test":        {"ok"},
			"Authorization": {"secret"},
		}

		k.SetHeaders(src)

		if k.Headers == nil {
			t.Fatal("Headers is nil, want existing map reused")
		}

		if got := k.Headers.Get("Already"); got != "present" {
			t.Fatalf("Already = %q, want %q", got, "present")
		}

		if got := k.Headers.Get("X-Test"); got != "ok" {
			t.Fatalf("X-Test = %q, want %q", got, "ok")
		}

		if got := k.Headers.Get("Authorization"); got != "" {
			t.Fatalf("Authorization = %q, want empty because it must be ignored", got)
		}
	})
}

func TestDetails_SetRequest(t *testing.T) {
	k := &Details{}

	req := map[string]any{
		"id":      123,
		"message": "hello",
	}

	k.SetRequest(req)

	if !reflect.DeepEqual(k.Request, req) {
		t.Fatalf("Request = %#v, want %#v", k.Request, req)
	}
}

func TestDetails_SetResponse(t *testing.T) {
	k := &Details{}

	resp := struct {
		Code int
		OK   bool
	}{
		Code: 200,
		OK:   true,
	}

	k.SetResponse(resp)

	if !reflect.DeepEqual(k.Response, resp) {
		t.Fatalf("Response = %#v, want %#v", k.Response, resp)
	}
}

func TestProcess_SetStatus(t *testing.T) {
	s := &Process{}

	s.SetStatus(ERROR)

	if s.Status != ERROR {
		t.Fatalf("Status = %v, want %v", s.Status, ERROR)
	}
}

func TestProcess_SetRequest(t *testing.T) {
	s := &Process{}

	req := map[string]any{
		"id":      123,
		"message": "hello",
	}
	s.SetRequest(req)

	if !reflect.DeepEqual(s.Request, req) {
		t.Fatalf("Request = %#v, want %#v", s.Request, req)
	}
}

func TestProcess_SetResponse(t *testing.T) {
	s := &Process{}

	resp := struct {
		Code int
		OK   bool
	}{
		Code: 200,
		OK:   true,
	}
	s.SetResponse(resp)

	if !reflect.DeepEqual(s.Response, resp) {
		t.Fatalf("Response = %#v, want %#v", s.Response, resp)
	}
}

func TestBuildDetails(t *testing.T) {
	t.Run("all fields", func(t *testing.T) {
		headers := http.Header{
			"Content-Type": {"application/json"},
		}
		req := map[string]any{"amount": 100}
		resp := map[string]any{"ok": true}

		got := buildDetails(Details{
			System:   "loan-service",
			Client:   "mobile-app",
			Protocol: "HTTP",
			Method:   "POST",
			Path:     "/loan/simulate",
			Headers:  headers,
			Request:  req,
			Response: resp,
		})

		want := map[string]any{
			"system":   "loan-service",
			"client":   "mobile-app",
			"protocol": "HTTP",
			"method":   "POST",
			"path":     "/loan/simulate",
			"headers":  headers,
			"request":  req,
			"response": resp,
		}

		if !reflect.DeepEqual(got, want) {
			t.Fatalf("buildDetails() = %#v, want %#v", got, want)
		}
	})

	t.Run("only required system", func(t *testing.T) {
		got := buildDetails(Details{
			System: "loan-service",
		})

		want := map[string]any{
			"system": "loan-service",
		}

		if !reflect.DeepEqual(got, want) {
			t.Fatalf("buildDetails() = %#v, want %#v", got, want)
		}
	})

	t.Run("empty headers and nil request response are omitted", func(t *testing.T) {
		got := buildDetails(Details{
			System:  "loan-service",
			Headers: http.Header{},
		})

		want := map[string]any{
			"system": "loan-service",
		}

		if !reflect.DeepEqual(got, want) {
			t.Fatalf("buildDetails() = %#v, want %#v", got, want)
		}
	})
}

func TestBuildServices(t *testing.T) {
	t.Run("all fields", func(t *testing.T) {
		req := map[string]any{"token": "abc"}
		resp := map[string]any{"valid": true}
		responseCapture := &BodyCaptureMetadata{Truncated: true, CapturedBytes: 1024, LimitBytes: 1024}

		got := buildServices([]Process{
			{
				TraceID:         "sat-001",
				SpanID:          "span-001",
				System:          "auth-service",
				Process:         "validate-token",
				Server:          "auth.internal",
				Protocol:        "HTTP",
				Method:          "POST",
				Path:            "/auth/validate",
				Code:            200,
				Request:         req,
				Response:        resp,
				ResponseCapture: responseCapture,
				Status:          SUCCESS,
				Latency:         12,
			},
		})

		want := []map[string]any{
			{
				"traceID":         "sat-001",
				"spanID":          "span-001",
				"system":          "auth-service",
				"process":         "validate-token",
				"server":          "auth.internal",
				"protocol":        "HTTP",
				"method":          "POST",
				"path":            "/auth/validate",
				"code":            int64(200),
				"request":         req,
				"response":        resp,
				"responseCapture": responseCapture,
				"status":          SUCCESS,
				"latency":         int64(12),
			},
		}

		if !reflect.DeepEqual(got, want) {
			t.Fatalf("buildServices() = %#v, want %#v", got, want)
		}
	})

	t.Run("empty service produces empty map", func(t *testing.T) {
		got := buildServices([]Process{{}})

		want := []map[string]any{{}}

		if !reflect.DeepEqual(got, want) {
			t.Fatalf("buildServices() = %#v, want %#v", got, want)
		}
	})

	t.Run("zero values are omitted", func(t *testing.T) {
		got := buildServices([]Process{
			{
				System: "score-engine",
			},
		})

		want := []map[string]any{
			{
				"system": "score-engine",
			},
		}

		if !reflect.DeepEqual(got, want) {
			t.Fatalf("buildServices() = %#v, want %#v", got, want)
		}
	})

	t.Run("multiple services", func(t *testing.T) {
		got := buildServices([]Process{
			{
				TraceID: "sat-001",
				SpanID:  "span-001",
				System:  "auth-service",
			},
			{
				TraceID: "sat-002",
				SpanID:  "span-002",
				System:  "score-engine",
			},
		})

		want := []map[string]any{
			{
				"traceID": "sat-001",
				"spanID":  "span-001",
				"system":  "auth-service",
			},
			{
				"traceID": "sat-002",
				"spanID":  "span-002",
				"system":  "score-engine",
			},
		}

		if !reflect.DeepEqual(got, want) {
			t.Fatalf("buildServices() = %#v, want %#v", got, want)
		}
	})
}
