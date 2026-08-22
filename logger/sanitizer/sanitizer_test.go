// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package sanitizer

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/PointerByte/forge-go/logger/formatter"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/spf13/viper"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Public   string `json:"public"`
}

type unsupportedLoginRequest struct {
	Password chan int `json:"password"`
}

type cyclicLoginRequest struct {
	Password string              `json:"password"`
	Next     *cyclicLoginRequest `json:"next"`
}

func TestLogFormatRedactsSensitiveKeys(t *testing.T) {
	s := New([]string{"password", "email", "phone"})
	processHeaders := http.Header{
		"X-Password": {"header-secret"},
		"X-Trace":    {`{"email":"trace@example.com"}`},
	}

	log := formatter.LogFormat{
		Message: "login failed password=message-secret token=public",
		Details: formatter.Details{
			System:  "api",
			Headers: http.Header{"X-Email": {"person@example.com"}, "X-Trace": {`{"phone":"555"}`}},
			Request: map[string]any{
				"password": "secret",
				"profile": map[string]any{
					"user_email": "person@example.com",
					"name":       "Ada",
				},
			},
			Response: `{"ok":false,"phone":"555-0100"}`,
		},
		Process: []formatter.Process{
			{
				System:   "auth",
				Headers:  &processHeaders,
				Request:  loginRequest{Email: "service@example.com", Password: "service-secret", Public: "ok"},
				Response: `{"phone":"555-0199","password":"trace-response-secret"}`,
			},
		},
	}

	got := s.LogFormat(log)
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal(sanitized log) failed: %v", err)
	}
	out := string(data)

	for _, secret := range []string{"message-secret", "person@example.com", "secret", "555-0100", "service@example.com", "service-secret", "header-secret", "trace@example.com", "555-0199", "trace-response-secret"} {
		if strings.Contains(out, secret) {
			t.Fatalf("sanitized log still contains %q: %s", secret, out)
		}
	}
	if count := strings.Count(out, RedactedValue); count < 6 {
		t.Fatalf("redaction count = %d, want at least 6 in %s", count, out)
	}
	if !strings.Contains(out, "token=public") {
		t.Fatalf("disabled key token was redacted unexpectedly: %s", out)
	}

	originalRequest := log.Details.Request.(map[string]any)
	if originalRequest["password"] != "secret" {
		t.Fatalf("original request was mutated: %#v", originalRequest)
	}
}

func TestValueSanitizesRawStrings(t *testing.T) {
	s := New([]string{"password", "email"})

	tests := []struct {
		name      string
		value     string
		notWanted []string
	}{
		{
			name:      "json string",
			value:     `{"password":"secret","profile":{"email":"person@example.com"},"ok":true}`,
			notWanted: []string{"secret", "person@example.com"},
		},
		{
			name:      "key value string",
			value:     "password=secret email=person@example.com ok=true",
			notWanted: []string{"secret", "person@example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := s.Value(tt.value).(string)
			if !ok {
				t.Fatalf("Value(%q) type = %T, want string", tt.value, got)
			}
			for _, secret := range tt.notWanted {
				if strings.Contains(got, secret) {
					t.Fatalf("sanitized string still contains %q: %s", secret, got)
				}
			}
			if !strings.Contains(got, RedactedValue) {
				t.Fatalf("sanitized string missing redaction marker: %s", got)
			}
		})
	}
}

func TestFromViper(t *testing.T) {
	viper.Reset()
	viperdata.ResetViperDataSingleton()
	t.Cleanup(func() {
		viper.Reset()
		viperdata.ResetViperDataSingleton()
	})

	viper.Set(string(viperdata.LoggerSensibleKeysAtribute), []string{"customKey"})

	s := FromViper()
	got := s.Value(map[string]any{
		"password":  "secret",
		"customKey": "secret",
		"colour":    "visible",
	}).(map[string]any)

	if got["password"] != RedactedValue {
		t.Fatalf("password = %#v, want redacted by the always-on baseline", got["password"])
	}
	if got["customKey"] != RedactedValue {
		t.Fatalf("customKey = %#v, want redacted by configuration", got["customKey"])
	}
	if got["colour"] != "visible" {
		t.Fatalf("colour = %#v, want visible", got["colour"])
	}
}

// TestCredentialKeysAreRedactedWithoutConfiguration is the security default: a
// deployment that configures nothing must still not log a token or a secret.
func TestCredentialKeysAreRedactedWithoutConfiguration(t *testing.T) {
	viper.Reset()
	viperdata.ResetViperDataSingleton()
	t.Cleanup(func() {
		viper.Reset()
		viperdata.ResetViperDataSingleton()
	})

	s := FromViper()
	if !s.Enabled() {
		t.Fatal("FromViper() produced a disabled sanitizer with no configuration")
	}

	got := s.Value(map[string]any{
		"authorization": "Bearer abc",
		"refresh_token": "rt",
		"client_secret": "cs",
		"colour":        "visible",
	}).(map[string]any)

	for _, key := range []string{"authorization", "refresh_token", "client_secret"} {
		if got[key] != RedactedValue {
			t.Errorf("%s = %#v, want redacted", key, got[key])
		}
	}
	if got["colour"] != "visible" {
		t.Errorf("colour = %#v, want visible", got["colour"])
	}
}

func TestDisabledSanitizerReturnsOriginalValue(t *testing.T) {
	s := New(nil)
	value := map[string]any{"password": "secret"}

	got := s.Value(value)
	if got == nil || got.(map[string]any)["password"] != "secret" {
		t.Fatalf("disabled sanitizer changed value: %#v", got)
	}
}

func TestSanitizerCoversCompositeValues(t *testing.T) {
	s := New([]string{"password", "email", "phone"})

	stringMap := s.Value(map[string]string{
		"password": "secret",
		"note":     "email=person@example.com",
	}).(map[string]string)
	if stringMap["password"] != RedactedValue || strings.Contains(stringMap["note"], "person@example.com") {
		t.Fatalf("map[string]string was not sanitized: %#v", stringMap)
	}

	stringSliceMap := s.Value(map[string][]string{
		"phone": {"555-0100", "555-0101"},
		"note":  {"email=person@example.com"},
	}).(map[string][]string)
	if stringSliceMap["phone"][0] != RedactedValue || strings.Contains(stringSliceMap["note"][0], "person@example.com") {
		t.Fatalf("map[string][]string was not sanitized: %#v", stringSliceMap)
	}

	values := s.Value([]any{
		map[string]any{"password": "secret"},
		"email=person@example.com",
	}).([]any)
	if values[0].(map[string]any)["password"] != RedactedValue || strings.Contains(values[1].(string), "person@example.com") {
		t.Fatalf("[]any was not sanitized: %#v", values)
	}

	stringsValue := s.Value([]string{"email=person@example.com"}).([]string)
	if strings.Contains(stringsValue[0], "person@example.com") {
		t.Fatalf("[]string was not sanitized: %#v", stringsValue)
	}

	bytesValue := s.Value([]byte(`{"password":"secret"}`)).(string)
	if strings.Contains(bytesValue, "secret") {
		t.Fatalf("[]byte json was not sanitized: %s", bytesValue)
	}
}

func TestSanitizerCoversReflectionValues(t *testing.T) {
	s := New([]string{"password", "email"})

	var nilRequest *loginRequest
	if got := s.Value(nilRequest); got != nil {
		t.Fatalf("nil pointer value = %#v, want nil", got)
	}

	pointerValue := s.Value(&loginRequest{Email: "person@example.com", Password: "secret", Public: "ok"}).(map[string]any)
	if pointerValue["email"] != RedactedValue || pointerValue["password"] != RedactedValue || pointerValue["public"] != "ok" {
		t.Fatalf("pointer struct was not sanitized: %#v", pointerValue)
	}

	mapValue := s.Value(map[int]any{7: map[string]any{"password": "secret"}}).(map[string]any)
	if mapValue["7"].(map[string]any)["password"] != RedactedValue {
		t.Fatalf("reflect map was not sanitized: %#v", mapValue)
	}

	arrayValue := s.Value([2]any{"email=person@example.com", 3}).([]any)
	if strings.Contains(arrayValue[0].(string), "person@example.com") || arrayValue[1].(int) != 3 {
		t.Fatalf("array was not sanitized: %#v", arrayValue)
	}

	if got := s.Value(42); got != 42 {
		t.Fatalf("scalar value = %#v, want 42", got)
	}

	if got := s.Value(unsupportedLoginRequest{Password: make(chan int)}); got != RedactedValue {
		t.Fatalf("unsupported struct fallback = %#v, want %q", got, RedactedValue)
	}
}

func TestSanitizerCoversGuardBranches(t *testing.T) {
	disabled := New(nil)
	details := formatter.Details{Client: "email=person@example.com"}
	if got := disabled.LogFormat(formatter.LogFormat{Message: "password=secret"}); got.Message != "password=secret" {
		t.Fatalf("disabled LogFormat changed message: %#v", got)
	}
	if got := disabled.Details(details); got.Client != details.Client {
		t.Fatalf("disabled Details changed value: %#v", got)
	}
	if got := disabled.Service(formatter.Process{Server: "email=person@example.com"}); got.Server != "email=person@example.com" {
		t.Fatalf("disabled Service changed value: %#v", got)
	}
	if got := disabled.Headers(http.Header{"Email": {"person@example.com"}}); got.Get("Email") != "person@example.com" {
		t.Fatalf("disabled Headers changed value: %#v", got)
	}

	s := New([]string{"password"})
	if got := s.Headers(nil); got != nil {
		t.Fatalf("Headers(nil) = %#v, want nil", got)
	}
	if got := s.value("", "secret", maxDepth+1); got != RedactedValue {
		t.Fatalf("max depth guard = %#v, want %q", got, RedactedValue)
	}
	if s.isSensitive("") {
		t.Fatal("empty key must not be sensitive")
	}
}

func TestSanitizerFailsClosedBeyondMaximumDepth(t *testing.T) {
	s := New([]string{"password"})
	root := map[string]any{}
	current := root
	for depth := 0; depth <= maxDepth+1; depth++ {
		next := map[string]any{}
		current["next"] = next
		current = next
	}
	current["password"] = "deep-secret"

	got := s.Value(root)
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal(sanitized deep value) error = %v", err)
	}
	if strings.Contains(string(data), "deep-secret") {
		t.Fatalf("sanitized deep value exposed a secret: %s", data)
	}
	if !strings.Contains(string(data), RedactedValue) {
		t.Fatalf("sanitized deep value lacks depth marker: %s", data)
	}
}

func TestSanitizerFailsClosedForCycles(t *testing.T) {
	s := New([]string{"password"})

	t.Run("map cycle", func(t *testing.T) {
		cycle := map[string]any{"password": "cycle-secret"}
		cycle["self"] = cycle

		got := s.Value(cycle)
		data, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("json.Marshal(sanitized map cycle) error = %v", err)
		}
		if strings.Contains(string(data), "cycle-secret") {
			t.Fatalf("sanitized map cycle exposed a secret: %s", data)
		}
		if !strings.Contains(string(data), RedactedValue) {
			t.Fatalf("sanitized map cycle lacks redaction marker: %s", data)
		}
	})

	t.Run("pointer cycle", func(t *testing.T) {
		cycle := &cyclicLoginRequest{Password: "pointer-secret"}
		cycle.Next = cycle

		got := s.Value(cycle)
		if got != RedactedValue {
			t.Fatalf("sanitized pointer cycle = %#v, want %q", got, RedactedValue)
		}
	})
}

func TestSanitizeJSONStringRejectsPartialJSON(t *testing.T) {
	s := New([]string{"password"})

	got := s.Value(`{"password":"secret"} trailing`).(string)
	if strings.Contains(got, "secret") || !strings.Contains(got, "trailing") {
		t.Fatalf("partial json string was not sanitized as raw text: %s", got)
	}
}
