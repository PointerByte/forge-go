package portable

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestManifestIsDeterministicAndDetached(t *testing.T) {
	dispatcher := DefaultDispatcher()
	first := dispatcher.ManifestJSON()
	second := dispatcher.ManifestJSON()
	if !bytes.Equal(first, second) {
		t.Fatal("manifest encoding is not deterministic")
	}

	manifest := dispatcher.Manifest()
	if manifest.Package != PackageName || manifest.Version != PackageVersion || manifest.ABI != ABIVersion {
		t.Fatalf("unexpected manifest identity: %+v", manifest)
	}
	if len(manifest.Operations) != 8 || len(manifest.Errors) != len(errorCatalog) {
		t.Fatalf("incomplete manifest: %+v", manifest)
	}
	manifest.Operations[0].Name = "mutated"
	if dispatcher.Manifest().Operations[0].Name == "mutated" {
		t.Fatal("manifest returned shared mutable state")
	}
}

func TestNewDispatcherRejectsUnsafeLimits(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxResponseBytes = minimumResponseLimit - 1
	if _, err := NewDispatcher(limits); err == nil || err.Code != ErrorInvalidRequest {
		t.Fatalf("expected invalid limits error, got %v", err)
	}

	limits = DefaultLimits()
	limits.MaxBinaryBytes = limits.MaxRequestBytes + 1
	if _, err := NewDispatcher(limits); err == nil || err.Code != ErrorInvalidRequest {
		t.Fatalf("expected inconsistent limits error, got %v", err)
	}

	limits = DefaultLimits()
	limits.MaxBinaryBytes = minimumBinaryLimit - 1
	if _, err := NewDispatcher(limits); err == nil || err.Code != ErrorInvalidRequest {
		t.Fatalf("expected unusable binary limit error, got %v", err)
	}
}

func TestStrictJSONFailures(t *testing.T) {
	tests := []struct {
		name    string
		request []byte
		code    ErrorCode
	}{
		{"malformed", []byte(`{"abi":`), ErrorInvalidJSON},
		{"root-array", []byte(`[]`), ErrorInvalidJSON},
		{"trailing-value", []byte(`{"abi":"goforge.abi.v1"} {}`), ErrorInvalidJSON},
		{"invalid-utf8", []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}, ErrorInvalidUTF8},
		{"unknown-envelope-field", []byte(`{"abi":"goforge.abi.v1","id":"x","operation":"crypto.sha256","payload":{"data":""},"extra":true}`), ErrorUnknownField},
		{"duplicate-envelope-field", []byte(`{"abi":"goforge.abi.v1","id":"x","id":"y","operation":"crypto.sha256","payload":{"data":""}}`), ErrorDuplicateField},
		{"duplicate-payload-field", []byte(`{"abi":"goforge.abi.v1","id":"x","operation":"crypto.sha256","payload":{"data":"","data":"YWJj"}}`), ErrorDuplicateField},
		{"unknown-payload-field", []byte(`{"abi":"goforge.abi.v1","id":"x","operation":"crypto.sha256","payload":{"data":"","extra":true}}`), ErrorUnknownField},
		{"missing-payload", []byte(`{"abi":"goforge.abi.v1","id":"x","operation":"crypto.sha256"}`), ErrorInvalidRequest},
		{"null-payload", []byte(`{"abi":"goforge.abi.v1","id":"x","operation":"crypto.sha256","payload":null}`), ErrorInvalidJSON},
		{"invalid-abi", []byte(`{"abi":"v0","id":"x","operation":"crypto.sha256","payload":{"data":""}}`), ErrorInvalidABI},
		{"unknown-operation", []byte(`{"abi":"goforge.abi.v1","id":"x","operation":"unknown","payload":{}}`), ErrorUnknownOperation},
		{"control-in-id", []byte("{\"abi\":\"goforge.abi.v1\",\"id\":\"x\\n\",\"operation\":\"crypto.sha256\",\"payload\":{\"data\":\"\"}}"), ErrorInvalidRequest},
	}

	dispatcher := DefaultDispatcher()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertErrorCode(t, dispatcher.DispatchJSON(test.request, ExecutionState{}), test.code)
		})
	}
}

func TestCanonicalBase64Failures(t *testing.T) {
	tests := []string{
		"aGVsbG8",
		"aGVs\nbG8=",
		"____",
		"aGVsbG8==",
	}
	for _, encoded := range tests {
		t.Run(encoded, func(t *testing.T) {
			request := makeRequest(t, OperationBase64Decode, map[string]any{"encoded": encoded}, nil)
			assertErrorCode(t, DefaultDispatcher().DispatchJSON(request, ExecutionState{}), ErrorInvalidBase64)
		})
	}
}

func TestRequestAndResponseBounds(t *testing.T) {
	dispatcher := DefaultDispatcher()
	oversized := bytes.Repeat([]byte{'x'}, DefaultLimits().MaxRequestBytes+1)
	assertErrorCode(t, dispatcher.DispatchJSON(oversized, ExecutionState{}), ErrorRequestTooLarge)

	limits := Limits{
		MaxRequestBytes:           4096,
		MaxResponseBytes:          minimumResponseLimit,
		MaxBinaryBytes:            1024,
		MaxStringBytes:            1024,
		MaxIDBytes:                32,
		MaxCancellationTokenBytes: 32,
		MaxRequiredCapabilities:   8,
		MaxJSONDepth:              8,
	}
	small, err := NewDispatcher(limits)
	if err != nil {
		t.Fatal(err)
	}
	request := makeRequest(t, OperationBase64Encode, map[string]any{"text": strings.Repeat("a", 400)}, nil)
	assertErrorCode(t, small.DispatchJSON(request, ExecutionState{}), ErrorResponseTooLarge)
}

func TestExecutionControlsFailClosed(t *testing.T) {
	deadline := int64(2_000)
	basePayload := map[string]any{"data": "YWJj"}

	tests := []struct {
		name     string
		metadata *RequestMetadata
		state    ExecutionState
		code     ErrorCode
	}{
		{"deadline-not-checked", &RequestMetadata{DeadlineUnixMilliseconds: &deadline}, ExecutionState{}, ErrorExecutionStateRequired},
		{"deadline-expired", &RequestMetadata{DeadlineUnixMilliseconds: &deadline}, ExecutionState{ClockChecked: true, NowUnixMilliseconds: deadline}, ErrorDeadlineExceeded},
		{"cancellation-not-checked", &RequestMetadata{CancellationToken: "token-1"}, ExecutionState{}, ErrorExecutionStateRequired},
		{"cancellation-token-mismatch", &RequestMetadata{CancellationToken: "token-1"}, ExecutionState{CancellationChecked: true, CancellationToken: "token-2"}, ErrorExecutionStateRequired},
		{"cancelled", &RequestMetadata{CancellationToken: "token-1"}, ExecutionState{CancellationChecked: true, CancellationToken: "token-1", CancellationRequested: true}, ErrorCancellationRequested},
		{"unsupported-capability", &RequestMetadata{RequiredCapabilities: []string{"host.network"}}, ExecutionState{}, ErrorCapabilityUnavailable},
		{"malformed-capability", &RequestMetadata{RequiredCapabilities: []string{"HOST"}}, ExecutionState{}, ErrorInvalidRequest},
		{"duplicate-capability", &RequestMetadata{RequiredCapabilities: []string{"crypto.sha256", "crypto.sha256"}}, ExecutionState{}, ErrorInvalidRequest},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := makeRequest(t, OperationSHA256, basePayload, test.metadata)
			assertErrorCode(t, DefaultDispatcher().DispatchJSON(request, test.state), test.code)
		})
	}

	metadata := &RequestMetadata{
		DeadlineUnixMilliseconds: &deadline,
		CancellationToken:        "token-1",
		RequiredCapabilities:     []string{"crypto.sha256", "control.deadline", "control.cancellation"},
	}
	state := ExecutionState{
		ClockChecked:          true,
		NowUnixMilliseconds:   deadline - 1,
		CancellationChecked:   true,
		CancellationToken:     "token-1",
		CancellationRequested: false,
	}
	response := decodeResponse(t, DefaultDispatcher().DispatchJSON(makeRequest(t, OperationSHA256, basePayload, metadata), state))
	if !response.OK {
		t.Fatalf("valid execution controls failed: %+v", response.Error)
	}
}

func makeRequest(t *testing.T, operation Operation, payload any, metadata *RequestMetadata) []byte {
	t.Helper()
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{
		ABI:       ABIVersion,
		ID:        "test-request",
		Operation: operation,
		Metadata:  metadata,
		Payload:   encodedPayload,
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func decodeResponse(t *testing.T, encoded []byte) Response {
	t.Helper()
	if !json.Valid(encoded) {
		t.Fatalf("dispatcher emitted invalid JSON: %q", encoded)
	}
	var response Response
	if err := json.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func assertErrorCode(t *testing.T, encoded []byte, code ErrorCode) {
	t.Helper()
	response := decodeResponse(t, encoded)
	if response.OK || response.Error == nil || response.Error.Code != code {
		t.Fatalf("expected %q, got %s", code, encoded)
	}
	if response.Result != nil {
		t.Fatalf("error response contains a result: %s", encoded)
	}
}
