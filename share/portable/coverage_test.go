package portable

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestOperationInputFailures(t *testing.T) {
	dispatcher := DefaultDispatcher()
	oversizedString := strings.Repeat("x", DefaultLimits().MaxStringBytes+1)
	oversizedBinary := base64.StdEncoding.EncodeToString(make([]byte, DefaultLimits().MaxBinaryBytes+1))
	tests := []struct {
		name      string
		operation Operation
		payload   map[string]any
		code      ErrorCode
	}{
		{"normalize-missing-value", OperationNormalize, map[string]any{"trim": true}, ErrorInvalidRequest},
		{"normalize-oversized", OperationNormalize, map[string]any{"value": oversizedString}, ErrorInputTooLarge},
		{"validate-missing-rules", OperationValidate, map[string]any{"value": "x"}, ErrorInvalidRequest},
		{"validate-oversized", OperationValidate, map[string]any{"value": oversizedString, "rules": map[string]any{}}, ErrorInputTooLarge},
		{"base64-encode-missing", OperationBase64Encode, map[string]any{}, ErrorInvalidRequest},
		{"base64-encode-oversized", OperationBase64Encode, map[string]any{"text": oversizedString}, ErrorInputTooLarge},
		{"base64-decode-missing", OperationBase64Decode, map[string]any{}, ErrorInvalidRequest},
		{"sha-missing", OperationSHA256, map[string]any{}, ErrorInvalidRequest},
		{"sha-invalid-base64", OperationSHA256, map[string]any{"data": "!"}, ErrorInvalidBase64},
		{"sha-oversized", OperationSHA256, map[string]any{"data": oversizedBinary}, ErrorInputTooLarge},
		{"hmac-missing-data", OperationHMACSHA256, map[string]any{"key": "AAAAAAAAAAAAAAAAAAAAAA=="}, ErrorInvalidRequest},
		{"hmac-invalid-data", OperationHMACSHA256, map[string]any{"key": "AAAAAAAAAAAAAAAAAAAAAA==", "data": "!"}, ErrorInvalidBase64},
		{"aes-invalid-key-base64", OperationAESGCMEncrypt, aesPayload("!", "AAAAAAAAAAAAAAAA", "", ""), ErrorInvalidBase64},
		{"aes-invalid-nonce-base64", OperationAESGCMEncrypt, aesPayload("AAAAAAAAAAAAAAAAAAAAAA==", "!", "", ""), ErrorInvalidBase64},
		{"aes-invalid-aad-base64", OperationAESGCMEncrypt, aesPayload("AAAAAAAAAAAAAAAAAAAAAA==", "AAAAAAAAAAAAAAAA", "!", ""), ErrorInvalidBase64},
		{"aes-invalid-plaintext-base64", OperationAESGCMEncrypt, aesPayload("AAAAAAAAAAAAAAAAAAAAAA==", "AAAAAAAAAAAAAAAA", "", "!"), ErrorInvalidBase64},
		{"aes-decrypt-invalid-aad", OperationAESGCMDecrypt, map[string]any{"key": "AAAAAAAAAAAAAAAAAAAAAA==", "nonce": "AAAAAAAAAAAAAAAA", "aad": "!", "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA=="}, ErrorInvalidBase64},
		{"aes-decrypt-invalid-ciphertext", OperationAESGCMDecrypt, map[string]any{"key": "AAAAAAAAAAAAAAAAAAAAAA==", "nonce": "AAAAAAAAAAAAAAAA", "aad": "", "ciphertext": "!"}, ErrorInvalidBase64},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := makeRequest(t, test.operation, test.payload, nil)
			assertErrorCode(t, dispatcher.DispatchJSON(request, ExecutionState{}), test.code)
		})
	}
}

func TestAllValidationViolationKinds(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		rules    map[string]any
		expected []string
	}{
		{
			name:  "empty",
			value: "",
			rules: map[string]any{
				"required": true, "min_bytes": 1, "min_runes": 1, "prefix": "x", "suffix": "y",
			},
			expected: []string{"required", "min_bytes", "min_runes", "prefix", "suffix"},
		},
		{
			name:  "non-ascii-control-whitespace-and-maximums",
			value: "é \n",
			rules: map[string]any{
				"ascii": true, "forbid_control": true, "forbid_whitespace": true,
				"max_bytes": 2, "max_runes": 2, "prefix": "x", "suffix": "z",
			},
			expected: []string{"max_bytes", "max_runes", "ascii", "control", "whitespace", "prefix", "suffix"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := makeRequest(t, OperationValidate, map[string]any{"value": test.value, "rules": test.rules}, nil)
			response := decodeResponse(t, DefaultDispatcher().DispatchJSON(request, ExecutionState{}))
			if !response.OK {
				t.Fatalf("validation operation failed: %v", response.Error)
			}
			var result validateResult
			if err := json.Unmarshal(response.Result, &result); err != nil {
				t.Fatal(err)
			}
			actual := make([]string, len(result.Violations))
			for index, violation := range result.Violations {
				actual[index] = violation.Code
			}
			if strings.Join(actual, ",") != strings.Join(test.expected, ",") {
				t.Fatalf("violations mismatch: %v != %v", actual, test.expected)
			}
		})
	}
}

func TestAdditionalEnvelopeAndControlFailures(t *testing.T) {
	dispatcher := DefaultDispatcher()
	request := makeRequest(t, OperationSHA256, map[string]any{"data": ""}, nil)
	var decoded Request
	if err := json.Unmarshal(request, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded.ID = strings.Repeat("x", DefaultLimits().MaxIDBytes+1)
	assertDecodedError(t, dispatcher.Dispatch(decoded, ExecutionState{}), ErrorInvalidRequest)

	zero := int64(0)
	decoded.ID = "control"
	decoded.Metadata = &RequestMetadata{DeadlineUnixMilliseconds: &zero}
	assertDecodedError(t, dispatcher.Dispatch(decoded, ExecutionState{}), ErrorInvalidRequest)

	decoded.Metadata = &RequestMetadata{CancellationToken: "bad\ncontrol"}
	assertDecodedError(t, dispatcher.Dispatch(decoded, ExecutionState{}), ErrorInvalidRequest)

	capabilities := make([]string, DefaultLimits().MaxRequiredCapabilities+1)
	for index := range capabilities {
		capabilities[index] = "crypto.sha256"
	}
	decoded.Metadata = &RequestMetadata{RequiredCapabilities: capabilities}
	assertDecodedError(t, dispatcher.Dispatch(decoded, ExecutionState{}), ErrorInputTooLarge)

	decoded.Metadata = nil
	decoded.Operation = "not-known"
	assertDecodedError(t, dispatcher.Dispatch(decoded, ExecutionState{}), ErrorUnknownOperation)
}

func TestJSONArraysAndDepthAreRejectedSafely(t *testing.T) {
	arrayPayload := []byte(`{"abi":"goforge.abi.v1","id":"array","operation":"crypto.sha256","payload":{"data":[]}}`)
	assertErrorCode(t, DefaultDispatcher().DispatchJSON(arrayPayload, ExecutionState{}), ErrorInvalidJSON)

	limits := DefaultLimits()
	limits.MaxJSONDepth = 3
	dispatcher, err := NewDispatcher(limits)
	if err != nil {
		t.Fatal(err)
	}
	deep := []byte(`{"abi":"goforge.abi.v1","id":"deep","operation":"crypto.sha256","payload":{"data":{"nested":true}}}`)
	assertErrorCode(t, dispatcher.DispatchJSON(deep, ExecutionState{}), ErrorInvalidJSON)
}

func TestErrorBehaviorAndUnknownInternalCode(t *testing.T) {
	var nilError *ABIError
	if nilError.Error() != "" {
		t.Fatal("nil ABI error must have an empty Error string")
	}
	err := newABIError(ErrorInvalidKey, "key")
	if err.Error() != "invalid_key: cryptographic key has an invalid length" {
		t.Fatalf("unexpected Error string: %q", err.Error())
	}
	internal := newABIError(ErrorCode("not-in-catalog"), "")
	if internal.Code != ErrorInternal {
		t.Fatalf("unknown catalog code did not fail closed: %+v", internal)
	}
	if _, operationError := DefaultDispatcher().execute("not-known", []byte(`{}`)); operationError == nil || operationError.Code != ErrorUnknownOperation {
		t.Fatalf("unknown direct operation did not fail: %v", operationError)
	}
}

func aesPayload(key, nonce, aad, plaintext string) map[string]any {
	return map[string]any{"key": key, "nonce": nonce, "aad": aad, "plaintext": plaintext}
}

func assertDecodedError(t *testing.T, response Response, code ErrorCode) {
	t.Helper()
	if response.OK || response.Error == nil || response.Error.Code != code {
		t.Fatalf("expected %q, got %+v", code, response)
	}
}
