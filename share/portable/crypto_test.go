package portable

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestCryptographicOperationsFailClosed(t *testing.T) {
	dispatcher := DefaultDispatcher()
	tests := []struct {
		name      string
		operation Operation
		payload   map[string]any
		code      ErrorCode
	}{
		{
			name:      "short-hmac-key",
			operation: OperationHMACSHA256,
			payload:   map[string]any{"key": "a2V5", "data": ""},
			code:      ErrorInvalidKey,
		},
		{
			name:      "invalid-aes-key-size",
			operation: OperationAESGCMEncrypt,
			payload:   map[string]any{"key": "a2V5", "nonce": "AAAAAAAAAAAAAAAA", "aad": "", "plaintext": ""},
			code:      ErrorInvalidKey,
		},
		{
			name:      "invalid-aes-nonce-size",
			operation: OperationAESGCMEncrypt,
			payload:   map[string]any{"key": "AAAAAAAAAAAAAAAAAAAAAA==", "nonce": "AAAAAAAAAAA=", "aad": "", "plaintext": ""},
			code:      ErrorInvalidNonce,
		},
		{
			name:      "truncated-ciphertext",
			operation: OperationAESGCMDecrypt,
			payload:   map[string]any{"key": "AAAAAAAAAAAAAAAAAAAAAA==", "nonce": "AAAAAAAAAAAAAAAA", "aad": "", "ciphertext": "AA=="},
			code:      ErrorAuthenticationFailed,
		},
		{
			name:      "tampered-ciphertext",
			operation: OperationAESGCMDecrypt,
			payload:   map[string]any{"key": "AAAAAAAAAAAAAAAAAAAAAA==", "nonce": "AAAAAAAAAAAAAAAA", "aad": "", "ciphertext": "A4jazmC2o5LzKMK5cbL+eKtuR9Qs7BO99TpnshJXvd4="},
			code:      ErrorAuthenticationFailed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertErrorCode(t, dispatcher.DispatchJSON(makeRequest(t, test.operation, test.payload, nil), ExecutionState{}), test.code)
		})
	}
}

func TestAESGCMRequiresCallerNonceAndIsDeterministic(t *testing.T) {
	payload := map[string]any{
		"key":       "AAAAAAAAAAAAAAAAAAAAAA==",
		"nonce":     "AAAAAAAAAAAAAAAA",
		"aad":       "",
		"plaintext": "AAAAAAAAAAAAAAAAAAAAAA==",
	}
	request := makeRequest(t, OperationAESGCMEncrypt, payload, nil)
	dispatcher := DefaultDispatcher()
	first := dispatcher.DispatchJSON(request, ExecutionState{})
	second := dispatcher.DispatchJSON(request, ExecutionState{})
	if string(first) != string(second) {
		t.Fatalf("caller-supplied inputs did not produce deterministic output\n%s\n%s", first, second)
	}

	delete(payload, "nonce")
	assertErrorCode(t, dispatcher.DispatchJSON(makeRequest(t, OperationAESGCMEncrypt, payload, nil), ExecutionState{}), ErrorInvalidRequest)
	for _, field := range []string{"key", "nonce", "aad", "plaintext"} {
		missing := map[string]any{
			"key":       "AAAAAAAAAAAAAAAAAAAAAA==",
			"nonce":     "AAAAAAAAAAAAAAAA",
			"aad":       "",
			"plaintext": "",
		}
		delete(missing, field)
		assertErrorCode(t, dispatcher.DispatchJSON(makeRequest(t, OperationAESGCMEncrypt, missing, nil), ExecutionState{}), ErrorInvalidRequest)
	}
}

func TestBase64DecodeRejectsNonUTF8OperationResult(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe})
	request := makeRequest(t, OperationBase64Decode, map[string]any{"encoded": encoded}, nil)
	assertErrorCode(t, DefaultDispatcher().DispatchJSON(request, ExecutionState{}), ErrorInvalidUTF8)
}

func TestValidationRulesAreBounded(t *testing.T) {
	tests := []map[string]any{
		{"value": "abc", "rules": map[string]any{"min_bytes": -1}},
		{"value": "abc", "rules": map[string]any{"min_bytes": 4, "max_bytes": 3}},
		{"value": "abc", "rules": map[string]any{"min_runes": 4, "max_runes": 3}},
	}
	for _, payload := range tests {
		request := makeRequest(t, OperationValidate, payload, nil)
		assertErrorCode(t, DefaultDispatcher().DispatchJSON(request, ExecutionState{}), ErrorInvalidRequest)
	}
}

func TestDispatchDecodedRequest(t *testing.T) {
	payload, err := json.Marshal(map[string]string{"data": "YWJj"})
	if err != nil {
		t.Fatal(err)
	}
	response := DefaultDispatcher().Dispatch(Request{
		ABI:       ABIVersion,
		ID:        "decoded",
		Operation: OperationSHA256,
		Payload:   payload,
	}, ExecutionState{})
	if !response.OK || response.Error != nil || response.ID != "decoded" {
		t.Fatalf("unexpected decoded dispatch response: %+v", response)
	}
}
