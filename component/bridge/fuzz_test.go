package bridge

import (
	"encoding/json"
	"testing"
)

func FuzzDispatchAlwaysReturnsJSON(f *testing.F) {
	f.Add(`{"abi":"goforge.abi.v1","id":"fuzz-1","operation":"crypto.sha256","payload":{"data":"YWJj"}}`)
	f.Add(`{"abi":`)
	f.Add("")

	f.Fuzz(func(t *testing.T, request string) {
		response := Dispatch(request, ExecutionState{})
		if !json.Valid([]byte(response)) {
			t.Fatalf("bridge emitted invalid JSON: %q", response)
		}
	})
}
