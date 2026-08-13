package portable

import (
	"bytes"
	"encoding/json"
	"testing"
)

func FuzzDispatchJSONNeverPanics(f *testing.F) {
	dispatcher := DefaultDispatcher()
	f.Add([]byte(`{"abi":"goforge.abi.v1","id":"seed","operation":"crypto.sha256","payload":{"data":"YWJj"}}`))
	f.Add([]byte(`{"abi":"goforge.abi.v1","id":"x","id":"y"}`))
	f.Add([]byte{0xff, 0x00, '{', '}'})

	f.Fuzz(func(t *testing.T, input []byte) {
		response := dispatcher.DispatchJSON(input, ExecutionState{})
		if len(response) > DefaultLimits().MaxResponseBytes {
			t.Fatalf("response exceeded limit: %d", len(response))
		}
		if !json.Valid(response) {
			t.Fatalf("invalid response JSON: %q", response)
		}
	})
}

func FuzzCanonicalBase64RoundTrip(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte{})
	f.Add([]byte{0x00, 0xff, 0x7f})

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4096 {
			t.Skip()
		}
		encoded := encodeBinary(input)
		decoded, err := decodeBinary(encoded, "fuzz", 4096)
		if err != nil {
			t.Fatalf("canonical value rejected: %v", err)
		}
		defer zeroBytes(decoded)
		if !bytes.Equal(input, decoded) {
			t.Fatal("Base64 round trip changed bytes")
		}
	})
}
