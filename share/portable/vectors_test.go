package portable

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

type vectorFile struct {
	Schema  string       `json:"schema"`
	ABI     string       `json:"abi"`
	Vectors []testVector `json:"vectors"`
}

type testVector struct {
	Name     string          `json:"name"`
	Request  json.RawMessage `json:"request"`
	Response json.RawMessage `json:"response"`
}

func TestDeterministicVectors(t *testing.T) {
	encoded, err := os.ReadFile("testdata/vectors/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "goforge.test-vectors.v1" || vectors.ABI != ABIVersion {
		t.Fatalf("unexpected vector contract: %q %q", vectors.Schema, vectors.ABI)
	}
	if len(vectors.Vectors) != 8 {
		t.Fatalf("expected all eight operations, got %d", len(vectors.Vectors))
	}

	dispatcher := DefaultDispatcher()
	for _, vector := range vectors.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			actual := dispatcher.DispatchJSON(vector.Request, ExecutionState{})
			expected := compactJSON(t, vector.Response)
			if !bytes.Equal(actual, expected) {
				t.Fatalf("response mismatch\nactual:   %s\nexpected: %s", actual, expected)
			}
		})
	}
}

func compactJSON(t *testing.T, input []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	if err := json.Compact(&output, input); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
