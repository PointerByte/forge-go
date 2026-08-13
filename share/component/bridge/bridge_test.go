package bridge

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/PointerByte/forge-go/share/portable"
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

func TestManifestUsesPortableSourceOfTruth(t *testing.T) {
	want := string(portable.DefaultDispatcher().ManifestJSON())
	if got := Manifest(); got != want {
		t.Fatalf("component manifest diverged from portable manifest\ngot:  %s\nwant: %s", got, want)
	}

	var manifest portable.Manifest
	if err := json.Unmarshal([]byte(Manifest()), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Package != "pointerbyte:goforge" || manifest.Version != "0.1.0" || manifest.ABI != portable.ABIVersion {
		t.Fatalf("unexpected component identity: %+v", manifest)
	}
}

func TestDispatchSharedPortableVectors(t *testing.T) {
	encoded, err := os.ReadFile("../../portable/testdata/vectors/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "goforge.test-vectors.v1" || vectors.ABI != portable.ABIVersion || len(vectors.Vectors) == 0 {
		t.Fatalf("unexpected shared vector contract: %+v", vectors)
	}

	for _, vector := range vectors.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			var compact bytes.Buffer
			if err := json.Compact(&compact, vector.Response); err != nil {
				t.Fatal(err)
			}
			if got := Dispatch(string(vector.Request), ExecutionState{}); got != compact.String() {
				t.Fatalf("response mismatch\ngot:  %s\nwant: %s", got, compact.String())
			}
		})
	}
}

func TestDispatchPreservesFailClosedExecutionControls(t *testing.T) {
	request := `{"abi":"goforge.abi.v1","id":"deadline-1","operation":"crypto.sha256","metadata":{"deadline_unix_ms":2000,"required_capabilities":["crypto.sha256","control.deadline"]},"payload":{"data":"YWJj"}}`

	assertErrorCode(t, Dispatch(request, ExecutionState{}), portable.ErrorExecutionStateRequired)
	assertErrorCode(t, Dispatch(request, ExecutionState{
		ClockChecked:        true,
		NowUnixMilliseconds: 2_000,
	}), portable.ErrorDeadlineExceeded)

	var response portable.Response
	if err := json.Unmarshal([]byte(Dispatch(request, ExecutionState{
		ClockChecked:        true,
		NowUnixMilliseconds: 1_999,
	})), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.ID != "deadline-1" {
		t.Fatalf("checked state did not reach portable dispatcher: %+v", response)
	}
}

func assertErrorCode(t *testing.T, encoded string, code portable.ErrorCode) {
	t.Helper()
	var response portable.Response
	if err := json.Unmarshal([]byte(encoded), &response); err != nil {
		t.Fatal(err)
	}
	if response.OK || response.Error == nil || response.Error.Code != code {
		t.Fatalf("expected error %q, got %s", code, encoded)
	}
}
