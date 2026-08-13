package export_pointerbyte_goforge_operations

import (
	"encoding/json"
	"testing"

	"github.com/PointerByte/forge-go/share/portable"
	"wit_component/pointerbyte_goforge_operations"
)

func TestExportsDelegateToPortableContract(t *testing.T) {
	if got, want := Manifest(), string(portable.DefaultDispatcher().ManifestJSON()); got != want {
		t.Fatalf("manifest mismatch\ngot:  %s\nwant: %s", got, want)
	}

	request := `{"abi":"goforge.abi.v1","id":"component-1","operation":"crypto.sha256","payload":{"data":"YWJj"}}`
	var response portable.Response
	if err := json.Unmarshal([]byte(Dispatch(request, pointerbyte_goforge_operations.ExecutionState{})), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.ID != "component-1" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestExportsMapEveryExecutionStateField(t *testing.T) {
	request := `{"abi":"goforge.abi.v1","id":"cancel-1","operation":"crypto.sha256","metadata":{"cancellation_token":"token-1"},"payload":{"data":"YWJj"}}`
	encoded := Dispatch(request, pointerbyte_goforge_operations.ExecutionState{
		ClockChecked:          true,
		NowUnixMilliseconds:   123,
		CancellationChecked:   true,
		CancellationToken:     "token-1",
		CancellationRequested: true,
	})
	var response portable.Response
	if err := json.Unmarshal([]byte(encoded), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != portable.ErrorCancellationRequested {
		t.Fatalf("state mapping did not reach portable dispatcher: %s", encoded)
	}
}
