// Package export_pointerbyte_goforge_operations implements the generated WIT
// export surface by delegating directly to the canonical component bridge.
package export_pointerbyte_goforge_operations

import (
	"github.com/PointerByte/forge-go/component/bridge"
	"wit_component/pointerbyte_goforge_operations"
)

// Manifest returns the portable core's canonical manifest JSON.
func Manifest() string {
	return bridge.Manifest()
}

// Dispatch maps the generated WIT state record to the portable state contract
// and delegates without interpreting or rewriting the JSON envelope.
func Dispatch(requestJSON string, state pointerbyte_goforge_operations.ExecutionState) string {
	return bridge.Dispatch(requestJSON, bridge.ExecutionState{
		ClockChecked:          state.ClockChecked,
		NowUnixMilliseconds:   state.NowUnixMilliseconds,
		CancellationChecked:   state.CancellationChecked,
		CancellationToken:     state.CancellationToken,
		CancellationRequested: state.CancellationRequested,
	})
}
