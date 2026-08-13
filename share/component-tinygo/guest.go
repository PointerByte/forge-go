//go:build tinygo

// Command component-tinygo builds the production GoForge component world with
// TinyGo instead of componentize-go, so the two compilers can be soaked against
// the same workload.
//
// It deliberately imports the production `share/component/bridge` package rather than
// re-implementing it: the only variable under test is the compiler and its
// runtime, so the guest-side logic must be identical to the shipped component's.
package main

import (
	"github.com/PointerByte/forge-go/share/component-tinygo/generated/pointerbyte/goforge/operations"
	"github.com/PointerByte/forge-go/share/component/bridge"
)

func init() {
	operations.Exports.Manifest = bridge.Manifest
	operations.Exports.Dispatch = dispatch
}

// dispatch maps the generated WIT state record onto the canonical portable
// contract, exactly as the componentize-go export does.
func dispatch(requestJSON string, state operations.ExecutionState) string {
	return bridge.Dispatch(requestJSON, bridge.ExecutionState{
		ClockChecked:          state.ClockChecked,
		NowUnixMilliseconds:   state.NowUnixMilliseconds,
		CancellationChecked:   state.CancellationChecked,
		CancellationToken:     state.CancellationToken,
		CancellationRequested: state.CancellationRequested,
	})
}

func main() {}
