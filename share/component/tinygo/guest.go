//go:build tinygo

// Command tinygo is the production guest for the `pointerbyte:goforge@0.1.0`
// world, compiled by TinyGo 0.41.1 per ADR 0012.
//
// It owns no business rules. Everything it exports delegates to
// `share/component/bridge`, which delegates to the portable core — the same package
// the retained componentize-go regression guest uses, so the two builds differ
// only by compiler and can be compared directly.
package main

import (
	"github.com/PointerByte/forge-go/share/component/bridge"
	"github.com/PointerByte/forge-go/share/component/tinygo/generated/pointerbyte/goforge/operations"
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
