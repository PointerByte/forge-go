// Package bridge is the thin Component Model boundary around GoForge's
// canonical portable dispatcher. It owns no business rules.
package bridge

import "github.com/PointerByte/forge-go/share/portable"

var dispatcher = portable.DefaultDispatcher()

// ExecutionState is the canonical host-observed execution state. The alias
// deliberately prevents this component from defining a second contract.
type ExecutionState = portable.ExecutionState

// Manifest returns the exact deterministic portable contract manifest.
func Manifest() string {
	return string(dispatcher.ManifestJSON())
}

// Dispatch forwards one JSON request and explicit host state to the portable
// dispatcher. Every domain failure is represented by its ABI response.
func Dispatch(requestJSON string, state ExecutionState) string {
	return string(dispatcher.DispatchJSON([]byte(requestJSON), state))
}
