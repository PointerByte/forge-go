package bridge

import "testing"

func BenchmarkDispatchSHA256(b *testing.B) {
	request := `{"abi":"goforge.abi.v1","id":"bench-1","operation":"crypto.sha256","payload":{"data":"YWJj"}}`
	b.ReportAllocs()
	for range b.N {
		_ = Dispatch(request, ExecutionState{})
	}
}
