package workers

import (
	"runtime"
	"sync"
	"testing"
)

func BenchmarkWorkerThroughput(b *testing.B) {
	resetWorkerState(b, runtime.GOMAXPROCS(0))
	RunWorkers()

	var completed sync.WaitGroup
	completed.Add(b.N)
	task := completed.Done

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		AddTask(task)
	}
	completed.Wait()
	b.StopTimer()
}
