package workers

import (
	"runtime"
	"sync"
	"testing"
)

func BenchmarkWorkerThroughput(b *testing.B) {
	modes := []struct {
		name     string
		parallel bool
	}{
		{name: "sequential", parallel: false},
		{name: "parallel", parallel: true},
	}

	for _, mode := range modes {
		b.Run(mode.name, func(b *testing.B) {
			resetWorkerState(b, runtime.GOMAXPROCS(0), mode.parallel)
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
		})
	}
}
