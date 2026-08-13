package workers

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const workerTestTimeout = time.Second

func resetWorkerState(t testing.TB, limit int) {
	t.Helper()

	StopWorkers()

	stateMu.Lock()
	originalPool := workerPool
	originalLimit := workersLimit
	stateMu.Unlock()

	SetWorkersLimit(limit)

	t.Cleanup(func() {
		StopWorkers()

		waitForActiveTasks(t, 0)

		stateMu.Lock()
		workerPool = originalPool
		workersLimit = originalLimit
		stateMu.Unlock()
	})
}

func waitForActiveTasks(t testing.TB, want int) {
	t.Helper()

	deadline := time.Now().Add(workerTestTimeout)
	for {
		executionMu.Lock()
		running := activeTasks
		executionMu.Unlock()
		if running == want {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("active tasks = %d, want %d", running, want)
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForSignal(t testing.TB, signal <-chan struct{}, message string) {
	t.Helper()

	select {
	case <-signal:
	case <-time.After(workerTestTimeout):
		t.Fatal(message)
	}
}

func assertNoSignal(t testing.TB, signal <-chan struct{}, message string) {
	t.Helper()

	select {
	case <-signal:
		t.Fatal(message)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestAddTaskBlocksWhenPoolIsFullUntilDispatcherConsumesTask(t *testing.T) {
	resetWorkerState(t, 1)

	var completed sync.WaitGroup
	completed.Add(2)
	secondTaskQueued := make(chan struct{})

	AddTask(completed.Done)

	go func() {
		AddTask(completed.Done)
		close(secondTaskQueued)
	}()

	assertNoSignal(t, secondTaskQueued, "AddTask returned while the pool was full")

	RunWorkers()
	waitForSignal(t, secondTaskQueued, "AddTask remained blocked after workers consumed from the pool")

	done := make(chan struct{})
	go func() {
		completed.Wait()
		close(done)
	}()
	waitForSignal(t, done, "queued backpressure test tasks did not finish")
}

func TestSetWorkerLimitConfiguresQueueCapacity(t *testing.T) {
	resetWorkerState(t, 1)

	SetWorkersLimit(3)

	stateMu.Lock()
	capacity := cap(workerPool)
	limit := workersLimit
	stateMu.Unlock()
	if capacity != 3 {
		t.Fatalf("worker pool capacity = %d, want 3", capacity)
	}
	if limit != 3 {
		t.Fatalf("worker limit = %d, want 3", limit)
	}
}

func TestSetWorkerLimitUsesDefaultForInvalidValues(t *testing.T) {
	resetWorkerState(t, 1)

	SetWorkersLimit(0)

	stateMu.Lock()
	capacity := cap(workerPool)
	limit := workersLimit
	stateMu.Unlock()
	if capacity != defaultWorkerLimit {
		t.Fatalf("worker pool capacity = %d, want default %d", capacity, defaultWorkerLimit)
	}
	if limit != defaultWorkerLimit {
		t.Fatalf("worker limit = %d, want default %d", limit, defaultWorkerLimit)
	}
}

func TestRunWorkersExecutesTasksQueuedBeforeStart(t *testing.T) {
	resetWorkerState(t, 2)

	var completed sync.WaitGroup
	completed.Add(2)
	AddTask(completed.Done)
	AddTask(completed.Done)

	RunWorkers()

	done := make(chan struct{})
	go func() {
		completed.Wait()
		close(done)
	}()
	waitForSignal(t, done, "workers did not execute tasks queued before start")
}

func TestWorkersLimitBoundsConcurrentExecution(t *testing.T) {
	const (
		limit     = 2
		taskCount = 4
	)
	resetWorkerState(t, limit)
	RunWorkers()

	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseTasks := func() {
		releaseOnce.Do(func() { close(release) })
	}
	t.Cleanup(releaseTasks)

	started := make(chan struct{}, taskCount)
	finished := make(chan struct{}, taskCount)
	var active atomic.Int32
	var maximum atomic.Int32

	for range taskCount {
		AddTask(func() {
			current := active.Add(1)
			for observed := maximum.Load(); current > observed; observed = maximum.Load() {
				if maximum.CompareAndSwap(observed, current) {
					break
				}
			}
			started <- struct{}{}
			<-release
			active.Add(-1)
			finished <- struct{}{}
		})
	}

	waitForSignal(t, started, "first task did not start")
	waitForSignal(t, started, "second task did not start")
	assertNoSignal(t, started, "a third task started while two execution slots were occupied")

	releaseTasks()
	for range taskCount {
		waitForSignal(t, finished, "not all bounded tasks finished")
	}

	if got := maximum.Load(); got > limit {
		t.Fatalf("maximum concurrent tasks = %d, want at most %d", got, limit)
	}
}

func TestStopWorkersLeavesQueuedTasksForNextRun(t *testing.T) {
	resetWorkerState(t, 1)
	RunWorkers()

	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseFirst) })
	}
	t.Cleanup(release)

	firstStarted := make(chan struct{})
	firstFinished := make(chan struct{})
	secondStarted := make(chan struct{})
	secondFinished := make(chan struct{})

	AddTask(func() {
		close(firstStarted)
		<-releaseFirst
		close(firstFinished)
	})
	waitForSignal(t, firstStarted, "first task did not start")

	AddTask(func() {
		close(secondStarted)
		close(secondFinished)
	})

	stopped := make(chan struct{})
	go func() {
		StopWorkers()
		close(stopped)
	}()
	waitForSignal(t, stopped, "StopWorkers waited for an already-running task")

	release()
	waitForSignal(t, firstFinished, "task running at stop did not finish")
	assertNoSignal(t, secondStarted, "stopped workers consumed a queued task")

	RunWorkers()
	waitForSignal(t, secondStarted, "queued task did not start on the next run")
	waitForSignal(t, secondFinished, "queued task did not finish on the next run")
}

func TestRestartWorkersRetainsLimitAcrossRunningTasks(t *testing.T) {
	resetWorkerState(t, 1)
	RunWorkers()

	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseFirst) })
	}
	t.Cleanup(release)

	firstStarted := make(chan struct{})
	firstFinished := make(chan struct{})
	secondStarted := make(chan struct{})
	secondFinished := make(chan struct{})

	AddTask(func() {
		close(firstStarted)
		<-releaseFirst
		close(firstFinished)
	})
	waitForSignal(t, firstStarted, "first task did not start")

	AddTask(func() {
		close(secondStarted)
		close(secondFinished)
	})

	RestartWorkers()
	if !flagRunning.Load() {
		t.Fatal("workers are not running after restart")
	}
	assertNoSignal(t, secondStarted, "restart exceeded the limit while an earlier task was running")

	release()
	waitForSignal(t, firstFinished, "first task did not finish after restart")
	waitForSignal(t, secondStarted, "restarted workers did not consume the queued task")
	waitForSignal(t, secondFinished, "queued task did not finish after restart")
}

func TestRunWorkersIsIdempotent(t *testing.T) {
	resetWorkerState(t, 1)

	RunWorkers()

	stateMu.Lock()
	firstRun := activeRun
	firstStop := stopSignal
	stateMu.Unlock()
	if firstRun == nil || firstStop == nil {
		t.Fatal("worker run was not initialized")
	}

	RunWorkers()

	stateMu.Lock()
	secondRun := activeRun
	secondStop := stopSignal
	stateMu.Unlock()
	if secondRun != firstRun || secondStop != firstStop {
		t.Fatal("second RunWorkers call replaced the active worker run")
	}

	StopWorkers()
	if flagRunning.Load() {
		t.Fatal("workers remained marked running after stop")
	}

	stateMu.Lock()
	defer stateMu.Unlock()
	if activeRun != nil || stopSignal != nil {
		t.Fatal("worker state was not cleared after stop")
	}
}

func TestWorkersSupportRepeatedStartStopCycles(t *testing.T) {
	resetWorkerState(t, 2)

	for cycle := range 3 {
		RunWorkers()

		finished := make(chan struct{})
		AddTask(func() { close(finished) })
		waitForSignal(t, finished, "task did not finish during repeated lifecycle cycle")

		StopWorkers()
		if flagRunning.Load() {
			t.Fatalf("workers remained running after cycle %d", cycle)
		}
	}
}
