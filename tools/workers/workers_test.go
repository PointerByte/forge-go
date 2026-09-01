package workers

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const workerTestTimeout = time.Second

// resetWorkerState isolates a test from the package-wide dispatcher state. The
// dispatch mode is an explicit argument because it changes the observable
// contract, not just throughput: a sequential dispatcher runs each task inline,
// so StopWorkers waits for the task in flight instead of returning while it
// runs.
func resetWorkerState(t testing.TB, limit int, parallel bool) {
	t.Helper()

	StopWorkers()

	stateMu.Lock()
	originalQueue := queue
	originalLimit := workersLimit
	stateMu.Unlock()
	originalParallelism := parallelism.Load()

	SetWorkersLimit(limit)
	SetParallelism(parallel)

	t.Cleanup(func() {
		StopWorkers()

		waitForActiveTasks(t, 0)

		stateMu.Lock()
		queue = originalQueue
		workersLimit = originalLimit
		stateMu.Unlock()
		SetParallelism(originalParallelism)
	})
}

func waitForActiveTasks(t testing.TB, want int) {
	t.Helper()

	deadline := time.Now().Add(workerTestTimeout)
	for {
		stateMu.Lock()
		running := activeTasks
		stateMu.Unlock()
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
	resetWorkerState(t, 1, false)

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
	resetWorkerState(t, 1, false)

	SetWorkersLimit(3)

	for range 3 {
		AddTask(func() {})
	}

	fourthQueued := make(chan struct{})
	go func() {
		AddTask(func() {})
		close(fourthQueued)
	}()
	assertNoSignal(t, fourthQueued, "AddTask returned while the queue was full")

	stateMu.Lock()
	queued := len(queue)
	limit := workersLimit
	stateMu.Unlock()
	if queued != 3 {
		t.Fatalf("queued tasks = %d, want 3", queued)
	}
	if limit != 3 {
		t.Fatalf("worker limit = %d, want 3", limit)
	}

	RunWorkers()
	waitForSignal(t, fourthQueued, "AddTask stayed blocked after the dispatcher made room")
}

// TestSetWorkerLimitAppliesZeroVerbatim pins the current contract: the package
// no longer carries a default limit, so a zero limit is applied as written and
// leaves the dispatcher with neither an execution slot nor room to queue. The
// task is not rejected, it waits for a limit it can run under.
func TestSetWorkerLimitAppliesZeroVerbatim(t *testing.T) {
	resetWorkerState(t, 1, false)

	SetWorkersLimit(0)
	RunWorkers()

	stateMu.Lock()
	limit := workersLimit
	stateMu.Unlock()
	if limit != 0 {
		t.Fatalf("worker limit = %d, want 0", limit)
	}

	queued := make(chan struct{})
	executed := make(chan struct{})
	go func() {
		AddTask(func() { close(executed) })
		close(queued)
	}()
	assertNoSignal(t, queued, "AddTask found room in a zero-capacity queue")

	SetWorkersLimit(1)
	waitForSignal(t, queued, "AddTask stayed blocked after a positive limit was configured")
	waitForSignal(t, executed, "the queued task never ran under a positive limit")
}

// TestSetWorkersLimitReachesRunningDispatcher covers a limit raised mid-flight:
// the dispatcher reads the limit on every pass instead of capturing it when the
// run starts, so the change applies without a restart.
func TestSetWorkersLimitReachesRunningDispatcher(t *testing.T) {
	resetWorkerState(t, 1, true)
	RunWorkers()

	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseTasks := func() {
		releaseOnce.Do(func() { close(release) })
	}
	t.Cleanup(releaseTasks)

	firstStarted := make(chan struct{})
	AddTask(func() {
		close(firstStarted)
		<-release
	})
	waitForSignal(t, firstStarted, "first task did not start")

	secondStarted := make(chan struct{})
	AddTask(func() {
		close(secondStarted)
		<-release
	})
	assertNoSignal(t, secondStarted, "a second task started while the limit was 1")

	SetWorkersLimit(3)
	waitForSignal(t, secondStarted, "raising the limit did not reach the running dispatcher")

	releaseTasks()
}

// TestControlOperationsWorkWhileProducerWaitsForRoom is the regression test for
// the lock the queue used to hold: a producer parked on a full queue must not
// keep the control API from running, or the pool becomes unrecoverable.
func TestControlOperationsWorkWhileProducerWaitsForRoom(t *testing.T) {
	resetWorkerState(t, 1, true)
	RunWorkers()

	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseTask := func() {
		releaseOnce.Do(func() { close(release) })
	}
	t.Cleanup(releaseTask)

	running := make(chan struct{})
	AddTask(func() {
		close(running)
		<-release
	})
	waitForSignal(t, running, "task did not start")

	AddTask(func() {}) // fills the one-slot queue

	queued := make(chan struct{})
	go func() {
		AddTask(func() {})
		close(queued)
	}()
	assertNoSignal(t, queued, "AddTask returned while the queue was full")

	controlled := make(chan struct{})
	go func() {
		StopWorkers()
		SetWorkersLimit(2)
		RunWorkers()
		close(controlled)
	}()
	waitForSignal(t, controlled, "control operations blocked behind a producer waiting for room")
	waitForSignal(t, queued, "the waiting producer never got room")

	releaseTask()
}

// TestLoweringLimitKeepsQueuedTasks pins that a limit change is a change of
// policy, not of queue: what was already accepted still runs.
func TestLoweringLimitKeepsQueuedTasks(t *testing.T) {
	resetWorkerState(t, 4, true)

	var completed sync.WaitGroup
	completed.Add(4)
	for range 4 {
		AddTask(completed.Done)
	}

	SetWorkersLimit(1)
	RunWorkers()

	done := make(chan struct{})
	go func() {
		completed.Wait()
		close(done)
	}()
	waitForSignal(t, done, "tasks queued before the limit change were dropped")
}

func TestRunWorkersExecutesTasksQueuedBeforeStart(t *testing.T) {
	resetWorkerState(t, 2, false)

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
	resetWorkerState(t, limit, true)
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

// TestSequentialDispatchRunsOneTaskAtATime covers the default mode. The limit
// is deliberately higher than the task count, so serialization can only come
// from the dispatch mode.
func TestSequentialDispatchRunsOneTaskAtATime(t *testing.T) {
	const taskCount = 2
	resetWorkerState(t, taskCount+1, false)
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
	assertNoSignal(t, started, "a second task started while the dispatcher was sequential")

	releaseTasks()
	for range taskCount {
		waitForSignal(t, finished, "not all sequential tasks finished")
	}

	if got := maximum.Load(); got != 1 {
		t.Fatalf("maximum concurrent tasks = %d, want 1 in sequential mode", got)
	}
}

// TestStopWorkersWaitsForInlineTaskWhenSequential is the sequential
// counterpart of TestStopWorkersLeavesQueuedTasksForNextRun: with tasks running
// inline there is no separate goroutine to leave behind, so StopWorkers can only
// return once the task in flight has returned.
func TestStopWorkersWaitsForInlineTaskWhenSequential(t *testing.T) {
	resetWorkerState(t, 1, false)
	RunWorkers()

	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseTask := func() {
		releaseOnce.Do(func() { close(release) })
	}
	t.Cleanup(releaseTask)

	started := make(chan struct{})
	AddTask(func() {
		close(started)
		<-release
	})
	waitForSignal(t, started, "task did not start")

	stopped := make(chan struct{})
	go func() {
		StopWorkers()
		close(stopped)
	}()
	assertNoSignal(t, stopped, "StopWorkers returned while a task was still running inline")

	releaseTask()
	waitForSignal(t, stopped, "StopWorkers did not return after the inline task finished")
	if flagRunning.Load() {
		t.Fatal("workers remained marked running after stop")
	}
}

func TestStopWorkersLeavesQueuedTasksForNextRun(t *testing.T) {
	resetWorkerState(t, 1, true)
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

// TestStopWorkersReturnsWhileDispatcherWaitsForWork pins that StopWorkers waits
// for the run outside the lock. The dispatcher needs the same lock to observe
// the stop and close its done channel, so a StopWorkers that held it while
// waiting would deadlock the two against each other.
func TestStopWorkersReturnsWhileDispatcherWaitsForWork(t *testing.T) {
	resetWorkerState(t, 1, true)
	RunWorkers()

	ran := make(chan struct{})
	AddTask(func() { close(ran) })
	waitForSignal(t, ran, "task did not run")

	stopped := make(chan struct{})
	go func() {
		StopWorkers()
		close(stopped)
	}()
	waitForSignal(t, stopped, "StopWorkers blocked while the dispatcher waited for work")

	if flagRunning.Load() {
		t.Fatal("workers remained marked running after stop")
	}
}

func TestRestartWorkersRetainsLimitAcrossRunningTasks(t *testing.T) {
	resetWorkerState(t, 1, true)
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
	resetWorkerState(t, 1, false)

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
	resetWorkerState(t, 2, false)

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
