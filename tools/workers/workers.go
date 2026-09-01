package workers

import (
	"runtime"
	"sync"
	"sync/atomic"
)

type workerRun struct {
	done     chan struct{}
	stop     chan struct{}
	stopping bool
}

var (
	// stateMu guards every field below and stateChanged signals each change to
	// them. One lock for the whole dispatcher is what lets AddTask wait for
	// room without holding anyone else out: Cond.Wait releases the mutex while
	// a producer is parked, so SetWorkersLimit, StopWorkers and RunWorkers stay
	// serviceable even when the queue is full and nothing is draining it.
	stateMu      sync.Mutex
	stateChanged = sync.NewCond(&stateMu)

	// queue is the pending task list. It is never replaced, only appended to
	// and consumed from, so a limit change can never strand a producer on a
	// queue nobody reads, nor drop what is already waiting.
	queue        []func()
	workersLimit int
	activeTasks  int

	activeRun   *workerRun
	stopSignal  chan struct{}
	flagRunning atomic.Bool

	parallelism atomic.Bool
)

func init() {
	parallelism.Store(true)
	workersLimit = runtime.NumCPU()
}

// SetWorkersLimit sets the maximum number of concurrently executing tasks, and
// with it the queue capacity.
//
// The limit is applied verbatim: there is no fallback to a default, so a
// non-positive limit leaves the dispatcher without an execution slot and the
// queue without room, and tasks wait until a positive limit is configured.
//
// The change reaches a dispatcher that is already running. Raising the limit
// starts queued tasks and releases waiting producers right away; lowering it
// takes effect as the tasks in flight finish, since none of them is cancelled.
// Tasks already queued are never dropped by a limit change.
func SetWorkersLimit(limit int) {
	stateMu.Lock()
	defer stateMu.Unlock()

	workersLimit = limit
	stateChanged.Broadcast()
}

// SetParallelism sets whether tasks should be executed in parallel or sequentially.
func SetParallelism(parallel bool) {
	parallelism.Store(parallel)
}

// AddTask queues a task for asynchronous execution. It blocks while the queue
// holds as many tasks as the configured limit allows, and returns as soon as
// the dispatcher makes room or the limit is raised.
func AddTask(task func()) {
	stateMu.Lock()
	defer stateMu.Unlock()

	for len(queue) >= workersLimit {
		stateChanged.Wait()
	}

	queue = append(queue, task)
	stateChanged.Broadcast()
}

// StopWorkers stops the currently running worker loop, if any.
//
// The wait for the run to finish happens outside the lock on purpose: the
// dispatcher needs stateMu to observe the stop and close its done channel, so
// holding the lock here would deadlock the two against each other.
func StopWorkers() {
	run := signalStop()
	if run == nil {
		return
	}

	<-run.done
}

// signalStop marks the active run as stopping and wakes everyone waiting on the
// dispatcher state. It returns the run to wait for, or nil when none is active.
func signalStop() *workerRun {
	stateMu.Lock()
	defer stateMu.Unlock()

	run := activeRun
	if run == nil {
		flagRunning.Store(false)
		stopSignal = nil
		return nil
	}

	if !run.stopping {
		run.stopping = true
		close(run.stop)
	}
	stateChanged.Broadcast()

	return run
}

// RestartWorkers stops the current worker loop and starts it again.
func RestartWorkers() {
	StopWorkers()
	RunWorkers()
}

// RunWorkers starts the managed worker loop if one is not already running.
func RunWorkers() {
	stateMu.Lock()
	defer stateMu.Unlock()

	if activeRun != nil {
		return
	}

	run := &workerRun{
		done: make(chan struct{}),
		stop: make(chan struct{}),
	}
	activeRun = run
	stopSignal = run.stop
	flagRunning.Store(true)

	go dispatch(run)
}

func dispatch(run *workerRun) {
	defer finishRun(run)

	for {
		task, ok := nextTask(run)
		if !ok {
			return
		}

		if parallelism.Load() {
			go executeTask(task)
		} else {
			executeTask(task)
		}
	}
}

// nextTask waits for a queued task and a free execution slot, reserves the slot
// and hands the task over. It reports false once the run has been stopped.
//
// The limit is read on every pass rather than captured when the run starts,
// which is what makes SetWorkersLimit reach a dispatcher already in flight.
func nextTask(run *workerRun) (func(), bool) {
	stateMu.Lock()
	defer stateMu.Unlock()

	for !run.stopping && (len(queue) == 0 || activeTasks >= workersLimit) {
		stateChanged.Wait()
	}

	if run.stopping {
		return nil, false
	}

	task := queue[0]
	queue[0] = nil
	queue = queue[1:]
	activeTasks++
	stateChanged.Broadcast()

	return task, true
}

func releaseExecutionSlot() {
	stateMu.Lock()
	defer stateMu.Unlock()
	activeTasks--
	stateChanged.Broadcast()
}

func executeTask(task func()) {
	defer releaseExecutionSlot()
	task()
}

func finishRun(run *workerRun) {
	stateMu.Lock()
	if activeRun == run {
		activeRun = nil
		stopSignal = nil
		flagRunning.Store(false)
	}
	stateMu.Unlock()
	close(run.done)
}
