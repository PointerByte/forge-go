package workers

import (
	"runtime"
	"sync"
	"sync/atomic"
)

var defaultWorkerLimit = 1000

type workerRun struct {
	done     chan struct{}
	limit    int
	pool     <-chan func()
	stop     chan struct{}
	stopping bool
}

var (
	workerPool   chan func()
	workersLimit int

	stateMu     sync.Mutex
	activeRun   *workerRun
	stopSignal  chan struct{}
	flagRunning atomic.Bool

	executionMu      sync.Mutex
	executionChanged = sync.NewCond(&executionMu)
	activeTasks      int
)

func init() {
	defaultWorkerLimit = defaultWorkerLimit * runtime.NumCPU()
	workerPool = make(chan func(), defaultWorkerLimit)
	workersLimit = defaultWorkerLimit
}

func AddTask(task func()) {
	stateMu.Lock()
	pool := workerPool
	stateMu.Unlock()

	pool <- task
}

// SetWorkersLimit sets the maximum number of concurrent workers for future runs.
// It also sets the task queue capacity. Non-positive limits fall back to the
// default worker limit.
func SetWorkersLimit(limit int) {
	if limit <= 0 {
		limit = defaultWorkerLimit
	}

	stateMu.Lock()
	workerPool = make(chan func(), limit)
	workersLimit = limit
	stateMu.Unlock()
}

// StopWorkers stops the currently running worker loop, if any.
func StopWorkers() {
	stateMu.Lock()
	run := activeRun
	if run == nil {
		flagRunning.Store(false)
		stopSignal = nil
		stateMu.Unlock()
		return
	}

	if !run.stopping {
		run.stopping = true
		close(run.stop)
	}
	stateMu.Unlock()

	executionMu.Lock()
	executionChanged.Broadcast()
	executionMu.Unlock()

	<-run.done
}

// RestartWorkers stops the current worker loop and starts it again.
func RestartWorkers() {
	StopWorkers()
	RunWorkers()
}

// RunWorkers starts the managed worker loop if one is not already running.
func RunWorkers() {
	stateMu.Lock()
	if activeRun != nil {
		stateMu.Unlock()
		return
	}

	run := &workerRun{
		done:  make(chan struct{}),
		limit: workersLimit,
		pool:  workerPool,
		stop:  make(chan struct{}),
	}
	activeRun = run
	stopSignal = run.stop
	flagRunning.Store(true)
	stateMu.Unlock()

	go dispatch(run)
}

func dispatch(run *workerRun) {
	defer finishRun(run)

	for reserveExecutionSlot(run) {
		select {
		case <-run.stop:
			releaseExecutionSlot()
			return
		case task := <-run.pool:
			go executeTask(task)
		}
	}
}

func reserveExecutionSlot(run *workerRun) bool {
	executionMu.Lock()
	defer executionMu.Unlock()

	for activeTasks >= run.limit {
		if stopped(run.stop) {
			return false
		}
		executionChanged.Wait()
	}

	if stopped(run.stop) {
		return false
	}
	activeTasks++
	return true
}

func releaseExecutionSlot() {
	executionMu.Lock()
	activeTasks--
	executionChanged.Broadcast()
	executionMu.Unlock()
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

func stopped(stop <-chan struct{}) bool {
	select {
	case <-stop:
		return true
	default:
		return false
	}
}
