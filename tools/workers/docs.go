// Package workers provides a bounded in-process task dispatcher backed by a
// buffered function queue.
//
// The package exposes a process-wide worker loop. Tasks are submitted with
// AddTask and executed asynchronously after RunWorkers starts the dispatcher.
// SetWorkersLimit controls both the maximum number of concurrently executing
// tasks and the queue capacity.
//
// Main entry points:
//   - SetWorkersLimit configures the execution limit and task queue capacity.
//   - AddTask queues a function for asynchronous execution.
//   - RunWorkers starts the dispatcher if it is not already running.
//   - StopWorkers stops the current dispatcher loop.
//   - RestartWorkers stops the current dispatcher and starts a new one.
//
// Example:
//
//	workers.SetWorkersLimit(100)
//	workers.RunWorkers()
//	defer workers.StopWorkers()
//
//	workers.AddTask(func() {
//		// do work asynchronously
//	})
//
// AddTask blocks when the configured queue is full. RunWorkers is idempotent:
// calling it while the dispatcher is already running does not start another
// loop. StopWorkers stops consuming queued tasks, but it does not cancel tasks
// that have already started. Queued tasks remain available for a later run.
package workers
