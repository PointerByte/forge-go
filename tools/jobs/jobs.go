// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package jobs

import (
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/viper"
)

var globalJobs ijobs
var checkJobsStop atomic.Bool
var jobIDCounter atomic.Uint64

var (
	ErrNilJobFunc         = errors.New("jobs: job function is nil")
	ErrInvalidInterval    = errors.New("jobs: interval must be greater than zero")
	ErrEmptyJobID         = errors.New("jobs: job id is required")
	ErrDuplicateJobID     = errors.New("jobs: job id already exists")
	ErrJobNotFound        = errors.New("jobs: job id not found")
	ErrJobStopped         = errors.New("jobs: job is stopped")
	ErrInvalidCronTrigger = errors.New("jobs: invalid cron trigger")
	ErrCronTriggerExpired = errors.New("jobs: cron trigger has no future run")
)

func init() {
	globalJobs = newJobs()
}

// CronTrigger defines when a CronJob should run.
// Nil date fields match any value.
//
// Example:
//
//	trg := jobs.CronTrigger{Hour: 9, Minute: 0, Second: 0} // every day at 09:00:00
type CronTrigger struct {
	Year  *uint // nil = any year
	Month *uint // nil = any month, 1-12
	Day   *uint // nil = any day, 1-31

	Hour   uint // 0-23
	Minute uint // 0-59
	Second uint // 0-59
}

type cronTrigger = CronTrigger

// ijobs defines the operations used by the package-level scheduler.
// It is implemented by *Jobs.
//
// Example:
//
//	jobs.Job(func() { /* ... */ }, 2*time.Second, nil)
//	jobs.CronJob(func() { /* ... */ }, jobs.CronTrigger{Hour: 9}, 0)
//	jobs.StartJobs()
type ijobs interface {
	// job schedules fn to run periodically every interval.
	// If timeout != nil and *timeout > 0, the job stops automatically when
	// the timeout expires. If timeout is nil, the job keeps running until
	// StopAllJobs, Destroy, or process shutdown.
	//
	// Example:
	//
	//	timeout := 10 * time.Second
	//	j.job(func() { fmt.Println("every 500ms") }, 500*time.Millisecond, &timeout)
	job(fn func(), interval time.Duration, timeout *time.Duration) (string, error)
	jobWithID(id string, fn func(), interval time.Duration, timeout *time.Duration) error

	// cronJob schedules fn to start at the time defined by trigger.
	// If interval <= 0, the job runs daily.
	// If interval > 0, the first execution is aligned to trigger and the job
	// then repeats every interval until the instance is stopped.
	//
	// Examples:
	//
	//  // 1) Daily schedule:
	//  j.cronJob(func() { fmt.Println("daily") },
	//      jobs.CronTrigger{Hour: 7, Minute: 45, Second: 0}, 0)
	//
	//  // 2) First run at 09:00, then every 5 seconds:
	//  j.cronJob(func() { fmt.Println("starts at 09:00 and then runs every 5s") },
	//      jobs.CronTrigger{Hour: 9, Minute: 0, Second: 0}, 5*time.Second)
	cronJob(fn func(), trigger CronTrigger, interval time.Duration) (string, error)
	cronJobWithID(id string, fn func(), trigger CronTrigger, interval time.Duration) error

	// startJobs starts all jobs registered in the instance.
	// The operation is idempotent: multiple calls do not duplicate running jobs.
	startJobs()
}

// jobs manages the lifecycle of periodic and cron jobs for one internal
// scheduler instance.
type jobs struct {
	started atomic.Bool
	stopCh  atomic.Value

	mux          sync.Mutex
	intervalJobs []intervalJob
	cronJobs     []cronJob
	controls     map[string]*jobControl

	wg sync.WaitGroup
}

// newJobs creates and registers an internal jobs instance in the global registry.
// Any instance created with newJobs is affected by StopAllJobs.
//
// Example:
//
//	j := jobs.newJobs()
//	j.job(func() { fmt.Println("hello") }, time.Second, nil)
//	j.startJobs()
func newJobs() *jobs {
	j := &jobs{controls: make(map[string]*jobControl)}
	register(j)
	return j
}

// job registers a job that runs fn every interval.
// If timeout is not nil and greater than zero, the job stops automatically
// when the timeout expires.
//
// If the instance has already been started, the job starts immediately.
// Otherwise, it is queued until StartJobs is called.
//
// Examples:
//
//	// 1) No timeout:
//	j.job(func() { fmt.Println("tick") }, 500*time.Millisecond, nil)
//
//	// 2) With timeout (stops after 5 seconds):
//	t := 5 * time.Second
//	j.job(func() { fmt.Println("timed tick") }, 500*time.Millisecond, &t)
func (j *jobs) job(fn func(), interval time.Duration, timeout *time.Duration) (string, error) {
	if err := validateIntervalJob(fn, interval); err != nil {
		return "", err
	}

	id := nextJobID()
	if err := j.registerIntervalJob(id, fn, interval, timeout); err != nil {
		return "", err
	}
	return id, nil
}

func (j *jobs) jobWithID(id string, fn func(), interval time.Duration, timeout *time.Duration) error {
	if err := validateJobID(id); err != nil {
		return err
	}
	if err := validateIntervalJob(fn, interval); err != nil {
		return err
	}
	return j.registerIntervalJob(id, fn, interval, timeout)
}

func (j *jobs) registerIntervalJob(id string, fn func(), interval time.Duration, timeout *time.Duration) error {
	j.mux.Lock()
	control, err := j.addControlLocked(id)
	if err != nil {
		j.mux.Unlock()
		return err
	}
	ij := intervalJob{id: control.id, fn: fn, interval: interval, timeout: timeout, control: control}
	j.intervalJobs = append(j.intervalJobs, ij)

	if j.started.Load() {
		if ch, _ := j.stopCh.Load().(chan struct{}); ch != nil {
			j.mux.Unlock()
			j.startIntervalJob(ij, ch)
			return nil
		}
	}

	j.mux.Unlock()
	return nil
}

// Job registers a fixed-interval job in the package-level scheduler.
//
// The job runs once immediately when the scheduler starts, and then repeats
// every interval. If timeout is nil, the job keeps running until it is stopped
// by [StopAllJobs] or process shutdown. If timeout is non-nil and greater than
// zero, the job stops automatically when that duration expires.
//
// The job is only registered here; execution begins when [StartJobs] runs.
func Job(fn func(), interval time.Duration, timeout *time.Duration) (string, error) {
	return globalJobs.job(fn, interval, timeout)
}

// JobWithID registers a fixed-interval job using the provided id.
// It returns an error when the input is invalid or another active job already
// uses the same id.
func JobWithID(id string, fn func(), interval time.Duration, timeout *time.Duration) error {
	return globalJobs.jobWithID(id, fn, interval, timeout)
}

// cronJob registers a job that starts according to the provided trigger.
// If the instance is already running, scheduling begins immediately and waits
// for the next trigger. Otherwise, the job is queued until StartJobs.
//
// Example:
//
//	j.cronJob(func() { fmt.Println("daily") },
//		jobs.CronTrigger{Hour: 7, Minute: 45, Second: 0})
func (j *jobs) cronJob(fn func(), trigger CronTrigger, interval time.Duration) (string, error) {
	if err := validateCronJob(fn, trigger); err != nil {
		return "", err
	}

	id := nextJobID()
	if err := j.registerCronJob(id, fn, trigger, interval); err != nil {
		return "", err
	}
	return id, nil
}

func (j *jobs) cronJobWithID(id string, fn func(), trigger CronTrigger, interval time.Duration) error {
	if err := validateJobID(id); err != nil {
		return err
	}
	if err := validateCronJob(fn, trigger); err != nil {
		return err
	}
	return j.registerCronJob(id, fn, trigger, interval)
}

func (j *jobs) registerCronJob(id string, fn func(), trigger CronTrigger, interval time.Duration) error {
	j.mux.Lock()
	control, err := j.addControlLocked(id)
	if err != nil {
		j.mux.Unlock()
		return err
	}
	cj := cronJob{id: control.id, fn: fn, trigger: trigger, interval: interval, control: control}
	j.cronJobs = append(j.cronJobs, cj)

	if j.started.Load() {
		if ch, _ := j.stopCh.Load().(chan struct{}); ch != nil {
			j.mux.Unlock()
			j.startCronJob(cj, ch)
			return nil
		}
	}

	j.mux.Unlock()
	return nil
}

// CronJob registers a trigger-aligned job in the package-level scheduler.
//
// If interval <= 0, the job runs once per day at the time defined by trigger.
// If interval > 0, the first execution waits until the next matching trigger,
// and the job then repeats every interval.
//
// The job is only registered here; execution begins when [StartJobs] runs.
func CronJob(fn func(), trigger CronTrigger, interval time.Duration) (string, error) {
	return globalJobs.cronJob(fn, trigger, interval)
}

// CronJobWithID registers a trigger-aligned job using the provided id.
// It returns an error when the input is invalid or another active job already
// uses the same id.
func CronJobWithID(id string, fn func(), trigger CronTrigger, interval time.Duration) error {
	return globalJobs.cronJobWithID(id, fn, trigger, interval)
}

var lifecycleMu sync.Mutex

// StartJobs starts the package-level jobs scheduler.
//
// This is the entry point used by higher-level server packages such as
// `server/gin.Start(...)`. Concurrent lifecycle calls are serialized, and
// repeated starts do not duplicate running jobs.
//
// When `server.modeTest=true`, registered jobs are not started.
func StartJobs() {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	globalJobs.startJobs()
}

// RestartJobs requests a restart of the package-level scheduler.
//
// The restart flow stops currently running jobs without clearing their
// registered definitions and starts them again from the current process state.
// It is safe to call before StartJobs and never waits for a background
// receiver.
func RestartJobs() {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	stopAllJobs(false)
	globalJobs.startJobs()
}

// startJobs starts all previously registered jobs.
// If the instance is already started, the call has no additional effect.
//
// Jobs added after startJobs begin executing immediately.
//
// Example:
//
//	j.startJobs()
//	j.Job(func() { fmt.Println("starts now") }, 200*time.Millisecond, nil) // starts immediately
func (j *jobs) startJobs() {
	if viper.GetBool("server.modeTest") {
		return
	}
	if !j.started.CompareAndSwap(false, true) {
		return
	}
	ch := make(chan struct{})
	j.stopCh.Store(ch)

	j.mux.Lock()
	intervals := append([]intervalJob(nil), j.intervalJobs...)
	crons := append([]cronJob(nil), j.cronJobs...)
	j.mux.Unlock()

	for _, ij := range intervals {
		j.startIntervalJob(ij, ch)
	}
	for _, cj := range crons {
		j.startCronJob(cj, ch)
	}
	checkJobsStop.Store(true)
}

func (j *jobs) stop() {
	if !j.started.CompareAndSwap(true, false) {
		return
	}
	if ch, _ := j.stopCh.Load().(chan struct{}); ch != nil {
		close(ch)
	}
	j.wg.Wait()
}

// StopAndClear stops and clears only this instance.
// It is used internally by Destroy and global resets.
func (j *jobs) stopAndClear() {
	j.stop()

	j.mux.Lock()
	defer j.mux.Unlock()
	for _, control := range j.controls {
		control.stop()
	}
	j.intervalJobs = nil
	j.cronJobs = nil
	j.controls = make(map[string]*jobControl)
}

// destroy stops the instance jobs and removes the instance from the global registry.
// After destroy, StopAllJobs no longer affects the instance.
//
// Example:
//
//	j.destroy() // stops and unregisters this instance
func (j *jobs) destroy() {
	j.stopAndClear()
	unregister(j)
}

// StopAllJobs stops all internal scheduler instances. It is useful for
// coordinated shutdowns, tests, or global resets.
//
// Example:
//
//	jobs.StopAllJobs(true) // stops and clears all registered jobs in the process
//
// StopAllJobs stops every globally registered jobs instance.
//
// If clearJobs is false, the jobs stop but remain registered and can be
// started again later. If clearJobs is true, the jobs stop and their stored
// definitions are removed from each registered instance.
func StopAllJobs(clearJobs bool) {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	stopAllJobs(clearJobs)
}

func stopAllJobs(clearJobs bool) {
	regMu.Lock()
	list := make([]*jobs, 0, len(registry))
	for j := range registry {
		list = append(list, j)
	}
	regMu.Unlock()

	for _, j := range list {
		if clearJobs {
			j.stopAndClear()
		} else {
			j.stop()
		}
	}
	checkJobsStop.Store(false)
}

// CheckStatusJobs reports whether the package-level scheduler is currently
// marked as active.
//
// It returns true after jobs have started and false after they have been fully
// stopped.
func CheckStatusJobs() bool {
	return checkJobsStop.Load()
}

// PauseJob pauses all registered jobs matching id.
// It returns an error when the id is invalid or no matching job exists.
func PauseJob(id string) error {
	return applyToRegisteredJobs(func(j *jobs) error {
		return j.pauseJob(id)
	})
}

// ResumeJob resumes all registered jobs matching id.
// It returns an error when the id is invalid or no matching job exists.
func ResumeJob(id string) error {
	return applyToRegisteredJobs(func(j *jobs) error {
		return j.resumeJob(id)
	})
}

// StopJob stops all registered jobs matching id and removes their definitions.
// A stopped job will not be started again by RestartJobs.
func StopJob(id string) error {
	return applyToRegisteredJobs(func(j *jobs) error {
		return j.stopJob(id)
	})
}

// -------------------- Unexported internals --------------------

type intervalJob struct {
	id       string
	fn       func()
	interval time.Duration
	timeout  *time.Duration
	control  *jobControl
}

type cronJob struct {
	id       string
	fn       func()
	trigger  CronTrigger
	interval time.Duration
	control  *jobControl
}

type jobControl struct {
	id     string
	stopCh chan struct{}

	paused  atomic.Bool
	stopped atomic.Bool
	once    sync.Once
}

var (
	regMu    sync.Mutex
	registry = make(map[*jobs]struct{})
)

func register(j *jobs) {
	regMu.Lock()
	defer regMu.Unlock()
	registry[j] = struct{}{}
}

func unregister(j *jobs) {
	regMu.Lock()
	defer regMu.Unlock()
	delete(registry, j)
}

func nextJobID() string {
	return "job-" + strconv.FormatUint(jobIDCounter.Add(1), 10)
}

func (j *jobs) addControlLocked(id string) (*jobControl, error) {
	if j.controls == nil {
		j.controls = make(map[string]*jobControl)
	}
	if _, exists := j.controls[id]; exists {
		return nil, ErrDuplicateJobID
	}

	control := &jobControl{id: id, stopCh: make(chan struct{})}
	j.controls[id] = control
	return control, nil
}

func (j *jobs) pauseJob(id string) error {
	if err := validateJobID(id); err != nil {
		return err
	}
	control := j.control(id)
	if control == nil {
		return ErrJobNotFound
	}
	if control.stopped.Load() {
		return ErrJobStopped
	}
	control.paused.Store(true)
	return nil
}

func (j *jobs) resumeJob(id string) error {
	if err := validateJobID(id); err != nil {
		return err
	}
	control := j.control(id)
	if control == nil {
		return ErrJobNotFound
	}
	if control.stopped.Load() {
		return ErrJobStopped
	}
	control.paused.Store(false)
	return nil
}

func (j *jobs) stopJob(id string) error {
	if err := validateJobID(id); err != nil {
		return err
	}

	j.mux.Lock()
	defer j.mux.Unlock()
	control := j.controls[id]
	if control == nil {
		return ErrJobNotFound
	}

	delete(j.controls, id)
	j.intervalJobs = removeIntervalJob(j.intervalJobs, id)
	j.cronJobs = removeCronJob(j.cronJobs, id)
	control.stop()
	return nil
}

func (j *jobs) control(id string) *jobControl {
	j.mux.Lock()
	defer j.mux.Unlock()
	return j.controls[id]
}

func (c *jobControl) canRun() bool {
	return c != nil && !c.stopped.Load() && !c.paused.Load()
}

func (c *jobControl) stop() {
	if c == nil {
		return
	}
	c.stopped.Store(true)
	c.once.Do(func() {
		close(c.stopCh)
	})
}

func removeIntervalJob(items []intervalJob, id string) []intervalJob {
	filtered := items[:0]
	for _, item := range items {
		if item.id != id {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func removeCronJob(items []cronJob, id string) []cronJob {
	filtered := items[:0]
	for _, item := range items {
		if item.id != id {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func applyToRegisteredJobs(fn func(*jobs) error) error {
	regMu.Lock()
	list := make([]*jobs, 0, len(registry))
	for j := range registry {
		list = append(list, j)
	}
	regMu.Unlock()

	var applied bool
	var firstErr error = ErrJobNotFound
	for _, j := range list {
		err := fn(j)
		if err == nil {
			applied = true
			continue
		}
		if !errors.Is(err, ErrJobNotFound) && errors.Is(firstErr, ErrJobNotFound) {
			firstErr = err
		}
	}
	if applied {
		return nil
	}
	return firstErr
}

func validateJobID(id string) error {
	if id == "" {
		return ErrEmptyJobID
	}
	return nil
}

func validateIntervalJob(fn func(), interval time.Duration) error {
	if fn == nil {
		return ErrNilJobFunc
	}
	if interval <= 0 {
		return ErrInvalidInterval
	}
	return nil
}

func validateCronJob(fn func(), trigger CronTrigger) error {
	if fn == nil {
		return ErrNilJobFunc
	}
	if !validTrigger(trigger) {
		return ErrInvalidCronTrigger
	}
	if _, ok := nextRun(trigger, time.Now()); !ok {
		return ErrCronTriggerExpired
	}
	return nil
}

func (j *jobs) startIntervalJob(ij intervalJob, stopCh chan struct{}) {
	j.wg.Go(func() {
		ticker := time.NewTicker(ij.interval)
		defer ticker.Stop()

		var timeoutCh <-chan time.Time
		if ij.timeout != nil && *ij.timeout > 0 {
			timer := time.NewTimer(*ij.timeout)
			timeoutCh = timer.C
			defer timer.Stop()
		}

		// Run once immediately.
		if ij.control.canRun() {
			ij.fn()
		}

		for {
			select {
			case <-ticker.C:
				if ij.control.canRun() {
					ij.fn()
				}
			case <-timeoutCh:
				// Timeout expired: stop the job automatically.
				return
			case <-ij.control.stopCh:
				return
			case <-stopCh:
				return
			}
		}
	})
}

func (j *jobs) startCronJob(cj cronJob, stopCh chan struct{}) {
	j.wg.Go(func() {
		// Case 1: no interval provided, so the job runs daily.
		if cj.interval <= 0 {
			for {
				delay, ok := nextDelay(cj.trigger, time.Now())
				if !ok {
					return
				}
				timer := time.NewTimer(delay)

				select {
				case <-timer.C:
					if cj.control.canRun() {
						cj.fn()
					}
				case <-cj.control.stopCh:
					if !timer.Stop() {
						// No channel drain is needed here.
					}
					return
				case <-stopCh:
					if !timer.Stop() {
						// No channel drain is needed here.
					}
					return
				}
			}
		}

		// Case 2: align the first execution with the trigger,
		// then repeat every cj.interval.
		delay, ok := nextDelay(cj.trigger, time.Now())
		if !ok {
			return
		}
		timer := time.NewTimer(delay)

		select {
		case <-timer.C:
			if cj.control.canRun() {
				cj.fn()
			}
		case <-cj.control.stopCh:
			if !timer.Stop() {
				// No channel drain is needed here.
			}
			return
		case <-stopCh:
			if !timer.Stop() {
				// No channel drain is needed here.
			}
			return
		}

		ticker := time.NewTicker(cj.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if cj.control.canRun() {
					cj.fn()
				}
			case <-cj.control.stopCh:
				return
			case <-stopCh:
				if !timer.Stop() {
					// No channel drain is needed here.
				}
				return
			}
		}
	})
}

func nextDelay(trg CronTrigger, now time.Time) (time.Duration, bool) {
	next, ok := nextRun(trg, now)
	if !ok {
		return 0, false
	}
	return next.Sub(now), true
}

func nextRun(trg CronTrigger, now time.Time) (time.Time, bool) {
	if !validTrigger(trg) {
		return time.Time{}, false
	}

	loc := now.Location()
	startYear := now.Year()
	endYear := now.Year() + 400
	if trg.Year != nil {
		startYear = int(*trg.Year)
		endYear = startYear
	}

	for year := startYear; year <= endYear; year++ {
		startMonth := time.January
		endMonth := time.December
		if trg.Month != nil {
			startMonth = time.Month(*trg.Month)
			endMonth = startMonth
		}

		for month := startMonth; month <= endMonth; month++ {
			startDay := 1
			endDay := daysInMonth(year, month)
			if trg.Day != nil {
				if int(*trg.Day) > endDay {
					continue
				}
				startDay = int(*trg.Day)
				endDay = startDay
			}

			for day := startDay; day <= endDay; day++ {
				next := time.Date(year, month, day,
					int(trg.Hour), int(trg.Minute), int(trg.Second), 0, loc)
				if next.After(now) {
					return next, true
				}
			}
		}
	}
	return time.Time{}, false
}

func validTrigger(trg CronTrigger) bool {
	if trg.Month != nil && (*trg.Month < 1 || *trg.Month > 12) {
		return false
	}
	if trg.Day != nil && (*trg.Day < 1 || *trg.Day > 31) {
		return false
	}
	return trg.Hour <= 23 && trg.Minute <= 59 && trg.Second <= 59
}

func daysInMonth(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}
