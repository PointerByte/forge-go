// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package jobs

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func setupJobsTest(t *testing.T) {
	t.Helper()

	StopAllJobs(true)
	viper.Set("server.modeTest", false)

	t.Cleanup(func() {
		StopAllJobs(true)
		viper.Set("server.modeTest", false)
	})
}

func waitFor(t *testing.T, timeout time.Duration, check func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !check() {
		t.Fatalf("condition was not met within %s", timeout)
	}
}

func uintPtr(v uint) *uint {
	return &v
}

func TestJobRunsWithIntervalAndTimeout(t *testing.T) {
	setupJobsTest(t)

	j := newJobs()
	var hits int32

	timeout := 80 * time.Millisecond
	j.job(func() {
		atomic.AddInt32(&hits, 1)
	}, 15*time.Millisecond, &timeout)

	j.startJobs()

	waitFor(t, 120*time.Millisecond, func() bool {
		return atomic.LoadInt32(&hits) >= 2
	})

	waitFor(t, 250*time.Millisecond, func() bool {
		snapshot := atomic.LoadInt32(&hits)
		time.Sleep(50 * time.Millisecond)
		return atomic.LoadInt32(&hits) == snapshot
	})
}

func TestStartJobsIsIdempotentAndJobAddedAfterStartRunsImmediately(t *testing.T) {
	setupJobsTest(t)

	j := newJobs()
	var beforeCount int32

	j.job(func() {
		atomic.AddInt32(&beforeCount, 1)
	}, 200*time.Millisecond, nil)

	j.startJobs()
	j.startJobs()

	waitFor(t, 50*time.Millisecond, func() bool {
		return atomic.LoadInt32(&beforeCount) == 1
	})

	time.Sleep(40 * time.Millisecond)
	if got := atomic.LoadInt32(&beforeCount); got != 1 {
		t.Fatalf("expected StartJobs to be idempotent, got %d immediate executions", got)
	}

	var afterCount int32
	j.job(func() {
		atomic.AddInt32(&afterCount, 1)
	}, 100*time.Millisecond, nil)

	waitFor(t, 50*time.Millisecond, func() bool {
		return atomic.LoadInt32(&afterCount) >= 1
	})
}

func TestJobCanBePausedResumedAndStoppedByID(t *testing.T) {
	setupJobsTest(t)

	j := newJobs()
	var hits int32
	id := "cache-refresh"

	err := j.jobWithID(id, func() {
		atomic.AddInt32(&hits, 1)
	}, 20*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("expected job to be registered, got %v", err)
	}

	if err := j.jobWithID(id, func() {}, time.Second, nil); !errors.Is(err, ErrDuplicateJobID) {
		t.Fatalf("expected duplicate id error, got %v", err)
	}

	j.startJobs()

	waitFor(t, 120*time.Millisecond, func() bool {
		return atomic.LoadInt32(&hits) >= 2
	})

	if err := j.pauseJob(id); err != nil {
		t.Fatalf("expected job to pause, got %v", err)
	}

	pausedAt := atomic.LoadInt32(&hits)
	time.Sleep(80 * time.Millisecond)
	if got := atomic.LoadInt32(&hits); got != pausedAt {
		t.Fatalf("expected paused job to stop running; before=%d after=%d", pausedAt, got)
	}

	if err := j.resumeJob(id); err != nil {
		t.Fatalf("expected job to resume, got %v", err)
	}

	waitFor(t, 120*time.Millisecond, func() bool {
		return atomic.LoadInt32(&hits) > pausedAt
	})

	if err := j.pauseJob(id); err != nil {
		t.Fatalf("expected job to pause before stop, got %v", err)
	}
	stoppedAt := atomic.LoadInt32(&hits)

	if err := j.stopJob(id); err != nil {
		t.Fatalf("expected job to stop, got %v", err)
	}
	if err := j.resumeJob(id); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("expected stopped job not to resume, got %v", err)
	}

	time.Sleep(80 * time.Millisecond)
	if got := atomic.LoadInt32(&hits); got != stoppedAt {
		t.Fatalf("expected stopped job to stop running; before=%d after=%d", stoppedAt, got)
	}
}

func TestJobRegistrationReturnsSpecificErrors(t *testing.T) {
	setupJobsTest(t)

	j := newJobs()

	if _, err := j.job(nil, time.Second, nil); !errors.Is(err, ErrNilJobFunc) {
		t.Fatalf("expected nil function error, got %v", err)
	}
	if _, err := j.job(func() {}, 0, nil); !errors.Is(err, ErrInvalidInterval) {
		t.Fatalf("expected invalid interval error, got %v", err)
	}
	if err := j.jobWithID("", func() {}, time.Second, nil); !errors.Is(err, ErrEmptyJobID) {
		t.Fatalf("expected empty id error, got %v", err)
	}
	if err := j.jobWithID("specific", func() {}, time.Second, nil); err != nil {
		t.Fatalf("expected job registration, got %v", err)
	}
	if err := j.jobWithID("specific", func() {}, time.Second, nil); !errors.Is(err, ErrDuplicateJobID) {
		t.Fatalf("expected duplicate id error, got %v", err)
	}
}

func TestPackageJobCanBeControlledByID(t *testing.T) {
	setupJobsTest(t)

	var hits int32
	id := "global-refresh"
	err := JobWithID(id, func() {
		atomic.AddInt32(&hits, 1)
	}, 20*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("expected package job to be registered, got %v", err)
	}

	StartJobs()

	waitFor(t, 120*time.Millisecond, func() bool {
		return atomic.LoadInt32(&hits) >= 2
	})

	if err := PauseJob(id); err != nil {
		t.Fatalf("expected package job to pause, got %v", err)
	}
	pausedAt := atomic.LoadInt32(&hits)
	time.Sleep(80 * time.Millisecond)
	if got := atomic.LoadInt32(&hits); got != pausedAt {
		t.Fatalf("expected package job to pause; before=%d after=%d", pausedAt, got)
	}

	if err := ResumeJob(id); err != nil {
		t.Fatalf("expected package job to resume, got %v", err)
	}
	waitFor(t, 120*time.Millisecond, func() bool {
		return atomic.LoadInt32(&hits) > pausedAt
	})

	if err := StopJob(id); err != nil {
		t.Fatalf("expected package job to stop, got %v", err)
	}
	if err := PauseJob(id); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("expected stopped package job not to pause, got %v", err)
	}
}

func TestCronJobRegistrationReturnsSpecificErrors(t *testing.T) {
	setupJobsTest(t)

	j := newJobs()
	invalidMonth := uint(13)
	pastYear := uint(time.Now().Year() - 1)

	if err := j.cronJobWithID("cron-invalid", func() {}, CronTrigger{
		Month: &invalidMonth,
		Hour:  9,
	}, 0); !errors.Is(err, ErrInvalidCronTrigger) {
		t.Fatalf("expected invalid cron trigger error, got %v", err)
	}

	if err := j.cronJobWithID("cron-expired", func() {}, CronTrigger{
		Year: &pastYear,
		Hour: 9,
	}, 0); !errors.Is(err, ErrCronTriggerExpired) {
		t.Fatalf("expected expired cron trigger error, got %v", err)
	}
}

func TestCronJobRunsAtNextTrigger(t *testing.T) {
	setupJobsTest(t)

	j := newJobs()
	j.startJobs()

	var fired int32
	trigTime := time.Now().Add(2 * time.Second)
	trigger := cronTrigger{
		Hour:   uint(trigTime.Hour()),
		Minute: uint(trigTime.Minute()),
		Second: uint(trigTime.Second()),
	}

	j.cronJob(func() {
		atomic.AddInt32(&fired, 1)
	}, trigger, 0)

	waitFor(t, 4*time.Second, func() bool {
		return atomic.LoadInt32(&fired) >= 1
	})
}

func TestCronTriggerUsesYearMonthAndDay(t *testing.T) {
	now := time.Date(2026, time.June, 14, 10, 0, 0, 0, time.UTC)
	trigger := CronTrigger{
		Year:   uintPtr(2026),
		Month:  uintPtr(6),
		Day:    uintPtr(15),
		Hour:   9,
		Minute: 30,
		Second: 0,
	}

	delay, ok := nextDelay(trigger, now)
	if !ok {
		t.Fatalf("expected trigger to have a next run")
	}

	want := 23*time.Hour + 30*time.Minute
	if delay != want {
		t.Fatalf("expected delay %s, got %s", want, delay)
	}
}

func TestCronTriggerReturnsNoNextRunForPastYear(t *testing.T) {
	now := time.Date(2026, time.June, 14, 10, 0, 0, 0, time.UTC)
	trigger := CronTrigger{
		Year: uintPtr(2025),
		Hour: 9,
	}

	if _, ok := nextDelay(trigger, now); ok {
		t.Fatalf("expected past year trigger to have no next run")
	}
}

func TestCronJobWithIntervalRunsAgainAfterFirstTrigger(t *testing.T) {
	setupJobsTest(t)

	j := newJobs()
	j.startJobs()

	var hits int32
	trigTime := time.Now().Add(2 * time.Second)
	trigger := cronTrigger{
		Hour:   uint(trigTime.Hour()),
		Minute: uint(trigTime.Minute()),
		Second: uint(trigTime.Second()),
	}

	j.cronJob(func() {
		atomic.AddInt32(&hits, 1)
	}, trigger, time.Second)

	waitFor(t, 5*time.Second, func() bool {
		return atomic.LoadInt32(&hits) >= 3
	})
}

func TestStopAllJobsStopsAllRegisteredInstances(t *testing.T) {
	setupJobsTest(t)

	a := newJobs()
	b := newJobs()

	var countA int32
	var countB int32

	a.job(func() { atomic.AddInt32(&countA, 1) }, 20*time.Millisecond, nil)
	b.job(func() { atomic.AddInt32(&countB, 1) }, 20*time.Millisecond, nil)

	a.startJobs()
	b.startJobs()

	waitFor(t, 120*time.Millisecond, func() bool {
		return atomic.LoadInt32(&countA) > 1 && atomic.LoadInt32(&countB) > 1
	})

	beforeA := atomic.LoadInt32(&countA)
	beforeB := atomic.LoadInt32(&countB)

	StopAllJobs(false)

	time.Sleep(80 * time.Millisecond)

	afterA := atomic.LoadInt32(&countA)
	afterB := atomic.LoadInt32(&countB)

	if afterA != beforeA {
		t.Fatalf("expected instance A to stop; before=%d after=%d", beforeA, afterA)
	}
	if afterB != beforeB {
		t.Fatalf("expected instance B to stop; before=%d after=%d", beforeB, afterB)
	}
}

func TestDestroyUnregistersInstanceFromGlobalStop(t *testing.T) {
	setupJobsTest(t)

	j := newJobs()
	var hits int32

	j.job(func() { atomic.AddInt32(&hits, 1) }, 15*time.Millisecond, nil)
	j.startJobs()

	waitFor(t, 80*time.Millisecond, func() bool {
		return atomic.LoadInt32(&hits) >= 2
	})

	j.destroy()

	var afterDestroyHits int32
	j.job(func() { atomic.AddInt32(&afterDestroyHits, 1) }, 15*time.Millisecond, nil)
	j.startJobs()
	defer j.destroy()

	waitFor(t, 80*time.Millisecond, func() bool {
		return atomic.LoadInt32(&afterDestroyHits) >= 2
	})

	beforeGlobalStop := atomic.LoadInt32(&afterDestroyHits)
	StopAllJobs(true)
	time.Sleep(60 * time.Millisecond)
	afterGlobalStop := atomic.LoadInt32(&afterDestroyHits)

	if afterGlobalStop == beforeGlobalStop {
		t.Fatalf("expected unregistered instance to keep running after global stop; before=%d after=%d", beforeGlobalStop, afterGlobalStop)
	}
}

func TestStartJobsDoesNothingInModeTest(t *testing.T) {
	setupJobsTest(t)

	viper.Set("server.modeTest", true)

	j := newJobs()
	var hits int32

	j.job(func() { atomic.AddInt32(&hits, 1) }, 15*time.Millisecond, nil)
	j.startJobs()

	time.Sleep(60 * time.Millisecond)

	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("expected no executions in mode test, got %d", got)
	}
}

func TestRestartJobsBeforeStartReturnsAndStartsRegisteredJobs(t *testing.T) {
	setupJobsTest(t)

	var hits int32
	if _, err := Job(func() {
		atomic.AddInt32(&hits, 1)
	}, 15*time.Millisecond, nil); err != nil {
		t.Fatalf("expected package job registration, got %v", err)
	}

	returned := make(chan struct{})
	go func() {
		RestartJobs()
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("RestartJobs blocked before StartJobs")
	}

	waitFor(t, 120*time.Millisecond, func() bool {
		return atomic.LoadInt32(&hits) >= 2
	})
}

func TestRestartJobsPreservesDefinitions(t *testing.T) {
	setupJobsTest(t)

	var hits int32
	if err := JobWithID("restart-preserves", func() {
		atomic.AddInt32(&hits, 1)
	}, 15*time.Millisecond, nil); err != nil {
		t.Fatalf("expected package job registration, got %v", err)
	}
	StartJobs()

	waitFor(t, 120*time.Millisecond, func() bool {
		return atomic.LoadInt32(&hits) >= 2
	})
	before := atomic.LoadInt32(&hits)

	RestartJobs()

	waitFor(t, 120*time.Millisecond, func() bool {
		return atomic.LoadInt32(&hits) > before
	})
}

func TestConcurrentPackageLifecycleCallsReturn(t *testing.T) {
	setupJobsTest(t)

	if _, err := Job(func() {}, time.Second, nil); err != nil {
		t.Fatalf("expected package job registration, got %v", err)
	}

	const calls = 24
	done := make(chan struct{}, calls)
	for i := 0; i < calls; i++ {
		go func(call int) {
			switch call % 3 {
			case 0:
				StartJobs()
			case 1:
				RestartJobs()
			default:
				StopAllJobs(false)
			}
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < calls; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("concurrent lifecycle call did not return")
		}
	}
}
