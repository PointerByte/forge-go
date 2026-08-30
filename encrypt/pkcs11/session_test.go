// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestSessionIsDead(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "not a token error", err: errors.New("boom"), want: false},
		{name: "session handle invalid", err: newTokenError("C_Sign", ckrSessionHandleInval), want: true},
		{name: "session closed", err: newTokenError("C_Sign", ckrSessionClosed), want: true},
		{name: "device removed", err: newTokenError("C_Sign", ckrDeviceRemoved), want: true},
		{name: "token not present", err: newTokenError("C_Sign", ckrTokenNotPresent), want: true},
		{name: "not logged in", err: newTokenError("C_Sign", ckrUserNotLoggedIn), want: true},
		{name: "wrapped", err: errors.Join(errors.New("ctx"), newTokenError("C_Sign", ckrDeviceError)), want: true},
		{name: "signature invalid is not fatal", err: newTokenError("C_Verify", ckrSignatureInvalid), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sessionIsDead(test.err); got != test.want {
				t.Fatalf("sessionIsDead(%v) = %v, want %v", test.err, got, test.want)
			}
		})
	}
}

func TestSlotStateRequireMechanism(t *testing.T) {
	slot := &slotState{mechanisms: map[mechanism]bool{ckmAESGCM: true}}

	if err := slot.requireMechanism(ckmAESGCM); err != nil {
		t.Fatalf("requireMechanism(supported) = %v", err)
	}
	err := slot.requireMechanism(ckmEdDSA)
	if err == nil {
		t.Fatal("requireMechanism(unsupported) must fail")
	}
	// Failing rather than falling back is the point: a caller asking for a
	// hardware-backed operation must never silently get a software one.
	var unsupported unsupportedMechanismError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error = %T, want unsupportedMechanismError", err)
	}
}

// TestSlotStateLoginOnce pins that a token is authenticated exactly once even
// under concurrency: PKCS#11 login state is per-slot and shared across the
// application's sessions.
func TestSlotStateLoginOnce(t *testing.T) {
	fake := &fakeModule{}
	slot := &slotState{}

	var pinCalls int
	var pinMu sync.Mutex
	provider := func(context.Context) (string, error) {
		pinMu.Lock()
		pinCalls++
		pinMu.Unlock()
		return "1234", nil
	}

	var group sync.WaitGroup
	for range 20 {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := slot.login(context.Background(), fake, 1, provider); err != nil {
				t.Errorf("login() error = %v", err)
			}
		}()
	}
	group.Wait()

	if fake.loginCalls != 1 {
		t.Fatalf("C_Login called %d times, want 1", fake.loginCalls)
	}
	if pinCalls != 1 {
		t.Fatalf("PinProvider called %d times, want 1", pinCalls)
	}
}

func TestSlotStateLoginPropagatesErrors(t *testing.T) {
	slot := &slotState{}
	pinErr := errors.New("vault unavailable")

	err := slot.login(context.Background(), &fakeModule{}, 1, func(context.Context) (string, error) {
		return "", pinErr
	})
	if !errors.Is(err, pinErr) {
		t.Fatalf("login() = %v, want the pin provider error", err)
	}

	loginErr := newTokenError("C_Login", ckrPinIncorrect)
	fake := &fakeModule{loginFn: func(sessionHandle, string) error { return loginErr }}
	if err := slot.login(context.Background(), fake, 1, testPin); !errors.Is(err, loginErr) {
		t.Fatalf("login() = %v, want the token error", err)
	}
	// A failed login must not latch: the next attempt has to retry.
	if slot.loggedIn {
		t.Fatal("a failed login must not mark the slot authenticated")
	}
}

// TestSlotStateResetLogin covers the recovery path for a network HSM that
// restarts: without clearing the flag the service would never re-authenticate.
func TestSlotStateResetLogin(t *testing.T) {
	fake := &fakeModule{}
	slot := &slotState{}

	if err := slot.login(context.Background(), fake, 1, testPin); err != nil {
		t.Fatalf("login() error = %v", err)
	}
	slot.resetLogin()
	if err := slot.login(context.Background(), fake, 1, testPin); err != nil {
		t.Fatalf("login() after reset error = %v", err)
	}
	if fake.loginCalls != 2 {
		t.Fatalf("C_Login called %d times, want 2 after a reset", fake.loginCalls)
	}
}

func TestSessionPoolReusesSessions(t *testing.T) {
	fake := &fakeModule{}
	pool := newSessionPool(1, 2)

	first, err := pool.acquire(context.Background(), fake)
	if err != nil {
		t.Fatalf("acquire() error = %v", err)
	}
	pool.release(fake, first, nil)

	second, err := pool.acquire(context.Background(), fake)
	if err != nil {
		t.Fatalf("acquire() error = %v", err)
	}
	if second != first {
		t.Fatalf("acquire() = %d, want the pooled session %d", second, first)
	}
	if fake.openSessions != 1 {
		t.Fatalf("opened %d sessions, want 1 reused", fake.openSessions)
	}
	pool.release(fake, second, nil)
}

func TestSessionPoolDiscardsDeadSessions(t *testing.T) {
	fake := &fakeModule{}
	pool := newSessionPool(1, 2)

	session, err := pool.acquire(context.Background(), fake)
	if err != nil {
		t.Fatalf("acquire() error = %v", err)
	}
	pool.release(fake, session, newTokenError("C_Sign", ckrSessionClosed))

	if fake.closedSessions != 1 {
		t.Fatalf("closed %d sessions, want the dead one closed", fake.closedSessions)
	}
	next, err := pool.acquire(context.Background(), fake)
	if err != nil {
		t.Fatalf("acquire() error = %v", err)
	}
	if next == session {
		t.Fatal("a dead session must not be handed out again")
	}
}

// TestSessionPoolBoundsConcurrency pins the invariant that makes the pool safe:
// PKCS#11 operations are stateful pairs on one session, so a session may never
// be handed to two callers at once.
func TestSessionPoolBoundsConcurrency(t *testing.T) {
	fake := &fakeModule{}
	pool := newSessionPool(1, 3)

	var mu sync.Mutex
	inUse := make(map[sessionHandle]bool)
	maxConcurrent := 0
	current := 0

	var group sync.WaitGroup
	for range 50 {
		group.Add(1)
		go func() {
			defer group.Done()
			session, err := pool.acquire(context.Background(), fake)
			if err != nil {
				t.Errorf("acquire() error = %v", err)
				return
			}

			mu.Lock()
			if inUse[session] {
				t.Errorf("session %d handed out twice concurrently", session)
			}
			inUse[session] = true
			current++
			if current > maxConcurrent {
				maxConcurrent = current
			}
			mu.Unlock()

			mu.Lock()
			delete(inUse, session)
			current--
			mu.Unlock()

			pool.release(fake, session, nil)
		}()
	}
	group.Wait()

	if maxConcurrent > 3 {
		t.Fatalf("observed %d concurrent sessions, want at most 3", maxConcurrent)
	}
}

func TestSessionPoolHonoursCancellation(t *testing.T) {
	fake := &fakeModule{}
	pool := newSessionPool(1, 1)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := pool.acquire(cancelled, fake); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire(cancelled) = %v, want context.Canceled", err)
	}

	// With the single slot taken, a cancelled waiter must give up rather than
	// block: an in-flight PKCS#11 call cannot be interrupted, so cancellation
	// gates entry instead.
	held, err := pool.acquire(context.Background(), fake)
	if err != nil {
		t.Fatalf("acquire() error = %v", err)
	}
	waiting, cancelWaiting := context.WithCancel(context.Background())
	go cancelWaiting()
	if _, err := pool.acquire(waiting, fake); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire(blocked) = %v, want context.Canceled", err)
	}
	pool.release(fake, held, nil)
}

func TestSessionPoolReleasesSlotOnOpenFailure(t *testing.T) {
	openErr := newTokenError("C_OpenSession", ckrSessionCount)
	fake := &fakeModule{openSessionFn: func(uint64) (sessionHandle, error) { return 0, openErr }}
	pool := newSessionPool(1, 1)

	if _, err := pool.acquire(context.Background(), fake); !errors.Is(err, openErr) {
		t.Fatalf("acquire() = %v, want the open error", err)
	}
	// The semaphore slot must have been given back, or the pool would deadlock
	// after a transient failure.
	fake.openSessionFn = nil
	if _, err := pool.acquire(context.Background(), fake); err != nil {
		t.Fatalf("acquire() after a failure error = %v", err)
	}
}

func TestSessionPoolDrain(t *testing.T) {
	fake := &fakeModule{}
	pool := newSessionPool(1, 2)

	first, _ := pool.acquire(context.Background(), fake)
	pool.release(fake, first, nil)

	if err := pool.drain(fake); err != nil {
		t.Fatalf("drain() error = %v", err)
	}
	if fake.closedSessions != 1 {
		t.Fatalf("closed %d sessions, want 1", fake.closedSessions)
	}
	if err := pool.drain(fake); err != nil {
		t.Fatalf("drain() on an empty pool error = %v", err)
	}
}

func TestNewSessionPoolClampsSize(t *testing.T) {
	if pool := newSessionPool(1, 0); cap(pool.sem) != 1 {
		t.Fatalf("cap = %d, want a pool of at least one session", cap(pool.sem))
	}
}

// TestAcquireModuleInitializesOnce pins the C_Initialize contract: it may run
// only once per library per process, so repositories sharing a path share one
// initialized module.
func TestAcquireModuleInitializesOnce(t *testing.T) {
	fake := &fakeModule{}
	installFake(t, fake)

	first, err := acquireModule("/nonexistent/forge-test.so")
	if err != nil {
		t.Fatalf("acquireModule() error = %v", err)
	}
	second, err := acquireModule("/nonexistent/forge-test.so")
	if err != nil {
		t.Fatalf("acquireModule() error = %v", err)
	}

	if first != second {
		t.Fatal("the same library path must yield the same entry")
	}
	if fake.initializeCalls != 1 {
		t.Fatalf("C_Initialize called %d times, want 1", fake.initializeCalls)
	}
	if refs := first.refs.Load(); refs != 2 {
		t.Fatalf("refs = %d, want 2", refs)
	}
}

func TestAcquireModulePropagatesLoadError(t *testing.T) {
	previous := newModuleFn
	t.Cleanup(func() {
		newModuleFn = previous
		resetRegistry()
	})
	resetRegistry()

	loadErr := errors.New("dlopen failed")
	newModuleFn = func(string) (module, error) { return nil, loadErr }

	if _, err := acquireModule("/nonexistent/broken.so"); !errors.Is(err, loadErr) {
		t.Fatalf("acquireModule() = %v, want the load error", err)
	}
	// The failure is cached by sync.Once, so a retry reports the same error
	// rather than dlopen-ing a known-bad library on every call.
	if _, err := acquireModule("/nonexistent/broken.so"); !errors.Is(err, loadErr) {
		t.Fatalf("acquireModule() retry = %v, want the cached error", err)
	}
}

func TestAcquireModulePropagatesInitializeError(t *testing.T) {
	initErr := newTokenError("C_Initialize", ckrDeviceError)
	installFake(t, &fakeModule{initializeFn: func() error { return initErr }})

	if _, err := acquireModule("/nonexistent/forge-test.so"); !errors.Is(err, initErr) {
		t.Fatalf("acquireModule() = %v, want the initialize error", err)
	}
}

func TestResolveSlotIDByLabel(t *testing.T) {
	fake := &fakeModule{
		slotsFn: func(bool) ([]slotInfo, error) {
			return []slotInfo{
				{ID: 0, TokenLabel: "other", TokenPresent: true},
				{ID: 5, TokenLabel: "forge-hsm ", TokenPresent: true},
			}, nil
		},
	}
	entry := &moduleEntry{mod: fake, slots: map[uint64]*slotState{}}

	got, err := entry.resolveSlotID(&config{tokenLabel: "forge-hsm"})
	if err != nil {
		t.Fatalf("resolveSlotID() error = %v", err)
	}
	if got != 5 {
		t.Fatalf("resolveSlotID() = %d, want 5", got)
	}

	if _, err := entry.resolveSlotID(&config{tokenLabel: "absent"}); err == nil {
		t.Fatal("resolveSlotID() must fail when no token carries the label")
	}
}

func TestResolveSlotIDBySlotNumber(t *testing.T) {
	entry := &moduleEntry{mod: &fakeModule{}, slots: map[uint64]*slotState{}}

	got, err := entry.resolveSlotID(&config{hasSlotID: true, slotID: 9})
	if err != nil || got != 9 {
		t.Fatalf("resolveSlotID() = %d, %v, want 9", got, err)
	}
	if _, err := entry.resolveSlotID(&config{}); !errors.Is(err, ErrTokenRequired) {
		t.Fatalf("resolveSlotID() = %v, want ErrTokenRequired", err)
	}
}

func TestSlotForCachesMechanisms(t *testing.T) {
	var mechanismCalls int
	fake := &fakeModule{
		mechanismsFn: func(uint64) ([]mechanism, error) {
			mechanismCalls++
			return []mechanism{ckmAESGCM}, nil
		},
	}
	entry := &moduleEntry{mod: fake, slots: map[uint64]*slotState{}}
	cfg := &config{tokenLabel: "forge-hsm", maxSession: 4}

	first, err := entry.slotFor(cfg)
	if err != nil {
		t.Fatalf("slotFor() error = %v", err)
	}
	second, err := entry.slotFor(cfg)
	if err != nil {
		t.Fatalf("slotFor() error = %v", err)
	}

	if first != second {
		t.Fatal("slotFor() must cache the slot state")
	}
	if mechanismCalls != 1 {
		t.Fatalf("C_GetMechanismList called %d times, want 1", mechanismCalls)
	}
	if !first.supports(ckmAESGCM) || first.supports(ckmEdDSA) {
		t.Fatal("the cached mechanism set is wrong")
	}
}

func TestSlotForPropagatesMechanismError(t *testing.T) {
	mechErr := newTokenError("C_GetMechanismList", ckrDeviceError)
	fake := &fakeModule{mechanismsFn: func(uint64) ([]mechanism, error) { return nil, mechErr }}
	entry := &moduleEntry{mod: fake, slots: map[uint64]*slotState{}}

	if _, err := entry.slotFor(&config{tokenLabel: "forge-hsm", maxSession: 1}); !errors.Is(err, mechErr) {
		t.Fatalf("slotFor() = %v, want the mechanism error", err)
	}
}

// TestPoolSizeClampsToToken pins that the configured concurrency never exceeds
// what the token can serve.
func TestPoolSizeClampsToToken(t *testing.T) {
	fake := &fakeModule{
		slotsFn: func(bool) ([]slotInfo, error) {
			return []slotInfo{{ID: 1, TokenLabel: "forge-hsm", TokenPresent: true, MaxSessions: 2}}, nil
		},
	}
	entry := &moduleEntry{mod: fake, slots: map[uint64]*slotState{}}

	if got := entry.poolSize(&config{maxSession: 8}, 1); got != 2 {
		t.Fatalf("poolSize() = %d, want it clamped to 2", got)
	}
	if got := entry.poolSize(&config{maxSession: 1}, 1); got != 1 {
		t.Fatalf("poolSize() = %d, want 1", got)
	}
	// An unknown slot or an unlimited token leaves the configured value alone.
	if got := entry.poolSize(&config{maxSession: 8}, 99); got != 8 {
		t.Fatalf("poolSize() = %d, want 8", got)
	}
}

func TestPoolSizeSurvivesSlotError(t *testing.T) {
	fake := &fakeModule{slotsFn: func(bool) ([]slotInfo, error) { return nil, errors.New("boom") }}
	entry := &moduleEntry{mod: fake, slots: map[uint64]*slotState{}}

	if got := entry.poolSize(&config{maxSession: 6}, 1); got != 6 {
		t.Fatalf("poolSize() = %d, want the configured value kept", got)
	}
}

func TestShutdownFinalizes(t *testing.T) {
	var finalized int
	fake := &fakeModule{finalizeFn: func() error { finalized++; return nil }}
	installFake(t, fake)

	if _, err := acquireModule("/nonexistent/forge-test.so"); err != nil {
		t.Fatalf("acquireModule() error = %v", err)
	}
	if err := Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if finalized != 1 {
		t.Fatalf("C_Finalize called %d times, want 1", finalized)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Shutdown(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Shutdown(cancelled) = %v", err)
	}
}

func TestResolveModulePath(t *testing.T) {
	// A path that cannot be resolved is used as given, so the error surfaces
	// from dlopen rather than from path resolution.
	if got := resolveModulePath("/nonexistent/forge-test.so"); got == "" {
		t.Fatal("resolveModulePath() returned empty")
	}
	if got := resolveModulePath("/usr/lib64"); got == "" {
		t.Fatal("resolveModulePath() returned empty for an existing path")
	}
}
