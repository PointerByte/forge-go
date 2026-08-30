// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// moduleEntry is one loaded PKCS#11 library, shared by every repository that
// points at the same file. C_Initialize may only run once per library per
// process, so the entry owns that call.
type moduleEntry struct {
	path string

	once sync.Once
	mod  module
	err  error

	refs atomic.Int64

	mu    sync.Mutex
	slots map[uint64]*slotState
}

// moduleRegistry maps a resolved library path to its entry. Paths are resolved
// through EvalSymlinks so that /usr/lib64/pkcs11/opensc-pkcs11.so and its
// target collapse onto one entry instead of initializing the library twice.
var moduleRegistry = struct {
	sync.Mutex
	entries map[string]*moduleEntry
}{entries: make(map[string]*moduleEntry)}

// resolveModulePath canonicalises a library path for registry lookup. A path
// that cannot be resolved is used as given, so a missing file still produces a
// dlopen error rather than a confusing path error.
func resolveModulePath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return absolute
	}
	return resolved
}

// acquireModule returns the shared entry for path, loading and initializing the
// library on first use and incrementing its reference count.
func acquireModule(path string) (*moduleEntry, error) {
	key := resolveModulePath(path)

	moduleRegistry.Lock()
	entry, ok := moduleRegistry.entries[key]
	if !ok {
		entry = &moduleEntry{path: key, slots: make(map[uint64]*slotState)}
		moduleRegistry.entries[key] = entry
	}
	moduleRegistry.Unlock()

	entry.once.Do(func() {
		mod, err := newModuleFn(key)
		if err != nil {
			entry.err = err
			return
		}
		if err := mod.Initialize(); err != nil {
			entry.err = err
			return
		}
		entry.mod = mod
	})
	if entry.err != nil {
		return nil, entry.err
	}

	entry.refs.Add(1)
	return entry, nil
}

// release drops one reference. It deliberately does not call C_Finalize: two
// repositories may share the library through paths EvalSymlinks could not
// collapse, and finalizing under a live user is far worse than leaving the
// library initialized for the life of the process. Shutdown does that
// explicitly when a caller really wants it.
func (e *moduleEntry) release() error {
	e.refs.Add(-1)

	e.mu.Lock()
	slots := make([]*slotState, 0, len(e.slots))
	for _, slot := range e.slots {
		slots = append(slots, slot)
	}
	e.mu.Unlock()

	var joined error
	for _, slot := range slots {
		if err := slot.pool.drain(e.mod); err != nil {
			joined = errors.Join(joined, err)
		}
		// Closing every session on a slot makes the token drop the login, so
		// the cached flag has to go with them or the next session would skip
		// C_Login and fail with CKR_USER_NOT_LOGGED_IN.
		slot.resetLogin()
	}
	return joined
}

// slotState caches what is per-token: the advertised mechanism set, the session
// pool, and whether the application has logged in.
type slotState struct {
	id         uint64
	mechanisms map[mechanism]bool
	pool       *sessionPool

	loginMu  sync.Mutex
	loggedIn bool
}

// supports reports whether the token advertised mech in C_GetMechanismList.
func (s *slotState) supports(mech mechanism) bool {
	return s.mechanisms[mech]
}

// requireMechanism returns a descriptive error when the token cannot perform
// mech. It never downgrades the operation to software: a caller asking for a
// hardware-backed operation has to be told when the hardware cannot do it.
func (s *slotState) requireMechanism(mech mechanism) error {
	if s.supports(mech) {
		return nil
	}
	return errUnsupportedMechanism(mech)
}

// login authenticates once per token. PKCS#11 login state is per-slot and
// shared across the application's sessions, so repeating it is both unnecessary
// and, on some tokens, an error.
func (s *slotState) login(ctx context.Context, mod module, session sessionHandle, provider PinProvider) error {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()

	if s.loggedIn {
		return nil
	}

	pin, err := provider(ctx)
	if err != nil {
		return fmt.Errorf("pkcs11: obtain pin: %w", err)
	}
	if err := mod.Login(session, pin); err != nil {
		return err
	}

	s.loggedIn = true
	return nil
}

// resetLogin clears the login flag after the token dropped the session, so a
// network HSM that restarts is re-authenticated instead of failing forever.
func (s *slotState) resetLogin() {
	s.loginMu.Lock()
	s.loggedIn = false
	s.loginMu.Unlock()
}

// sessionPool hands out exclusive sessions. Exclusivity is required, not an
// optimisation: C_FindObjectsInit/C_FindObjects/C_FindObjectsFinal and
// C_SignInit/C_Sign are stateful pairs on one session and cannot interleave.
type sessionPool struct {
	slot uint64
	sem  chan struct{}
	idle chan sessionHandle
}

func newSessionPool(slot uint64, size int) *sessionPool {
	if size < 1 {
		size = 1
	}
	return &sessionPool{
		slot: slot,
		sem:  make(chan struct{}, size),
		idle: make(chan sessionHandle, size),
	}
}

// acquire takes a session, opening one if none is idle. This is the only place
// the context is honoured: a PKCS#11 call already in flight cannot be
// interrupted, so cancellation gates entry rather than aborting work.
func (p *sessionPool) acquire(ctx context.Context, mod module) (sessionHandle, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}

	select {
	case session := <-p.idle:
		return session, nil
	default:
	}

	session, err := mod.OpenSession(p.slot)
	if err != nil {
		<-p.sem
		return 0, err
	}
	return session, nil
}

// release returns a session to the pool, or closes it when the operation showed
// the token dropped it.
func (p *sessionPool) release(mod module, session sessionHandle, opErr error) {
	defer func() { <-p.sem }()

	if sessionIsDead(opErr) {
		_ = mod.CloseSession(session)
		return
	}

	select {
	case p.idle <- session:
	default:
		// The pool is full, which can only happen if capacity shrank; closing
		// is the correct disposal.
		_ = mod.CloseSession(session)
	}
}

// drain closes every idle session. In-flight sessions are not tracked here:
// they return to a pool nobody reads afterwards and are reclaimed when the
// process exits.
//
// Callers must reset the slot's login state afterwards: a token drops the
// login once its last session closes.
func (p *sessionPool) drain(mod module) error {
	var joined error
	for {
		select {
		case session := <-p.idle:
			if err := mod.CloseSession(session); err != nil {
				joined = errors.Join(joined, err)
			}
		default:
			return joined
		}
	}
}

// sessionIsDead reports whether err means the token invalidated the session, in
// which case it must not go back into the pool and the login must be redone.
func sessionIsDead(err error) bool {
	if err == nil {
		return false
	}
	var tokenErr tokenError
	if !errors.As(err, &tokenErr) {
		return false
	}
	switch tokenErr.code {
	case ckrSessionHandleInval, ckrSessionClosed, ckrDeviceRemoved,
		ckrTokenNotPresent, ckrDeviceError, ckrCryptokiNotInitiali,
		ckrUserNotLoggedIn:
		return true
	default:
		return false
	}
}

// slotFor resolves the configured token to a slot, caching its mechanism list
// and session pool.
func (e *moduleEntry) slotFor(cfg *config) (*slotState, error) {
	slotID, err := e.resolveSlotID(cfg)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if state, ok := e.slots[slotID]; ok {
		return state, nil
	}

	mechanisms, err := e.mod.Mechanisms(slotID)
	if err != nil {
		return nil, err
	}
	supported := make(map[mechanism]bool, len(mechanisms))
	for _, mech := range mechanisms {
		supported[mech] = true
	}

	state := &slotState{
		id:         slotID,
		mechanisms: supported,
		pool:       newSessionPool(slotID, e.poolSize(cfg, slotID)),
	}
	e.slots[slotID] = state
	return state, nil
}

// resolveSlotID maps the configured token label to a slot id, or uses the
// configured slot id directly.
func (e *moduleEntry) resolveSlotID(cfg *config) (uint64, error) {
	if cfg.tokenLabel == "" {
		if cfg.hasSlotID {
			return cfg.slotID, nil
		}
		return 0, ErrTokenRequired
	}

	slots, err := e.mod.Slots(true)
	if err != nil {
		return 0, err
	}
	for _, slot := range slots {
		if strings.TrimSpace(slot.TokenLabel) == cfg.tokenLabel {
			return slot.ID, nil
		}
	}
	return 0, fmt.Errorf("pkcs11: no token labelled %q is present", cfg.tokenLabel)
}

// poolSize clamps the configured concurrency to what the token allows.
func (e *moduleEntry) poolSize(cfg *config, slotID uint64) int {
	size := cfg.maxSession
	slots, err := e.mod.Slots(true)
	if err != nil {
		return size
	}
	for _, slot := range slots {
		if slot.ID != slotID {
			continue
		}
		if slot.MaxSessions > 0 && uint64(size) > slot.MaxSessions {
			return int(slot.MaxSessions)
		}
	}
	return size
}

// Shutdown finalizes every PKCS#11 library this process loaded and clears the
// registry.
//
// It is separate from Close because C_Finalize tears down state shared by every
// user of the library in the process. Call it once, on the way out, when no
// repository is in use. Most services never need it: leaving a library
// initialized until the process exits is harmless.
func Shutdown(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	moduleRegistry.Lock()
	entries := make([]*moduleEntry, 0, len(moduleRegistry.entries))
	for _, entry := range moduleRegistry.entries {
		entries = append(entries, entry)
	}
	moduleRegistry.entries = make(map[string]*moduleEntry)
	moduleRegistry.Unlock()

	var joined error
	for _, entry := range entries {
		if entry.mod == nil {
			continue
		}
		if err := entry.mod.Finalize(); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	return joined
}
