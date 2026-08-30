// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/spf13/viper"
)

// fakeModule is an in-memory PKCS#11 module. Unset function fields report a
// descriptive error instead of panicking, so a test only wires the calls it
// exercises.
type fakeModule struct {
	mu sync.Mutex

	initializeFn      func() error
	finalizeFn        func() error
	slotsFn           func(bool) ([]slotInfo, error)
	mechanismsFn      func(uint64) ([]mechanism, error)
	openSessionFn     func(uint64) (sessionHandle, error)
	closeSessionFn    func(sessionHandle) error
	loginFn           func(sessionHandle, string) error
	logoutFn          func(sessionHandle) error
	findObjectsFn     func(sessionHandle, []attribute) ([]objectHandle, error)
	getAttributesFn   func(sessionHandle, objectHandle, []attributeType) ([]attribute, error)
	setAttributesFn   func(sessionHandle, objectHandle, []attribute) error
	destroyObjectFn   func(sessionHandle, objectHandle) error
	generateKeyFn     func(sessionHandle, mechanism, []attribute) (objectHandle, error)
	generateKeyPairFn func(sessionHandle, mechanism, []attribute, []attribute) (objectHandle, objectHandle, error)
	deriveKeyFn       func(sessionHandle, mechanism, mechanismParams, objectHandle, []attribute) (objectHandle, error)
	encryptFn         func(sessionHandle, mechanism, mechanismParams, objectHandle, []byte) ([]byte, error)
	decryptFn         func(sessionHandle, mechanism, mechanismParams, objectHandle, []byte) ([]byte, error)
	signFn            func(sessionHandle, mechanism, mechanismParams, objectHandle, []byte) ([]byte, error)
	verifyFn          func(sessionHandle, mechanism, mechanismParams, objectHandle, []byte, []byte) error

	// counters observable by tests.
	initializeCalls int
	loginCalls      int
	openSessions    int
	closedSessions  int
	nextSession     sessionHandle
}

var errFakeNotWired = errors.New("fake: call not wired")

func (f *fakeModule) Initialize() error {
	f.mu.Lock()
	f.initializeCalls++
	f.mu.Unlock()
	if f.initializeFn != nil {
		return f.initializeFn()
	}
	return nil
}

func (f *fakeModule) Finalize() error {
	if f.finalizeFn != nil {
		return f.finalizeFn()
	}
	return nil
}

func (f *fakeModule) Slots(tokenPresent bool) ([]slotInfo, error) {
	if f.slotsFn != nil {
		return f.slotsFn(tokenPresent)
	}
	return []slotInfo{{ID: 1, TokenLabel: "forge-hsm", TokenPresent: true}}, nil
}

func (f *fakeModule) Mechanisms(slot uint64) ([]mechanism, error) {
	if f.mechanismsFn != nil {
		return f.mechanismsFn(slot)
	}
	return allMechanisms(), nil
}

func (f *fakeModule) OpenSession(uint64) (sessionHandle, error) {
	if f.openSessionFn != nil {
		return f.openSessionFn(0)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.openSessions++
	f.nextSession++
	return f.nextSession, nil
}

func (f *fakeModule) CloseSession(session sessionHandle) error {
	f.mu.Lock()
	f.closedSessions++
	f.mu.Unlock()
	if f.closeSessionFn != nil {
		return f.closeSessionFn(session)
	}
	return nil
}

func (f *fakeModule) Login(session sessionHandle, pin string) error {
	f.mu.Lock()
	f.loginCalls++
	f.mu.Unlock()
	if f.loginFn != nil {
		return f.loginFn(session, pin)
	}
	return nil
}

func (f *fakeModule) Logout(session sessionHandle) error {
	if f.logoutFn != nil {
		return f.logoutFn(session)
	}
	return nil
}

func (f *fakeModule) FindObjects(session sessionHandle, template []attribute) ([]objectHandle, error) {
	if f.findObjectsFn != nil {
		return f.findObjectsFn(session, template)
	}
	return []objectHandle{42}, nil
}

func (f *fakeModule) GetAttributes(session sessionHandle, object objectHandle, types []attributeType) ([]attribute, error) {
	if f.getAttributesFn != nil {
		return f.getAttributesFn(session, object, types)
	}
	return nil, errFakeNotWired
}

func (f *fakeModule) SetAttributes(session sessionHandle, object objectHandle, template []attribute) error {
	if f.setAttributesFn != nil {
		return f.setAttributesFn(session, object, template)
	}
	return nil
}

func (f *fakeModule) DestroyObject(session sessionHandle, object objectHandle) error {
	if f.destroyObjectFn != nil {
		return f.destroyObjectFn(session, object)
	}
	return nil
}

func (f *fakeModule) GenerateKey(session sessionHandle, mech mechanism, template []attribute) (objectHandle, error) {
	if f.generateKeyFn != nil {
		return f.generateKeyFn(session, mech, template)
	}
	return 7, nil
}

func (f *fakeModule) GenerateKeyPair(session sessionHandle, mech mechanism, public, private []attribute) (objectHandle, objectHandle, error) {
	if f.generateKeyPairFn != nil {
		return f.generateKeyPairFn(session, mech, public, private)
	}
	return 8, 9, nil
}

func (f *fakeModule) DeriveKey(session sessionHandle, mech mechanism, params mechanismParams, base objectHandle, template []attribute) (objectHandle, error) {
	if f.deriveKeyFn != nil {
		return f.deriveKeyFn(session, mech, params, base, template)
	}
	return 0, errFakeNotWired
}

func (f *fakeModule) Encrypt(session sessionHandle, mech mechanism, params mechanismParams, key objectHandle, plaintext []byte) ([]byte, error) {
	if f.encryptFn != nil {
		return f.encryptFn(session, mech, params, key, plaintext)
	}
	return nil, errFakeNotWired
}

func (f *fakeModule) Decrypt(session sessionHandle, mech mechanism, params mechanismParams, key objectHandle, ciphertext []byte) ([]byte, error) {
	if f.decryptFn != nil {
		return f.decryptFn(session, mech, params, key, ciphertext)
	}
	return nil, errFakeNotWired
}

func (f *fakeModule) Sign(session sessionHandle, mech mechanism, params mechanismParams, key objectHandle, message []byte) ([]byte, error) {
	if f.signFn != nil {
		return f.signFn(session, mech, params, key, message)
	}
	return nil, errFakeNotWired
}

func (f *fakeModule) Verify(session sessionHandle, mech mechanism, params mechanismParams, key objectHandle, message, signature []byte) error {
	if f.verifyFn != nil {
		return f.verifyFn(session, mech, params, key, message, signature)
	}
	return errFakeNotWired
}

// allMechanisms is every mechanism the package can ask for, so a default fake
// token supports everything.
func allMechanisms() []mechanism {
	return []mechanism{
		ckmRSAPKCSKeyPairGen, ckmRSAPKCSOAEP, ckmSHA256RSAPKCS, ckmSHA256RSAPKCSPSS,
		ckmECKeyPairGen, ckmECDH1Derive, ckmAESKeyGen, ckmAESGCM, ckmSHA256HMAC,
		ckmSHA256, ckmECEdwardsKeyPairGe, ckmEdDSA, ckmGenericSecretKeyGe,
		ckmHKDFDerive, ckmRSAPKCS, ckmRSAPKCSPSS,
	}
}

// installFake points newModuleFn at fake, resets the module registry, and
// restores both plus viper on cleanup. Every test that touches a backend needs
// it, because the registry is process-wide by design.
func installFake(t *testing.T, fake *fakeModule) {
	t.Helper()

	previous := newModuleFn
	t.Cleanup(func() {
		newModuleFn = previous
		resetRegistry()
		viper.Reset()
	})

	resetRegistry()
	newModuleFn = func(string) (module, error) { return fake, nil }
}

// resetRegistry clears the process-wide module registry between tests.
func resetRegistry() {
	moduleRegistry.Lock()
	moduleRegistry.entries = make(map[string]*moduleEntry)
	moduleRegistry.Unlock()
}

// testOptions is the minimal configuration a backend needs to reach the fake.
func testOptions(extra ...Option) []Option {
	base := []Option{
		WithModulePath("/nonexistent/forge-test.so"),
		WithTokenLabel("forge-hsm"),
		WithPinProvider(func(context.Context) (string, error) { return "1234", nil }),
	}
	return append(base, extra...)
}
