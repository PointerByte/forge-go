// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build pkcs11 && cgo && !windows

package pkcs11

import (
	"os"
	"testing"
)

// candidateModules are PKCS#11 libraries commonly present on a Linux host. The
// smoke test uses whichever exists.
var candidateModules = []string{
	"/usr/lib64/pkcs11/libsofthsm2.so",
	"/usr/lib64/softhsm/libsofthsm2.so",
	"/usr/lib/softhsm/libsofthsm2.so",
	"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
	"/usr/lib64/pkcs11/p11-kit-trust.so",
	"/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so",
}

// TestABIAgainstRealModule loads a real vendor library and walks the function
// table.
//
// This is the only automated check that the hand-written CK_FUNCTION_LIST
// layout matches what a real module returns: the static assertions in
// cryptoki.h prove the struct is self-consistent, but only calling through it
// proves the entries line up with the library's own table. A wrong offset would
// dispatch to the wrong function, which is why this runs against whatever
// module the host happens to have.
func TestABIAgainstRealModule(t *testing.T) {
	// Candidates are tried in order until one both loads and initializes. A
	// module can be installed yet unusable here -- SoftHSM needs a readable
	// token store, which SOFTHSM2_CONF selects -- and that says nothing about
	// the ABI, so it moves on to the next rather than failing.
	var mod module
	var path string
	for _, candidate := range candidateModules {
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		loaded, err := newModule(candidate)
		if err != nil {
			// Loading is the part that exercises the function table layout, so
			// a failure here is a real problem worth reporting.
			t.Fatalf("newModule(%q) error = %v", candidate, err)
		}
		if err := loaded.Initialize(); err != nil {
			t.Logf("skipping %s: Initialize() = %v", candidate, err)
			continue
		}
		mod, path = loaded, candidate
		break
	}
	if mod == nil {
		t.Skip("no usable PKCS#11 module on this host")
	}
	t.Cleanup(func() { _ = mod.Finalize() })

	slots, err := mod.Slots(true)
	if err != nil {
		t.Fatalf("Slots() error = %v", err)
	}
	t.Logf("module %s exposes %d slot(s)", path, len(slots))

	for _, slot := range slots {
		mechanisms, err := mod.Mechanisms(slot.ID)
		if err != nil {
			// Some slots legitimately refuse; the call still proves dispatch.
			t.Logf("slot %d (%q): Mechanisms() = %v", slot.ID, slot.TokenLabel, err)
			continue
		}
		t.Logf("slot %d (%q) advertises %d mechanism(s)", slot.ID, slot.TokenLabel, len(mechanisms))
	}
}
