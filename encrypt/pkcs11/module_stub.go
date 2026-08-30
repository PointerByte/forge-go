// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !pkcs11 || !cgo || windows

package pkcs11

// newModule reports that PKCS#11 support was not compiled in.
//
// This file is what keeps CGO_ENABLED=0 builds and cross-compilation working
// for every consumer that does not need HSM support: without the "pkcs11" build
// tag the cgo binding is never compiled, so the module keeps building for
// targets that have no C toolchain. Windows is excluded because the canonical
// PKCS#11 header packs its structures to one byte there, which shifts the
// function table layout; a syscall-based Windows loader is future work.
func newModule(_ string) (module, error) {
	return nil, ErrUnavailable
}
