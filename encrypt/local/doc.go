// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package local provides in-process cryptographic helpers for symmetric
// encryption, hashing, RSA encryption, and digital signatures.
//
// Unlike the cloud-backed packages under encryption/encrypt, this package
// performs all operations locally and can generate exportable key material when
// the underlying algorithm supports it. The local repositories also implement
// the same context-aware method signatures exposed by the shared encrypt
// package.
package local
