// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package code contains the go-openssl certificate generation logic used by
// the CLI and by other Go code that needs to create plain or encrypted PEM
// assets programmatically. Artifact writes use same-filesystem staging and
// atomic replacement. New encrypted envelopes use Argon2id with AES-256-GCM;
// legacy version-1 envelopes remain readable for migration.
package code
