// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package sanitizer redacts configured sensitive keys before log formatting.
// Recursive values are bounded to a depth of 32; uninspected deeper subtrees
// are replaced with RedactedValue so sanitization fails closed.
package sanitizer
