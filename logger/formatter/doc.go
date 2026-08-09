// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package formatter provides the structured log models and formatting
// strategies used by the logger module.
//
// It defines the shape of log entries, service traces, and request metadata,
// and it can render logs as plain text, JSON, or custom templates.
//
// Main entry points:
//   - New to create a template-aware formatter
//   - Formatter as the formatting contract
//   - LogFormat, Service, and Details as the core log data structures
package formatter
