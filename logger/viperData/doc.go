// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package viperdata provides cached access to configuration values used by the
// logger module.
//
// It reads logger- and application-related settings from Viper, initializes a
// shared in-memory map on first access, and exposes helpers to read or reset
// that cached state during runtime and tests.
//
// Main entry points:
//   - GetViperData to read a cached logger setting
//   - ResetViperDataSingleton to clear the cache for tests or reinitialization
package viperdata
