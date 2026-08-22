// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package utilities provides shared configuration-loading helpers for GoForge.
//
// Its main responsibility is to load application settings from
// resources/application.yml, resources/application.yaml, or
// resources/application.json, merge the INI overlays and the env.files declared
// there, and apply environment-variable overrides derived from the Viper key
// paths.
//
// The INI overlays are resources/default.ini and the file named after app.name,
// for example resources/dragon-cmk.ini. Both are optional, and a directory that
// holds only default.ini is a valid configuration directory: an application
// file is required only when no INI file is present.
//
// LoadEnv also accepts a directory that contains application.* directly for
// compatibility with modules that keep local example configuration beside
// their code.
//
// Main entry point:
//   - LoadEnv to load configuration files and apply override rules
package utilities
