// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package http provides HTTP client helpers for the config module.
//
// It includes two complementary layers:
//   - a lower-level REST wrapper built around net/http requests and responses
//   - a higher-level generic client that serializes request bodies, deserializes
//     responses, and emits trace and log metadata through the logger package
//
// The package is intended for outbound service-to-service calls that should
// reuse GoForge conventions for context propagation, headers, timeouts, and
// observability.
//
// Main entry points:
//   - NewRestClient to create a plain *http.Client with a custom timeout and transport
//   - NewIRest to execute explicit HTTP requests through the IRest abstraction
//   - NewGenericRest to execute typed REST requests through RequestGeneric
//
// Both the concrete and generic clients are designed to be mockable in tests by
// depending on their interfaces instead of the concrete implementations.
package http
