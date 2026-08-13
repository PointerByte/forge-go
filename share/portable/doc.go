// Package portable contains GoForge's deterministic, runtime-independent
// business and cryptographic primitives together with the versioned ABI used
// by component hosts.
//
// Binary values in ABI payloads use canonical, standard, padded Base64. JSON
// decoding rejects unknown fields, duplicate object keys, invalid UTF-8, and
// trailing values. The package never reads clocks, randomness, files, the
// network, environment variables, or host logging facilities.
package portable
