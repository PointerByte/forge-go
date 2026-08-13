// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package formatter

type Level string

const (
	InfoLevel  Level = "INFO"
	DebugLevel Level = "DEBUG"
	WarnLevel  Level = "WARN"
	ErrorLevel Level = "ERROR"
)

type Status string

const (
	SUCCESS      Status = "SUCCESS"
	ERROR        Status = "ERROR"
	CLIENT_ERROR Status = "CLIENT_ERROR"
	OTHER        Status = "OTHER"
	UNKNOWN      Status = "UNKNOWN"
)
