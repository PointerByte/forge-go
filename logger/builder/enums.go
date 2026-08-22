// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package builder

type keyContex string

const (
	traceIDKey  keyContex = "traceID"
	detailsKey  keyContex = "details"
	servicesKey keyContex = "services"
)

type loggerAtribute string

const (
	timestampAtribute loggerAtribute = "timestamp"
	loggerMessage     loggerAtribute = "message"
	levelAtribute     loggerAtribute = "level"
)

type traceAtribute string

const (
	systemAtribute traceAtribute = "system"
	statusAtribute traceAtribute = "status"
)
