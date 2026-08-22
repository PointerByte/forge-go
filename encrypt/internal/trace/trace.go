// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package trace adds OpenTelemetry spans to the encrypt backends without
// exposing sensitive material.
//
// It only emits a span when the propagated context carries a *builder.Context
// (recovered with builder.From); otherwise Start is a no-op. The span only
// records the operation name and status, never keys, plaintext, ciphertext,
// signatures or any other payload.
//
// On fallback paths where a cloud backend delegates to the local backend, both
// layers are instrumented, producing nested parent-child spans
// (e.g. aws-kms/EncryptAES -> local/EncryptAES). This is the expected tracing
// behavior and the process names make the nesting self-describing.
package trace

import (
	"context"

	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/PointerByte/forge-go/logger/formatter"
)

// system is the coarse system attribute shared by every crypto span; the
// provider/method detail is carried by the process name instead.
const system = "encrypt"

// Start opens a span for process when ctx carries a *builder.Context, and
// returns a function that must be deferred with the method's final error. When
// ctx does not carry a *builder.Context the returned function is a no-op, so
// callers using context.Background() never trace.
//
// Usage for methods that return an error (named result required):
//
//	end := trace.Start(ctx, "aws-kms/EncryptAES")
//	defer end(err)
//
// Usage for methods without an error result:
//
//	defer trace.Start(ctx, "aws-kms/HMAC")(nil)
func Start(ctx context.Context, process string) func(error) {
	log, ok := builder.From(ctx)
	if !ok {
		return func(error) {}
	}

	svc := &formatter.Process{
		System:  system,
		Process: process,
		Status:  formatter.SUCCESS,
	}
	log.TraceInit(svc)

	return func(err error) {
		if err != nil {
			svc.SetStatus(formatter.ERROR)
		}
		log.TraceEnd(svc)
	}
}
