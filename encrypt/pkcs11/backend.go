// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"context"

	"github.com/PointerByte/forge-go/encrypt/models"
)

// backend is the shared plumbing behind the five repositories: it resolves the
// configuration, loads the library, and hands out logged-in sessions.
type backend struct {
	cfg *config
}

func newBackend(opts ...Option) *backend {
	return &backend{cfg: newConfig(opts...)}
}

// tokenOp receives an exclusive session on the configured token.
type tokenOp func(mod module, slot *slotState, session sessionHandle) error

// withSession validates the configuration, resolves the token, acquires an
// exclusive session, logs in once, and runs op.
//
// Resolution happens here rather than in the constructor so that a
// misconfigured backend fails on first use with a descriptive error, matching
// how the Azure backend defers credential resolution.
func (b *backend) withSession(ctx context.Context, op tokenOp) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.cfg.validate(); err != nil {
		return err
	}

	entry, err := acquireModule(b.cfg.modulePath)
	if err != nil {
		return err
	}

	slot, err := entry.slotFor(b.cfg)
	if err != nil {
		return err
	}

	session, err := slot.pool.acquire(ctx, entry.mod)
	if err != nil {
		return err
	}

	opErr := b.runLoggedIn(ctx, entry.mod, slot, session, op)
	slot.pool.release(entry.mod, session, opErr)
	if sessionIsDead(opErr) {
		slot.resetLogin()
	}
	return opErr
}

// runLoggedIn logs the session in if needed and runs op.
func (b *backend) runLoggedIn(ctx context.Context, mod module, slot *slotState, session sessionHandle, op tokenOp) error {
	if err := slot.login(ctx, mod, session, b.cfg.pin); err != nil {
		return err
	}
	return op(mod, slot, session)
}

// keyData builds the KeyData a token-backed key is described by. KeyRef is the
// RFC 7512 URI, which is what every operation accepts back.
func keyDataFor(uri *keyURI, publicKey string) *models.KeyData {
	return &models.KeyData{
		PublicKey: publicKey,
		KeyID:     uri.hexID(),
		KeyRef:    uri.String(),
		Provider:  providerName,
	}
}
