// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"context"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

// Viper keys, following the encrypt.vault.<backend>.<attribute> convention the
// other backends use.
//
// There is deliberately no "encrypt.vault.pkcs11.pin" key. A PIN in
// configuration ends up in application.yml, in process environment dumps and in
// logs; it is supplied through a PinProvider instead.
const (
	defaultModulePathKey = "encrypt.vault.pkcs11.module-path"
	defaultTokenLabelKey = "encrypt.vault.pkcs11.token-label"
	defaultSlotIDKey     = "encrypt.vault.pkcs11.slot-id"
	defaultKeyURIKey     = "encrypt.vault.pkcs11.key-uri"
	defaultMaxSessionKey = "encrypt.vault.pkcs11.max-sessions"

	providerName = "pkcs11"

	// defaultMaxSessions bounds three things at once: sessions held open on
	// the token, concurrent operations, and OS threads parked in blocking cgo
	// calls. They are the same resource, so they get the same number.
	defaultMaxSessions = 8

	// keyLabelPrefix mirrors the "GoForge-*" naming the other backends apply
	// to generated keys.
	symmetricKeyPrefix = "GoForge-symmetric"
	rsaKeyPrefix       = "GoForge-rsa"
	ecdhKeyPrefix      = "GoForge-ecdh"
	ed25519KeyPrefix   = "GoForge-ed25519" // gitleaks:allow
	hmacKeyPrefix      = "GoForge-hmac"

	// eccHKDFInfoPrefix mirrors the unexported constant the utilities package
	// uses to build the HKDF info string, so an in-hardware HKDF derives the
	// same key as utilities.DeriveECCAESKey.
	eccHKDFInfoPrefix = "GoForge-ecc-aes-gcm:"
)

// PinProvider returns the token PIN. It is called at most once per token, when
// the first session logs in, and the returned string is wiped from C memory as
// soon as C_Login returns.
//
// Supplying it as a function rather than a configuration value lets the PIN
// come from wherever the deployment keeps it — a file with restricted
// permissions, a secrets manager, Dragon CMK — without this package taking a
// dependency on any of them.
type PinProvider func(ctx context.Context) (string, error)

// config holds the resolved backend settings.
type config struct {
	modulePath string
	tokenLabel string
	slotID     uint64
	hasSlotID  bool
	keyURI     string
	maxSession int
	pin        PinProvider

	allowSecretExtraction bool
	deactivateDestroys    bool
	rotateDisablesPrev    bool
}

// Option customises the backend. Every value also has a viper key, so
// NewRepository() with no options behaves like the other backends.
type Option func(*config)

// WithModulePath sets the path to the vendor PKCS#11 shared library.
func WithModulePath(path string) Option {
	return func(c *config) { c.modulePath = strings.TrimSpace(path) }
}

// WithTokenLabel selects the token by its label, which is stable across
// reboots unlike the slot id.
func WithTokenLabel(label string) Option {
	return func(c *config) { c.tokenLabel = strings.TrimSpace(label) }
}

// WithSlotID selects the token by slot id. Prefer WithTokenLabel: slot ids are
// reassigned when tokens are added or removed.
func WithSlotID(id uint64) Option {
	return func(c *config) {
		c.slotID = id
		c.hasSlotID = true
	}
}

// WithKeyURI sets the default RFC 7512 key URI used when a request does not
// carry one, mirroring encrypt.vault.aws-kms.arn in the AWS backend.
func WithKeyURI(uri string) Option {
	return func(c *config) { c.keyURI = strings.TrimSpace(uri) }
}

// WithMaxSessions bounds concurrent token sessions. Values below one are
// ignored.
func WithMaxSessions(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.maxSession = n
		}
	}
}

// WithPinProvider supplies the token PIN.
func WithPinProvider(provider PinProvider) Option {
	return func(c *config) { c.pin = provider }
}

// WithAllowSecretExtraction controls whether ECDH_Decode may fall back to
// reading the derived shared secret out of the token when the token does not
// implement CKM_HKDF_DERIVE.
//
// It defaults to true. What leaves the token in that path is an ephemeral
// per-message secret, never long-term key material, and it is exactly what the
// aws-kms and azure-key-vault backends already do. Set it to false on a token
// whose policy must guarantee that nothing derived ever leaves the hardware,
// accepting that ECDH_Decode then fails on tokens without CKM_HKDF_DERIVE.
func WithAllowSecretExtraction(allow bool) Option {
	return func(c *config) { c.allowSecretExtraction = allow }
}

// WithDeactivateDestroys makes DeactivateKey destroy the object when the token
// refuses to clear its usage attributes.
//
// It defaults to false: failing is safer than destroying a key the caller only
// asked to disable.
func WithDeactivateDestroys(destroy bool) Option {
	return func(c *config) { c.deactivateDestroys = destroy }
}

// WithRotateDisablesPrevious makes RotateKey disable the previous key after
// generating its replacement. It defaults to false so that rotation stays
// non-destructive and old ciphertext remains decryptable.
func WithRotateDisablesPrevious(disable bool) Option {
	return func(c *config) { c.rotateDisablesPrev = disable }
}

// newConfig applies defaults, then viper, then the explicit options, so an
// option always wins over configuration.
func newConfig(opts ...Option) *config {
	resolved := &config{
		maxSession:            defaultMaxSessions,
		allowSecretExtraction: true,
	}

	resolved.modulePath = strings.TrimSpace(viper.GetString(defaultModulePathKey))
	resolved.tokenLabel = strings.TrimSpace(viper.GetString(defaultTokenLabelKey))
	resolved.keyURI = strings.TrimSpace(viper.GetString(defaultKeyURIKey))

	if raw := strings.TrimSpace(viper.GetString(defaultSlotIDKey)); raw != "" {
		if parsed, err := strconv.ParseUint(raw, 10, 64); err == nil {
			resolved.slotID = parsed
			resolved.hasSlotID = true
		}
	}
	if raw := strings.TrimSpace(viper.GetString(defaultMaxSessionKey)); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			resolved.maxSession = parsed
		}
	}

	for _, apply := range opts {
		apply(resolved)
	}
	return resolved
}

// validate reports the first missing setting. It runs on the first operation
// rather than in the constructor, matching how the Azure backend defers
// credential resolution to first use.
func (c *config) validate() error {
	if c.modulePath == "" {
		return ErrModuleRequired
	}
	if c.tokenLabel == "" && !c.hasSlotID {
		return ErrTokenRequired
	}
	if c.pin == nil {
		return ErrPinRequired
	}
	return nil
}

// resolveKeyURI returns the key reference for an operation, falling back to the
// configured default the way resolveAWSKMSKeyID does.
func (c *config) resolveKeyURI(reference string) (*keyURI, error) {
	if trimmed := strings.TrimSpace(reference); trimmed != "" {
		return parseKeyURI(trimmed)
	}
	if c.keyURI != "" {
		return parseKeyURI(c.keyURI)
	}
	return nil, ErrKeyURIRequired
}
