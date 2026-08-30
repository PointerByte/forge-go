// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"context"
	"errors"
	"testing"

	"github.com/spf13/viper"
)

func testPin(context.Context) (string, error) { return "1234", nil }

func TestNewConfigDefaults(t *testing.T) {
	t.Cleanup(viper.Reset)
	viper.Reset()

	cfg := newConfig()
	if cfg.maxSession != defaultMaxSessions {
		t.Fatalf("maxSession = %d, want %d", cfg.maxSession, defaultMaxSessions)
	}
	// Extraction defaults on because most tokens cannot do ECDH otherwise;
	// see WithAllowSecretExtraction.
	if !cfg.allowSecretExtraction {
		t.Fatal("allowSecretExtraction should default to true")
	}
	if cfg.deactivateDestroys {
		t.Fatal("deactivateDestroys should default to false")
	}
	if cfg.rotateDisablesPrev {
		t.Fatal("rotateDisablesPrev should default to false")
	}
}

func TestNewConfigReadsViper(t *testing.T) {
	t.Cleanup(viper.Reset)
	viper.Reset()

	viper.Set(defaultModulePathKey, " /usr/lib/softhsm.so ")
	viper.Set(defaultTokenLabelKey, "forge-hsm")
	viper.Set(defaultSlotIDKey, "3")
	viper.Set(defaultKeyURIKey, "pkcs11:object=k")
	viper.Set(defaultMaxSessionKey, "16")

	cfg := newConfig()
	if cfg.modulePath != "/usr/lib/softhsm.so" {
		t.Fatalf("modulePath = %q, want it trimmed", cfg.modulePath)
	}
	if cfg.tokenLabel != "forge-hsm" {
		t.Fatalf("tokenLabel = %q", cfg.tokenLabel)
	}
	if !cfg.hasSlotID || cfg.slotID != 3 {
		t.Fatalf("slotID = %d/%v, want 3/true", cfg.slotID, cfg.hasSlotID)
	}
	if cfg.keyURI != "pkcs11:object=k" {
		t.Fatalf("keyURI = %q", cfg.keyURI)
	}
	if cfg.maxSession != 16 {
		t.Fatalf("maxSession = %d, want 16", cfg.maxSession)
	}
}

func TestNewConfigIgnoresUnparseableViperValues(t *testing.T) {
	t.Cleanup(viper.Reset)
	viper.Reset()

	viper.Set(defaultSlotIDKey, "not-a-number")
	viper.Set(defaultMaxSessionKey, "zero-ish")

	cfg := newConfig()
	if cfg.hasSlotID {
		t.Fatal("an unparseable slot id must not be treated as configured")
	}
	if cfg.maxSession != defaultMaxSessions {
		t.Fatalf("maxSession = %d, want the default kept", cfg.maxSession)
	}
}

// TestOptionsOverrideViper pins the precedence: an explicit option always wins.
func TestOptionsOverrideViper(t *testing.T) {
	t.Cleanup(viper.Reset)
	viper.Reset()

	viper.Set(defaultModulePathKey, "/from/viper.so")
	viper.Set(defaultMaxSessionKey, "4")

	cfg := newConfig(
		WithModulePath("/from/option.so"),
		WithMaxSessions(9),
		WithSlotID(7),
		WithKeyURI("pkcs11:object=opt"),
		WithTokenLabel("opt-token"),
		WithAllowSecretExtraction(false),
		WithDeactivateDestroys(true),
		WithRotateDisablesPrevious(true),
	)

	if cfg.modulePath != "/from/option.so" {
		t.Fatalf("modulePath = %q, want the option to win", cfg.modulePath)
	}
	if cfg.maxSession != 9 {
		t.Fatalf("maxSession = %d, want 9", cfg.maxSession)
	}
	if !cfg.hasSlotID || cfg.slotID != 7 {
		t.Fatalf("slotID = %d/%v", cfg.slotID, cfg.hasSlotID)
	}
	if cfg.keyURI != "pkcs11:object=opt" || cfg.tokenLabel != "opt-token" {
		t.Fatalf("keyURI/tokenLabel = %q/%q", cfg.keyURI, cfg.tokenLabel)
	}
	if cfg.allowSecretExtraction || !cfg.deactivateDestroys || !cfg.rotateDisablesPrev {
		t.Fatal("boolean options were not applied")
	}
}

func TestWithMaxSessionsIgnoresNonPositive(t *testing.T) {
	t.Cleanup(viper.Reset)
	viper.Reset()

	cfg := newConfig(WithMaxSessions(0))
	if cfg.maxSession != defaultMaxSessions {
		t.Fatalf("maxSession = %d, want the default kept", cfg.maxSession)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config
		want error
	}{
		{name: "no module", cfg: &config{}, want: ErrModuleRequired},
		{name: "no token", cfg: &config{modulePath: "/x.so"}, want: ErrTokenRequired},
		{name: "no pin", cfg: &config{modulePath: "/x.so", tokenLabel: "t"}, want: ErrPinRequired},
		{name: "slot id counts as token", cfg: &config{modulePath: "/x.so", hasSlotID: true, pin: testPin}, want: nil},
		{name: "complete", cfg: &config{modulePath: "/x.so", tokenLabel: "t", pin: testPin}, want: nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.cfg.validate()
			if !errors.Is(err, test.want) {
				t.Fatalf("validate() = %v, want %v", err, test.want)
			}
		})
	}
}

func TestConfigResolveKeyURI(t *testing.T) {
	cfg := &config{keyURI: "pkcs11:object=default"}

	got, err := cfg.resolveKeyURI("pkcs11:object=explicit")
	if err != nil || got.Object != "explicit" {
		t.Fatalf("resolveKeyURI(explicit) = %v, %v", got, err)
	}

	got, err = cfg.resolveKeyURI("  ")
	if err != nil || got.Object != "default" {
		t.Fatalf("resolveKeyURI(blank) = %v, %v, want the configured default", got, err)
	}

	empty := &config{}
	if _, err := empty.resolveKeyURI(""); !errors.Is(err, ErrKeyURIRequired) {
		t.Fatalf("resolveKeyURI() = %v, want ErrKeyURIRequired", err)
	}
}
