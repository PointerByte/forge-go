// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package encrypt

import (
	"testing"

	"github.com/PointerByte/forge-go/encrypt/local"
)

func TestNewRepository(t *testing.T) {
	repository := NewRepository(local.NewRepository())
	if repository == nil {
		t.Fatal("expected repository")
	}
	if repository.SymmetricRepository == nil {
		t.Fatal("expected symmetric repository")
	}
	if repository.AsymmetricRepository == nil {
		t.Fatal("expected asymmetric repository")
	}
	if repository.KeyRepository == nil {
		t.Fatal("expected key repository")
	}
	if repository.SignatureRepository == nil {
		t.Fatal("expected signature repository")
	}
	if repository.HashRepository == nil {
		t.Fatal("expected hash repository")
	}
}
