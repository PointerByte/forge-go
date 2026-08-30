// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"errors"
	"strings"
	"testing"
)

func TestNewTokenError(t *testing.T) {
	if err := newTokenError("C_Sign", ckrOK); err != nil {
		t.Fatalf("newTokenError(CKR_OK) = %v, want nil", err)
	}

	err := newTokenError("C_Sign", ckrPinLocked)
	if err == nil {
		t.Fatal("newTokenError() returned nil for a failure code")
	}
	message := err.Error()
	if !strings.Contains(message, "C_Sign") || !strings.Contains(message, "CKR_PIN_LOCKED") {
		t.Fatalf("Error() = %q, want it to name the function and the code", message)
	}
}

func TestTokenErrorUnknownCode(t *testing.T) {
	err := newTokenError("C_Login", returnValue(0x0BADC0DE))
	if !strings.Contains(err.Error(), "0x0BADC0DE") {
		t.Fatalf("Error() = %q, want the numeric code", err.Error())
	}
}

// TestTokenErrorIs covers the two policy conditions callers branch on, which
// is the whole reason tokenError implements Is.
func TestTokenErrorIs(t *testing.T) {
	tests := []struct {
		name   string
		code   returnValue
		target error
		want   bool
	}{
		{name: "sensitive maps to not extractable", code: ckrAttributeSensitive, target: ErrSecretNotExtractable, want: true},
		{name: "unextractable maps to not extractable", code: ckrKeyUnextractable, target: ErrSecretNotExtractable, want: true},
		{name: "object handle maps to not found", code: ckrObjectHandleInvalid, target: ErrKeyNotFound, want: true},
		{name: "key handle maps to not found", code: ckrKeyHandleInvalid, target: ErrKeyNotFound, want: true},
		{name: "unrelated code", code: ckrDeviceError, target: ErrKeyNotFound, want: false},
		{name: "unrelated target", code: ckrAttributeSensitive, target: ErrPinRequired, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := newTokenError("C_DeriveKey", test.code)
			if got := errors.Is(err, test.target); got != test.want {
				t.Fatalf("errors.Is(%v, %v) = %v, want %v", err, test.target, got, test.want)
			}
		})
	}
}

func TestUnsupportedMechanismError(t *testing.T) {
	err := errUnsupportedMechanism(ckmEdDSA)
	if !strings.Contains(err.Error(), "CKM_EDDSA") {
		t.Fatalf("Error() = %q, want it to name the mechanism", err.Error())
	}
}
