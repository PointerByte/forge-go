// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"bytes"
	"encoding/asn1"
	"strings"
	"testing"

	"github.com/PointerByte/forge-go/encrypt/common"
)

func TestBoolAttributeRoundTrip(t *testing.T) {
	for _, want := range []bool{true, false} {
		attr := newBoolAttribute(ckaSign, want)
		if !attr.Present {
			t.Fatal("newBoolAttribute() must mark the attribute present")
		}
		got, ok := boolValue(attr.Value)
		if !ok {
			t.Fatalf("boolValue(%x) not decodable", attr.Value)
		}
		if got != want {
			t.Fatalf("boolValue() = %v, want %v", got, want)
		}
	}
	if _, ok := boolValue([]byte{0, 0}); ok {
		t.Fatal("boolValue() must reject a value that is not one byte")
	}
}

func TestULongAttributeRoundTrip(t *testing.T) {
	tests := []uint64{0, 1, 32, 2048, 0x00000010, 1<<32 + 7}
	for _, want := range tests {
		attr := newULongAttribute(ckaValueLen, want)
		if len(attr.Value) != 8 {
			t.Fatalf("newULongAttribute() produced %d bytes, want 8", len(attr.Value))
		}
		got, ok := uLongValue(attr.Value)
		if !ok {
			t.Fatalf("uLongValue(%x) not decodable", attr.Value)
		}
		if got != want {
			t.Fatalf("uLongValue() = %d, want %d", got, want)
		}
	}
	if _, ok := uLongValue([]byte{1, 2, 3}); ok {
		t.Fatal("uLongValue() must reject a value that is not eight bytes")
	}
}

func TestULongAttributeIsLittleEndian(t *testing.T) {
	attr := newULongAttribute(ckaClass, 0x0102)
	want := []byte{0x02, 0x01, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(attr.Value, want) {
		t.Fatalf("newULongAttribute() = %x, want %x", attr.Value, want)
	}
}

func TestFindAndHasAttribute(t *testing.T) {
	attributes := []attribute{
		{Type: ckaLabel, Value: []byte("k"), Present: true},
		{Type: ckaID, Value: nil, Present: false},
	}

	if value, ok := findAttribute(attributes, ckaLabel); !ok || string(value) != "k" {
		t.Fatalf("findAttribute(CKA_LABEL) = %q/%v, want k/true", value, ok)
	}
	// An absent attribute must not be reported as found: DeactivateKey builds
	// its template from this and the token rejects unknown attributes.
	if _, ok := findAttribute(attributes, ckaID); ok {
		t.Fatal("findAttribute() must ignore attributes marked absent")
	}
	if _, ok := findAttribute(attributes, ckaSign); ok {
		t.Fatal("findAttribute() must report a missing attribute")
	}
	if !hasAttribute(attributes, ckaLabel) {
		t.Fatal("hasAttribute(CKA_LABEL) = false, want true")
	}
	if hasAttribute(attributes, ckaID) {
		t.Fatal("hasAttribute() must ignore attributes marked absent")
	}
}

func TestECParamsForCurve(t *testing.T) {
	tests := []struct {
		name    string
		curve   common.CurveAsymmetricKey
		wantOID asn1.ObjectIdentifier
		wantErr bool
	}{
		{name: "P256", curve: common.CurveP256, wantOID: oidP256},
		{name: "P384", curve: common.CurveP384, wantOID: oidP384},
		{name: "P521", curve: common.CurveP521, wantOID: oidP521},
		{name: "unsupported", curve: common.CurveAsymmetricKey(99), wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := ecParamsForCurve(test.curve)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ecParamsForCurve() error = %v", err)
			}
			var decoded asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("encoded params are not a DER OID: %v", err)
			}
			if !decoded.Equal(test.wantOID) {
				t.Fatalf("oid = %v, want %v", decoded, test.wantOID)
			}
		})
	}
}

func TestECParamsForEd25519(t *testing.T) {
	encoded, err := ecParamsForEd25519()
	if err != nil {
		t.Fatalf("ecParamsForEd25519() error = %v", err)
	}
	var decoded asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("not a DER OID: %v", err)
	}
	if !decoded.Equal(oidEd25519) {
		t.Fatalf("oid = %v, want %v", decoded, oidEd25519)
	}
}

func TestRSAModulusBits(t *testing.T) {
	tests := []struct {
		name    string
		size    common.SizeAsymetrycKey
		want    uint64
		wantErr bool
	}{
		{name: "2048", size: common.Key2048Bits, want: 2048},
		{name: "3072", size: common.Key3072Bits, want: 3072},
		{name: "4096", size: common.Key4096Bits, want: 4096},
		{name: "unsupported", size: common.SizeAsymetrycKey(1024), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := rsaModulusBits(test.size)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("rsaModulusBits() = %d, %v, want %d", got, err, test.want)
			}
		})
	}
}

// TestAESValueLen pins the unit mismatch that would silently create 16-byte
// keys where 32 were asked for: common expresses symmetric sizes in bytes and
// CKA_VALUE_LEN is also in bytes, so the value passes through unchanged.
func TestAESValueLen(t *testing.T) {
	tests := []struct {
		name    string
		size    common.SizeSymetrycKey
		want    uint64
		wantErr bool
	}{
		{name: "128 bits is 16 bytes", size: common.Key128Bits, want: 16},
		{name: "256 bits is 32 bytes", size: common.Key256Bits, want: 32},
		{name: "unsupported", size: common.SizeSymetrycKey(24), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := aesValueLen(test.size)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("aesValueLen() = %d, %v, want %d", got, err, test.want)
			}
		})
	}
}

func TestMechanismString(t *testing.T) {
	if got := ckmAESGCM.String(); got != "CKM_AES_GCM" {
		t.Fatalf("String() = %q, want CKM_AES_GCM", got)
	}
	got := mechanism(0x12345678).String()
	if !strings.Contains(got, "12345678") {
		t.Fatalf("String() = %q, want it to carry the numeric code", got)
	}
}
