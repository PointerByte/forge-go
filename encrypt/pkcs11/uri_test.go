// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"bytes"
	"strings"
	"testing"
)

func TestIsKeyURI(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "uri", value: "pkcs11:object=key", want: true},
		{name: "uri with spaces", value: "  pkcs11:object=key  ", want: true},
		{name: "empty", value: "", want: false},
		{name: "base64 key material", value: "c29tZS1hZXMta2V5LTMyLWJ5dGVzLWxvbmchIQ==", want: false},
		{name: "aws arn", value: "arn:aws:kms:eu-west-1:1:key/abc", want: false},
		{name: "scheme prefix only in middle", value: "x-pkcs11:object=key", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isKeyURI(test.value); got != test.want {
				t.Fatalf("isKeyURI(%q) = %v, want %v", test.value, got, test.want)
			}
		})
	}
}

func TestParseKeyURI(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		wantToken  string
		wantObject string
		wantID     []byte
		wantClass  objectClass
		wantHas    bool
		wantErr    bool
	}{
		{
			name:       "full",
			value:      "pkcs11:token=forge-hsm;object=jwt-signing;id=%01%02;type=private",
			wantToken:  "forge-hsm",
			wantObject: "jwt-signing",
			wantID:     []byte{0x01, 0x02},
			wantClass:  classPrivateKey,
			wantHas:    true,
		},
		{
			name:       "object only",
			value:      "pkcs11:object=aes-key",
			wantObject: "aes-key",
		},
		{
			name:   "id only",
			value:  "pkcs11:id=%ff",
			wantID: []byte{0xff},
		},
		{
			name:       "unknown attributes ignored",
			value:      "pkcs11:model=Luna;manufacturer=Thales;object=k",
			wantObject: "k",
		},
		{
			name:       "public type",
			value:      "pkcs11:object=k;type=public",
			wantObject: "k",
			wantClass:  classPublicKey,
			wantHas:    true,
		},
		{
			name:       "secret key type",
			value:      "pkcs11:object=k;type=secret-key",
			wantObject: "k",
			wantClass:  classSecretKey,
			wantHas:    true,
		},
		{
			name:       "cert type",
			value:      "pkcs11:object=k;type=cert",
			wantObject: "k",
			wantClass:  classCertificate,
			wantHas:    true,
		},
		{
			name:       "data type",
			value:      "pkcs11:object=k;type=data",
			wantObject: "k",
			wantClass:  classData,
			wantHas:    true,
		},
		{
			name:       "empty segments tolerated",
			value:      "pkcs11:;object=k;",
			wantObject: "k",
		},
		{name: "not a uri", value: "plain", wantErr: true},
		{name: "no attributes", value: "pkcs11:", wantErr: true},
		{name: "malformed attribute", value: "pkcs11:object", wantErr: true},
		{name: "unsupported type", value: "pkcs11:object=k;type=weird", wantErr: true},
		{name: "neither object nor id", value: "pkcs11:token=forge", wantErr: true},
		{name: "bad percent escape", value: "pkcs11:object=%zz", wantErr: true},
		{name: "pin-value rejected", value: "pkcs11:object=k?pin-value=1234", wantErr: true},
		{name: "pin-source rejected", value: "pkcs11:object=k?pin-source=/tmp/pin", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseKeyURI(test.value)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseKeyURI(%q) expected error", test.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseKeyURI(%q) error = %v", test.value, err)
			}
			if got.Token != test.wantToken {
				t.Fatalf("Token = %q, want %q", got.Token, test.wantToken)
			}
			if got.Object != test.wantObject {
				t.Fatalf("Object = %q, want %q", got.Object, test.wantObject)
			}
			if !bytes.Equal(got.ID, test.wantID) {
				t.Fatalf("ID = %x, want %x", got.ID, test.wantID)
			}
			if got.HasClass != test.wantHas || got.Class != test.wantClass {
				t.Fatalf("Class = %v/%v, want %v/%v", got.Class, got.HasClass, test.wantClass, test.wantHas)
			}
		})
	}
}

// TestKeyURIRoundTrip is the property that matters: a binary CKA_ID must
// survive String followed by parseKeyURI unchanged, or a key reference handed
// back to the caller would stop resolving.
func TestKeyURIRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		uri  keyURI
	}{
		{name: "binary id", uri: keyURI{Token: "forge", Object: "k", ID: []byte{0x00, 0x01, 0xff, 0x3b, 0x3d}, Class: classPrivateKey, HasClass: true}},
		{name: "label with separators", uri: keyURI{Object: "a;b=c", ID: []byte{0x01}}},
		{name: "label with spaces", uri: keyURI{Object: "my key", ID: []byte{0x02}}},
		{name: "unicode label", uri: keyURI{Object: "clave-ñ", ID: []byte{0x03}}},
		{name: "no id", uri: keyURI{Object: "only-label"}},
		{name: "no object", uri: keyURI{ID: []byte{0xde, 0xad}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			formatted := test.uri.String()
			parsed, err := parseKeyURI(formatted)
			if err != nil {
				t.Fatalf("parseKeyURI(%q) error = %v", formatted, err)
			}
			if parsed.Object != test.uri.Object {
				t.Fatalf("Object = %q, want %q", parsed.Object, test.uri.Object)
			}
			if !bytes.Equal(parsed.ID, test.uri.ID) {
				t.Fatalf("ID = %x, want %x", parsed.ID, test.uri.ID)
			}
			if parsed.Token != test.uri.Token {
				t.Fatalf("Token = %q, want %q", parsed.Token, test.uri.Token)
			}
			if parsed.HasClass != test.uri.HasClass || parsed.Class != test.uri.Class {
				t.Fatalf("Class = %v/%v, want %v/%v", parsed.Class, parsed.HasClass, test.uri.Class, test.uri.HasClass)
			}
		})
	}
}

func TestKeyURIStringOmitsUnknownClass(t *testing.T) {
	uri := keyURI{Object: "k", Class: objectClass(99), HasClass: true}
	if strings.Contains(uri.String(), "type=") {
		t.Fatalf("String() = %q, should omit an unrepresentable class", uri.String())
	}
}

func TestKeyURIHexID(t *testing.T) {
	uri := keyURI{ID: []byte{0x0a, 0xff}}
	if got := uri.hexID(); got != "0aff" {
		t.Fatalf("hexID() = %q, want %q", got, "0aff")
	}
	empty := keyURI{}
	if got := empty.hexID(); got != "" {
		t.Fatalf("hexID() = %q, want empty", got)
	}
}

func TestClassFromTypeAndBack(t *testing.T) {
	for _, name := range []string{"private", "public", "secret-key", "cert", "data"} {
		class, err := classFromType(name)
		if err != nil {
			t.Fatalf("classFromType(%q) error = %v", name, err)
		}
		back, err := typeFromClass(class)
		if err != nil {
			t.Fatalf("typeFromClass(%v) error = %v", class, err)
		}
		if back != name {
			t.Fatalf("round trip = %q, want %q", back, name)
		}
	}
	if _, err := typeFromClass(objectClass(77)); err == nil {
		t.Fatal("typeFromClass() expected error for unknown class")
	}
}

func TestEscapeAttribute(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "unreserved untouched", value: "abcXYZ019-._~", want: "abcXYZ019-._~"},
		{name: "separators escaped", value: ";=", want: "%3B%3D"},
		{name: "space escaped", value: " ", want: "%20"},
		{name: "percent escaped", value: "%", want: "%25"},
		{name: "path safe kept", value: ":[]@!$'()*+,", want: ":[]@!$'()*+,"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := escapeAttribute(test.value); got != test.want {
				t.Fatalf("escapeAttribute(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

func TestRejectPinAttributes(t *testing.T) {
	if err := rejectPinAttributes(""); err != nil {
		t.Fatalf("rejectPinAttributes(\"\") error = %v", err)
	}
	if err := rejectPinAttributes("module-path=/x&other=1"); err != nil {
		t.Fatalf("rejectPinAttributes() error = %v", err)
	}
	if err := rejectPinAttributes("pin-value=1234"); err == nil {
		t.Fatal("expected pin-value to be rejected")
	}
}
