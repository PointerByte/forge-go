// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/PointerByte/forge-go/encrypt/utilities"
)

// TestDecodeECPoint covers the ambiguity that breaks naive implementations:
// 0x04 is both the ASN.1 OCTET STRING tag and the uncompressed-point prefix, so
// a wrapped and a bare point can look alike.
func TestDecodeECPoint(t *testing.T) {
	bareP256 := make([]byte, 65)
	bareP256[0] = 0x04
	for i := 1; i < len(bareP256); i++ {
		bareP256[i] = byte(i)
	}
	wrapped, err := asn1.Marshal(bareP256)
	if err != nil {
		t.Fatalf("asn1.Marshal() error = %v", err)
	}

	edwards := make([]byte, ed25519.PublicKeySize)
	for i := range edwards {
		edwards[i] = byte(i + 1)
	}
	wrappedEdwards, err := asn1.Marshal(edwards)
	if err != nil {
		t.Fatalf("asn1.Marshal() error = %v", err)
	}

	tests := []struct {
		name    string
		value   []byte
		want    []byte
		wantErr bool
	}{
		{name: "der wrapped point", value: wrapped, want: bareP256},
		{name: "bare point", value: bareP256, want: bareP256},
		{name: "der wrapped edwards", value: wrappedEdwards, want: edwards},
		{name: "bare edwards", value: edwards, want: edwards},
		{name: "empty", value: nil, wantErr: true},
		{name: "garbage", value: []byte{0x01, 0x02, 0x03}, wantErr: true},
		{name: "odd length point", value: []byte{0x04, 0x01, 0x02, 0x03}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := decodeECPoint(test.value)
			if test.wantErr {
				if err == nil {
					t.Fatalf("decodeECPoint(%x) expected error", test.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeECPoint() error = %v", err)
			}
			if string(got) != string(test.want) {
				t.Fatalf("decodeECPoint() = %x, want %x", got, test.want)
			}
		})
	}
}

func TestRSAPublicKeyFrom(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	attributes := []attribute{
		newBytesAttribute(ckaModulus, key.N.Bytes()),
		newBytesAttribute(ckaPublicExpon, big.NewInt(int64(key.E)).Bytes()),
	}

	encoded, err := rsaPublicKeyFrom(attributes)
	if err != nil {
		t.Fatalf("rsaPublicKeyFrom() error = %v", err)
	}

	// The encoding must be exactly what the other backends emit, or a caller
	// could not feed the public key back into the local implementation.
	parsed, err := utilities.ParseRSAPublicKeyFromBase64(encoded)
	if err != nil {
		t.Fatalf("the encoded key is not parseable by utilities: %v", err)
	}
	if parsed.N.Cmp(key.N) != 0 || parsed.E != key.E {
		t.Fatal("round-tripped public key does not match")
	}
}

func TestRSAPublicKeyFromRejectsIncompleteObjects(t *testing.T) {
	tests := []struct {
		name       string
		attributes []attribute
	}{
		{name: "no modulus", attributes: []attribute{newBytesAttribute(ckaPublicExpon, []byte{1, 0, 1})}},
		{name: "no exponent", attributes: []attribute{newBytesAttribute(ckaModulus, []byte{1, 2, 3})}},
		{name: "zero modulus", attributes: []attribute{
			newBytesAttribute(ckaModulus, []byte{0}),
			newBytesAttribute(ckaPublicExpon, []byte{1, 0, 1}),
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := rsaPublicKeyFrom(test.attributes); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestECDHPublicKeyFrom(t *testing.T) {
	tests := []struct {
		name  string
		curve ecdh.Curve
		oid   asn1.ObjectIdentifier
	}{
		{name: "P256", curve: ecdh.P256(), oid: oidP256},
		{name: "P384", curve: ecdh.P384(), oid: oidP384},
		{name: "P521", curve: ecdh.P521(), oid: oidP521},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			private, err := test.curve.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}
			params, err := asn1.Marshal(test.oid)
			if err != nil {
				t.Fatalf("asn1.Marshal() error = %v", err)
			}

			attributes := []attribute{
				newBytesAttribute(ckaECPoint, private.PublicKey().Bytes()),
				newBytesAttribute(ckaECParams, params),
			}
			encoded, err := ecdhPublicKeyFrom(attributes)
			if err != nil {
				t.Fatalf("ecdhPublicKeyFrom() error = %v", err)
			}
			parsed, err := utilities.ParseECDHPublicKeyFromBase64(encoded)
			if err != nil {
				t.Fatalf("the encoded key is not parseable by utilities: %v", err)
			}
			if !parsed.Equal(private.PublicKey()) {
				t.Fatal("round-tripped public key does not match")
			}
		})
	}
}

func TestECDHPublicKeyFromErrors(t *testing.T) {
	valid, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	p256Params, _ := asn1.Marshal(oidP256)
	unknownParams, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 3, 4})

	tests := []struct {
		name       string
		attributes []attribute
	}{
		{name: "no point", attributes: []attribute{newBytesAttribute(ckaECParams, p256Params)}},
		{name: "no params", attributes: []attribute{newBytesAttribute(ckaECPoint, valid.PublicKey().Bytes())}},
		{name: "unknown curve", attributes: []attribute{
			newBytesAttribute(ckaECPoint, valid.PublicKey().Bytes()),
			newBytesAttribute(ckaECParams, unknownParams),
		}},
		{name: "params not der", attributes: []attribute{
			newBytesAttribute(ckaECPoint, valid.PublicKey().Bytes()),
			newBytesAttribute(ckaECParams, []byte{0xff, 0xff}),
		}},
		{name: "point on wrong curve", attributes: []attribute{
			newBytesAttribute(ckaECPoint, mustP384Point(t)),
			newBytesAttribute(ckaECParams, p256Params),
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ecdhPublicKeyFrom(test.attributes); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func mustP384Point(t *testing.T) []byte {
	t.Helper()
	key, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return key.PublicKey().Bytes()
}

func TestEd25519PublicKeyFrom(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	encoded, err := ed25519PublicKeyFrom([]attribute{newBytesAttribute(ckaECPoint, public)})
	if err != nil {
		t.Fatalf("ed25519PublicKeyFrom() error = %v", err)
	}
	parsed, err := utilities.ParseEd25519PublicKeyFromBase64(encoded)
	if err != nil {
		t.Fatalf("the encoded key is not parseable by utilities: %v", err)
	}
	if !parsed.Equal(public) {
		t.Fatal("round-tripped public key does not match")
	}

	if _, err := ed25519PublicKeyFrom([]attribute{newBytesAttribute(ckaECPoint, []byte{0x04, 0x01, 0x02})}); err == nil {
		t.Fatal("expected an error for a point of the wrong length")
	}
	if _, err := ed25519PublicKeyFrom(nil); err == nil {
		t.Fatal("expected an error when CKA_EC_POINT is absent")
	}
}

func TestPublicKeyFromAttributes(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	ecKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh GenerateKey() error = %v", err)
	}
	p256Params, _ := asn1.Marshal(oidP256)

	tests := []struct {
		name       string
		attributes []attribute
		wantErr    bool
	}{
		{name: "rsa", attributes: []attribute{
			newULongAttribute(ckaKeyType, uint64(ckkRSA)),
			newBytesAttribute(ckaModulus, rsaKey.N.Bytes()),
			newBytesAttribute(ckaPublicExpon, big.NewInt(int64(rsaKey.E)).Bytes()),
		}},
		{name: "ec", attributes: []attribute{
			newULongAttribute(ckaKeyType, uint64(ckkEC)),
			newBytesAttribute(ckaECPoint, ecKey.PublicKey().Bytes()),
			newBytesAttribute(ckaECParams, p256Params),
		}},
		{name: "edwards", attributes: []attribute{
			newULongAttribute(ckaKeyType, uint64(ckkECEdwards)),
			newBytesAttribute(ckaECPoint, edPublic),
		}},
		{name: "no key type", attributes: nil, wantErr: true},
		{name: "key type not a ulong", attributes: []attribute{
			{Type: ckaKeyType, Value: []byte{1}, Present: true},
		}, wantErr: true},
		{name: "unsupported key type", attributes: []attribute{
			newULongAttribute(ckaKeyType, 0xdead),
		}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := publicKeyFromAttributes(test.attributes)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("publicKeyFromAttributes() error = %v", err)
			}
			if got == "" {
				t.Fatal("publicKeyFromAttributes() returned an empty key")
			}
		})
	}
}

func TestCertificatePublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "forge"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}

	encoded, err := certificatePublicKey([]attribute{newBytesAttribute(ckaValue, der)})
	if err != nil {
		t.Fatalf("certificatePublicKey() error = %v", err)
	}
	parsed, err := utilities.ParseRSAPublicKeyFromBase64(encoded)
	if err != nil {
		t.Fatalf("the encoded key is not parseable: %v", err)
	}
	if parsed.N.Cmp(key.N) != 0 {
		t.Fatal("certificate public key does not match")
	}

	if _, err := certificatePublicKey(nil); err == nil {
		t.Fatal("expected an error when CKA_VALUE is absent")
	}
	if _, err := certificatePublicKey([]attribute{newBytesAttribute(ckaValue, []byte{1, 2, 3})}); err == nil {
		t.Fatal("expected an error for a value that is not a certificate")
	}
}

func TestMarshalPublicKeyRejectsUnsupported(t *testing.T) {
	if _, err := marshalPublicKey("not a key"); err == nil {
		t.Fatal("expected an error for a non-key value")
	}
}

func TestFindObject(t *testing.T) {
	uri := &keyURI{Object: "jwt", ID: []byte{0x01}}

	var captured []attribute
	fake := &fakeModule{
		findObjectsFn: func(_ sessionHandle, template []attribute) ([]objectHandle, error) {
			captured = template
			return []objectHandle{11}, nil
		},
	}

	got, err := findObject(fake, 1, uri, classPrivateKey, true)
	if err != nil || got != 11 {
		t.Fatalf("findObject() = %d, %v", got, err)
	}
	if len(captured) != 3 {
		t.Fatalf("template has %d attributes, want class, label and id", len(captured))
	}

	// Without a class the search template must omit CKA_CLASS entirely.
	if _, err := findObject(fake, 1, uri, 0, false); err != nil {
		t.Fatalf("findObject() error = %v", err)
	}
	if len(captured) != 2 {
		t.Fatalf("template has %d attributes, want label and id only", len(captured))
	}
}

func TestFindObjectNotFound(t *testing.T) {
	fake := &fakeModule{
		findObjectsFn: func(sessionHandle, []attribute) ([]objectHandle, error) { return nil, nil },
	}
	_, err := findObject(fake, 1, &keyURI{Object: "absent"}, classPrivateKey, true)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("findObject() = %v, want ErrKeyNotFound", err)
	}
}

func TestResolveObjectPrefersExplicitClass(t *testing.T) {
	var classes []uint64
	fake := &fakeModule{
		findObjectsFn: func(_ sessionHandle, template []attribute) ([]objectHandle, error) {
			if raw, ok := findAttribute(template, ckaClass); ok {
				value, _ := uLongValue(raw)
				classes = append(classes, value)
			}
			return []objectHandle{3}, nil
		},
	}

	explicit := &keyURI{Object: "k", Class: classSecretKey, HasClass: true}
	if _, err := resolveObject(fake, 1, explicit, classPrivateKey); err != nil {
		t.Fatalf("resolveObject() error = %v", err)
	}
	if len(classes) != 1 || classes[0] != uint64(classSecretKey) {
		t.Fatalf("classes = %v, want the URI class to win", classes)
	}
}

// TestResolveObjectFallsBackToClasslessSearch covers tokens that store objects
// without the class the operation expects.
func TestResolveObjectFallsBackToClasslessSearch(t *testing.T) {
	var attempts int
	fake := &fakeModule{
		findObjectsFn: func(_ sessionHandle, template []attribute) ([]objectHandle, error) {
			attempts++
			if _, ok := findAttribute(template, ckaClass); ok {
				return nil, nil
			}
			return []objectHandle{4}, nil
		},
	}

	got, err := resolveObject(fake, 1, &keyURI{Object: "k"}, classPrivateKey)
	if err != nil || got != 4 {
		t.Fatalf("resolveObject() = %d, %v", got, err)
	}
	if attempts != 2 {
		t.Fatalf("made %d searches, want a classed then a classless one", attempts)
	}
}

// TestPublicObjectForFallsBackToCertificate covers the case that matters on
// smartcards and many HSMs: only the private key and a certificate are stored,
// with no CKO_PUBLIC_KEY object.
func TestPublicObjectForFallsBackToCertificate(t *testing.T) {
	fake := &fakeModule{
		findObjectsFn: func(_ sessionHandle, template []attribute) ([]objectHandle, error) {
			raw, ok := findAttribute(template, ckaClass)
			if !ok {
				return nil, nil
			}
			value, _ := uLongValue(raw)
			if objectClass(value) == classCertificate {
				return []objectHandle{21}, nil
			}
			return nil, nil
		},
	}

	handle, class, err := publicObjectFor(fake, 1, &keyURI{Object: "k", ID: []byte{0x01}})
	if err != nil {
		t.Fatalf("publicObjectFor() error = %v", err)
	}
	if handle != 21 || class != classCertificate {
		t.Fatalf("publicObjectFor() = %d/%v, want the certificate", handle, class)
	}
}

func TestPublicObjectForPrefersPublicKey(t *testing.T) {
	fake := &fakeModule{
		findObjectsFn: func(_ sessionHandle, template []attribute) ([]objectHandle, error) {
			raw, _ := findAttribute(template, ckaClass)
			value, _ := uLongValue(raw)
			if objectClass(value) == classPublicKey {
				return []objectHandle{31}, nil
			}
			return nil, nil
		},
	}
	handle, class, err := publicObjectFor(fake, 1, &keyURI{Object: "k"})
	if err != nil || handle != 31 || class != classPublicKey {
		t.Fatalf("publicObjectFor() = %d/%v/%v", handle, class, err)
	}
}

func TestPublicObjectForNotFound(t *testing.T) {
	fake := &fakeModule{
		findObjectsFn: func(sessionHandle, []attribute) ([]objectHandle, error) { return nil, nil },
	}
	if _, _, err := publicObjectFor(fake, 1, &keyURI{Object: "k", ID: []byte{1}}); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("publicObjectFor() = %v, want ErrKeyNotFound", err)
	}
}

func TestMarshalPublicKeyEncodesBase64(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	encoded, err := marshalPublicKey(public)
	if err != nil {
		t.Fatalf("marshalPublicKey() error = %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(encoded); err != nil {
		t.Fatalf("marshalPublicKey() did not produce base64: %v", err)
	}
}

// marshalPrivateKey encodes an RSA private key the way the local backend
// expects to receive it.
func marshalPrivateKey(key *rsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// marshalECDHPrivateKey encodes an ECDH private key the way the local backend
// expects to receive it.
func marshalECDHPrivateKey(key *ecdh.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}
