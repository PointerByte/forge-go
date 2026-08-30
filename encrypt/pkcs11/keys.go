// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
)

// findObject resolves a key URI to exactly one object handle.
func findObject(mod module, session sessionHandle, uri *keyURI, class objectClass, useClass bool) (objectHandle, error) {
	template := make([]attribute, 0, 3)
	if useClass {
		template = append(template, newULongAttribute(ckaClass, uint64(class)))
	}
	if uri.Object != "" {
		template = append(template, newBytesAttribute(ckaLabel, []byte(uri.Object)))
	}
	if len(uri.ID) > 0 {
		template = append(template, newBytesAttribute(ckaID, uri.ID))
	}

	handles, err := mod.FindObjects(session, template)
	if err != nil {
		return 0, err
	}
	if len(handles) == 0 {
		return 0, fmt.Errorf("%w: %s", ErrKeyNotFound, uri.String())
	}
	return handles[0], nil
}

// resolveObject finds the object a URI names, honouring an explicit "type"
// attribute and otherwise falling back to the class the operation needs.
func resolveObject(mod module, session sessionHandle, uri *keyURI, fallback objectClass) (objectHandle, error) {
	if uri.HasClass {
		return findObject(mod, session, uri, uri.Class, true)
	}
	if handle, err := findObject(mod, session, uri, fallback, true); err == nil {
		return handle, nil
	}
	return findObject(mod, session, uri, 0, false)
}

// publicObjectFor locates the public half of a key.
//
// Tokens vary widely here: some store a matching CKO_PUBLIC_KEY, many
// smartcards and HSMs store only the private key alongside an X.509
// certificate. Trying all three in order is what separates a GetKey that works
// on real hardware from one that only works on SoftHSM.
func publicObjectFor(mod module, session sessionHandle, uri *keyURI) (objectHandle, objectClass, error) {
	if handle, err := findObject(mod, session, uri, classPublicKey, true); err == nil {
		return handle, classPublicKey, nil
	}

	if len(uri.ID) > 0 {
		byID := &keyURI{Token: uri.Token, ID: uri.ID}
		if handle, err := findObject(mod, session, byID, classPublicKey, true); err == nil {
			return handle, classPublicKey, nil
		}
		if handle, err := findObject(mod, session, byID, classCertificate, true); err == nil {
			return handle, classCertificate, nil
		}
	}

	if handle, err := findObject(mod, session, uri, classCertificate, true); err == nil {
		return handle, classCertificate, nil
	}
	return 0, 0, fmt.Errorf("%w: no public key or certificate for %s", ErrKeyNotFound, uri.String())
}

// decodeECPoint extracts the SEC1 point from CKA_EC_POINT.
//
// The specification says the value is an ASN.1 OCTET STRING wrapping the point,
// but several tokens return the bare point. The two cases are ambiguous because
// 0x04 is both the OCTET STRING tag and the uncompressed-point prefix, so the
// DER reading is only accepted when the unwrapped length is consistent with an
// uncompressed point.
func decodeECPoint(value []byte) ([]byte, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("pkcs11: empty CKA_EC_POINT")
	}

	var unwrapped []byte
	if rest, err := asn1.Unmarshal(value, &unwrapped); err == nil && len(rest) == 0 {
		if isPlausibleECPoint(unwrapped) {
			return unwrapped, nil
		}
	}
	if isPlausibleECPoint(value) {
		return value, nil
	}
	return nil, fmt.Errorf("pkcs11: CKA_EC_POINT is neither a wrapped nor a bare point")
}

// isPlausibleECPoint reports whether value looks like an uncompressed SEC1
// point (0x04 followed by two equal-length coordinates) or an Edwards point.
func isPlausibleECPoint(value []byte) bool {
	switch {
	case len(value) == ed25519.PublicKeySize:
		return true
	case len(value) > 1 && value[0] == 0x04 && (len(value)-1)%2 == 0:
		return true
	default:
		return false
	}
}

// rsaPublicKeyFrom builds a PKIX-encoded, Base64 RSA public key from the
// CKA_MODULUS and CKA_PUBLIC_EXPONENT of a token object, which is the encoding
// every other backend returns in KeyData.PublicKey.
func rsaPublicKeyFrom(attributes []attribute) (string, error) {
	modulus, ok := findAttribute(attributes, ckaModulus)
	if !ok {
		return "", fmt.Errorf("pkcs11: object has no CKA_MODULUS")
	}
	exponent, ok := findAttribute(attributes, ckaPublicExpon)
	if !ok {
		return "", fmt.Errorf("pkcs11: object has no CKA_PUBLIC_EXPONENT")
	}

	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: int(new(big.Int).SetBytes(exponent).Int64()),
	}
	if publicKey.N.Sign() == 0 || publicKey.E == 0 {
		return "", fmt.Errorf("pkcs11: object has an unusable rsa public key")
	}
	return marshalPublicKey(publicKey)
}

// ecdhPublicKeyFrom builds a PKIX-encoded, Base64 ECDH public key from
// CKA_EC_POINT and CKA_EC_PARAMS.
func ecdhPublicKeyFrom(attributes []attribute) (string, error) {
	point, err := ecPointFrom(attributes)
	if err != nil {
		return "", err
	}
	params, ok := findAttribute(attributes, ckaECParams)
	if !ok {
		return "", fmt.Errorf("pkcs11: object has no CKA_EC_PARAMS")
	}

	curve, err := curveFromECParams(params)
	if err != nil {
		return "", err
	}
	publicKey, err := curve.NewPublicKey(point)
	if err != nil {
		return "", fmt.Errorf("pkcs11: parse ec point: %w", err)
	}
	return marshalPublicKey(publicKey)
}

// ed25519PublicKeyFrom builds a PKIX-encoded, Base64 Ed25519 public key.
func ed25519PublicKeyFrom(attributes []attribute) (string, error) {
	point, err := ecPointFrom(attributes)
	if err != nil {
		return "", err
	}
	if len(point) != ed25519.PublicKeySize {
		return "", fmt.Errorf("pkcs11: ed25519 public key has %d bytes, want %d", len(point), ed25519.PublicKeySize)
	}
	return marshalPublicKey(ed25519.PublicKey(point))
}

// ecPointFrom reads and unwraps CKA_EC_POINT.
func ecPointFrom(attributes []attribute) ([]byte, error) {
	raw, ok := findAttribute(attributes, ckaECPoint)
	if !ok {
		return nil, fmt.Errorf("pkcs11: object has no CKA_EC_POINT")
	}
	return decodeECPoint(raw)
}

// curveFromECParams maps a DER-encoded named curve OID to its ecdh.Curve.
func curveFromECParams(params []byte) (ecdh.Curve, error) {
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(params, &oid); err != nil {
		return nil, fmt.Errorf("pkcs11: decode CKA_EC_PARAMS: %w", err)
	}
	switch {
	case oid.Equal(oidP256):
		return ecdh.P256(), nil
	case oid.Equal(oidP384):
		return ecdh.P384(), nil
	case oid.Equal(oidP521):
		return ecdh.P521(), nil
	default:
		return nil, fmt.Errorf("pkcs11: unsupported curve oid %v", oid)
	}
}

// certificatePublicKey extracts the public key from a CKO_CERTIFICATE object's
// CKA_VALUE, which holds the DER X.509 certificate.
func certificatePublicKey(attributes []attribute) (string, error) {
	der, ok := findAttribute(attributes, ckaValue)
	if !ok {
		return "", fmt.Errorf("pkcs11: certificate object has no CKA_VALUE")
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("pkcs11: parse certificate: %w", err)
	}
	return marshalPublicKey(certificate.PublicKey)
}

// marshalPublicKey encodes a public key the way every backend reports it: PKIX
// DER, Base64 with standard padding.
func marshalPublicKey(publicKey any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("pkcs11: marshal public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}
