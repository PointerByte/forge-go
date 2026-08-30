// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"encoding/asn1"
	"fmt"

	"github.com/PointerByte/forge-go/encrypt/common"
)

// mechanism is a PKCS#11 CKM_ mechanism type.
type mechanism uint64

// The mechanisms this package can request. Every one is checked against
// C_GetMechanismList before use.
const (
	ckmRSAPKCSKeyPairGen  mechanism = 0x00000000
	ckmRSAPKCSOAEP        mechanism = 0x00000009
	ckmSHA256RSAPKCS      mechanism = 0x00000040
	ckmSHA256RSAPKCSPSS   mechanism = 0x00000043
	ckmECKeyPairGen       mechanism = 0x00001040
	ckmECDH1Derive        mechanism = 0x00001050
	ckmAESKeyGen          mechanism = 0x00001080
	ckmAESGCM             mechanism = 0x00001087
	ckmSHA256HMAC         mechanism = 0x00000251
	ckmSHA256             mechanism = 0x00000250
	ckmECEdwardsKeyPairGe mechanism = 0x00001055
	ckmEdDSA              mechanism = 0x00001057
	ckmGenericSecretKeyGe mechanism = 0x00000350
	ckmHKDFDerive         mechanism = 0x0000402A
)

// mechanismNames gives each mechanism its spec name for error messages.
var mechanismNames = map[mechanism]string{
	ckmRSAPKCSKeyPairGen:  "CKM_RSA_PKCS_KEY_PAIR_GEN",
	ckmRSAPKCSOAEP:        "CKM_RSA_PKCS_OAEP",
	ckmSHA256RSAPKCS:      "CKM_SHA256_RSA_PKCS",
	ckmSHA256RSAPKCSPSS:   "CKM_SHA256_RSA_PKCS_PSS",
	ckmECKeyPairGen:       "CKM_EC_KEY_PAIR_GEN",
	ckmECDH1Derive:        "CKM_ECDH1_DERIVE",
	ckmAESKeyGen:          "CKM_AES_KEY_GEN",
	ckmAESGCM:             "CKM_AES_GCM",
	ckmSHA256HMAC:         "CKM_SHA256_HMAC",
	ckmSHA256:             "CKM_SHA256",
	ckmECEdwardsKeyPairGe: "CKM_EC_EDWARDS_KEY_PAIR_GEN",
	ckmEdDSA:              "CKM_EDDSA",
	ckmGenericSecretKeyGe: "CKM_GENERIC_SECRET_KEY_GEN",
	ckmHKDFDerive:         "CKM_HKDF_DERIVE",
}

// String returns the canonical CKM_ name, falling back to the numeric code for
// mechanisms the package does not name.
func (m mechanism) String() string {
	if name, ok := mechanismNames[m]; ok {
		return name
	}
	return fmt.Sprintf("CKM_0x%08X", uint64(m))
}

// attributeType is a PKCS#11 CKA_ attribute type.
type attributeType uint64

// The attributes this package reads or writes.
const (
	ckaClass       attributeType = 0x00000000
	ckaToken       attributeType = 0x00000001
	ckaPrivate     attributeType = 0x00000002
	ckaLabel       attributeType = 0x00000003
	ckaKeyType     attributeType = 0x00000100
	ckaID          attributeType = 0x00000102
	ckaSensitive   attributeType = 0x00000103
	ckaEncrypt     attributeType = 0x00000104
	ckaDecrypt     attributeType = 0x00000105
	ckaWrap        attributeType = 0x00000106
	ckaUnwrap      attributeType = 0x00000107
	ckaSign        attributeType = 0x00000108
	ckaVerify      attributeType = 0x0000010A
	ckaDerive      attributeType = 0x0000010C
	ckaModulus     attributeType = 0x00000120
	ckaModulusBits attributeType = 0x00000121
	ckaPublicExpon attributeType = 0x00000122
	// ckaPrivateExponent is only ever read to prove it is unreadable; see the
	// non-extractability integration test.
	ckaPrivateExponent attributeType = 0x00000123
	ckaValue           attributeType = 0x00000011
	ckaValueLen        attributeType = 0x00000161
	ckaExtractable     attributeType = 0x00000162
	ckaECParams        attributeType = 0x00000180
	ckaECPoint         attributeType = 0x00000181
)

// keyType is a PKCS#11 CKK_ key type.
type keyType uint64

const (
	ckkRSA           keyType = 0x00000000
	ckkEC            keyType = 0x00000003
	ckkGenericSecret keyType = 0x00000010
	ckkAES           keyType = 0x0000001F
	ckkECEdwards     keyType = 0x00000040
)

// attribute is one CKA_ type/value pair. Values are raw bytes in the encoding
// PKCS#11 expects: little-endian CK_ULONG for numbers, a single byte for
// CK_BBOOL, DER for CKA_EC_PARAMS.
type attribute struct {
	Type  attributeType
	Value []byte
	// Present reports whether the object actually carries this attribute. It
	// is only meaningful on values returned by module.GetAttributes, where a
	// missing attribute comes back with Present false instead of failing the
	// whole call. Sending an attribute an object does not have makes
	// C_SetAttributeValue reject the entire template with
	// CKR_ATTRIBUTE_TYPE_INVALID, so DeactivateKey probes before it writes.
	Present bool
}

// newBoolAttribute builds a CK_BBOOL attribute.
func newBoolAttribute(kind attributeType, value bool) attribute {
	encoded := byte(0)
	if value {
		encoded = 1
	}
	return attribute{Type: kind, Value: []byte{encoded}, Present: true}
}

// newULongAttribute builds a CK_ULONG attribute in the platform encoding the
// binding expects (little-endian on every supported platform).
func newULongAttribute(kind attributeType, value uint64) attribute {
	encoded := make([]byte, 8)
	for index := 0; index < 8; index++ {
		encoded[index] = byte(value >> (8 * index))
	}
	return attribute{Type: kind, Value: encoded, Present: true}
}

// newBytesAttribute builds an attribute from raw bytes.
func newBytesAttribute(kind attributeType, value []byte) attribute {
	return attribute{Type: kind, Value: value, Present: true}
}

// uLongValue decodes a CK_ULONG attribute value.
func uLongValue(value []byte) (uint64, bool) {
	if len(value) != 8 {
		return 0, false
	}
	var decoded uint64
	for index := 0; index < 8; index++ {
		decoded |= uint64(value[index]) << (8 * index)
	}
	return decoded, true
}

// boolValue decodes a CK_BBOOL attribute value.
func boolValue(value []byte) (bool, bool) {
	if len(value) != 1 {
		return false, false
	}
	return value[0] != 0, true
}

// findAttribute returns the value of kind within attributes.
func findAttribute(attributes []attribute, kind attributeType) ([]byte, bool) {
	for _, candidate := range attributes {
		if candidate.Type == kind && candidate.Present {
			return candidate.Value, true
		}
	}
	return nil, false
}

// hasAttribute reports whether the object carries kind at all, regardless of
// its value. DeactivateKey uses it to build a template the token will accept.
func hasAttribute(attributes []attribute, kind attributeType) bool {
	for _, candidate := range attributes {
		if candidate.Type == kind && candidate.Present {
			return true
		}
	}
	return false
}

// Mask generation functions (CKG_MGF1_*).
const (
	ckgMGF1SHA256 uint64 = 0x00000002
)

// Source types for CK_RSA_PKCS_OAEP_PARAMS (CKZ_*). CKZ_DATA_SPECIFIED is the
// only defined value and is required even when no label is supplied; leaving
// the field zero makes strict tokens reject C_DecryptInit with
// CKR_ARGUMENTS_BAD.
const (
	ckzDataSpecified uint64 = 0x00000001
)

// Key derivation functions for CKM_ECDH1_DERIVE (CKD_*). The package uses
// CKD_NULL and runs HKDF as a separate derive step, because the KDFs this
// mechanism offers are ANSI X9.63, not HKDF, and could not reproduce the
// key that utilities.DeriveECCAESKey computes.
const (
	ckdNULL uint64 = 0x00000001
)

// Salt types for CKM_HKDF_DERIVE (CKF_HKDF_SALT_*). NULL means a salt of
// HashLen zero bytes, which is exactly RFC 5869 with a nil salt.
const (
	ckfHKDFSaltNull uint64 = 0x00000001
)

// Named curve OIDs, DER-encoded into CKA_EC_PARAMS.
var (
	oidP256    = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384    = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidP521    = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// ecParamsForCurve encodes CKA_EC_PARAMS for a NIST curve.
func ecParamsForCurve(curve common.CurveAsymmetricKey) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	switch curve {
	case common.CurveP256:
		oid = oidP256
	case common.CurveP384:
		oid = oidP384
	case common.CurveP521:
		oid = oidP521
	default:
		return nil, fmt.Errorf("pkcs11: unsupported ecc curve: %q", curve)
	}
	encoded, err := asn1.Marshal(oid)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: encode ec params: %w", err)
	}
	return encoded, nil
}

// ecParamsForEd25519 encodes CKA_EC_PARAMS for the Edwards25519 curve.
func ecParamsForEd25519() ([]byte, error) {
	encoded, err := asn1.Marshal(oidEd25519)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: encode ed25519 ec params: %w", err)
	}
	return encoded, nil
}

// rsaModulusBits validates the requested RSA size against the sizes the module
// supports.
func rsaModulusBits(size common.SizeAsymetrycKey) (uint64, error) {
	switch size {
	case common.Key2048Bits, common.Key3072Bits, common.Key4096Bits:
		return uint64(size), nil
	default:
		return 0, fmt.Errorf("pkcs11: unsupported rsa key size: %d", size)
	}
}

// aesValueLen validates the requested AES size, which common expresses in
// bytes.
func aesValueLen(size common.SizeSymetrycKey) (uint64, error) {
	switch size {
	case common.Key128Bits, common.Key256Bits:
		return uint64(size), nil
	default:
		return 0, fmt.Errorf("pkcs11: unsupported symmetric key size: %d", size)
	}
}

// gcmNonceLength is the AES-GCM IV length shared with the local backend, so a
// ciphertext produced here decrypts there and vice versa.
const gcmNonceLength = 12

// gcmTagBits is the AES-GCM authentication tag length in bits.
const gcmTagBits = 128
