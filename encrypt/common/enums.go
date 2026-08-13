// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package common

// SizeSymetrycKey defines the supported symmetric key sizes in bytes.
type SizeSymetrycKey uint

const (
	// Key128Bits represents a 128-bit symmetric key.
	Key128Bits SizeSymetrycKey = 16
	// Key256Bits represents a 256-bit symmetric key.
	Key256Bits SizeSymetrycKey = 32
)

// SizeAsymetrycKey defines the supported asymmetric key sizes in bits.
type SizeAsymetrycKey uint

const (
	// Key2048Bits represents a 2048-bit asymmetric key.
	Key2048Bits SizeAsymetrycKey = 2048
	// Key3072Bits represents a 3072-bit asymmetric key.
	Key3072Bits SizeAsymetrycKey = 3072
	// Key4096Bits represents a 4096-bit asymmetric key.
	Key4096Bits SizeAsymetrycKey = 4096
)

// CurveAsymmetricKey defines the supported elliptic curves for ECC encryption.
type CurveAsymmetricKey uint

const (
	// CurveP256 represents the NIST P-256 curve.
	CurveP256 CurveAsymmetricKey = 256
	// CurveP384 represents the NIST P-384 curve.
	CurveP384 CurveAsymmetricKey = 384
	// CurveP521 represents the NIST P-521 curve.
	CurveP521 CurveAsymmetricKey = 521
)

// String returns the canonical serialized name of the curve.
func (c CurveAsymmetricKey) String() string {
	switch c {
	case CurveP256:
		return "P-256"
	case CurveP384:
		return "P-384"
	case CurveP521:
		return "P-521"
	default:
		return "unknown"
	}
}
