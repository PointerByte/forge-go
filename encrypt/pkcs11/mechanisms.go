// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"crypto/sha256"
)

// sha256DigestInfoPrefix is the constant ASN.1 DigestInfo header for SHA-256,
// as used by RSASSA-PKCS1-v1_5. Prepending it to a digest yields exactly what
// CKM_RSA_PKCS expects, which lets a token that only implements the raw
// mechanism still produce a signature identical to CKM_SHA256_RSA_PKCS.
var sha256DigestInfoPrefix = []byte{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
}

// Raw mechanisms used only as degradation targets.
const (
	ckmRSAPKCS    mechanism = 0x00000001
	ckmRSAPKCSPSS mechanism = 0x0000000D
)

// signPlan describes how to produce one signature: which mechanism to invoke,
// which parameters it takes, and what to feed it.
//
// A plan exists because tokens differ in whether they implement the combined
// hash-and-sign mechanisms or only the raw ones. Choosing between them is a
// choice among PKCS#11 mechanisms that all yield the same signature; it is
// never a fallback to signing in software, which would silently void the
// guarantee that the private key stayed in hardware.
type signPlan struct {
	mechanism mechanism
	params    mechanismParams
	// retryParams is tried once when the first attempt fails with
	// CKR_MECHANISM_PARAM_INVALID. Vendors disagree on whether some mechanisms
	// accept a NULL parameter block, and the disagreement is only visible at
	// call time, not in C_GetMechanismList.
	retryParams mechanismParams
	// prepare turns the caller's message into the bytes the mechanism consumes.
	prepare func(message []byte) []byte
}

// identityMessage feeds the message through unchanged, for mechanisms that hash
// internally.
func identityMessage(message []byte) []byte { return message }

// sha256Digest hashes the message, for raw mechanisms that expect a digest.
func sha256Digest(message []byte) []byte {
	sum := sha256.Sum256(message)
	return sum[:]
}

// sha256DigestInfo hashes the message and prepends the DigestInfo header, for
// CKM_RSA_PKCS.
func sha256DigestInfo(message []byte) []byte {
	sum := sha256.Sum256(message)
	return append(append([]byte{}, sha256DigestInfoPrefix...), sum[:]...)
}

// planRSAPKCS1v15 picks the mechanism for RSASSA-PKCS1-v1_5 with SHA-256.
func planRSAPKCS1v15(slot *slotState) (signPlan, error) {
	if slot.supports(ckmSHA256RSAPKCS) {
		return signPlan{mechanism: ckmSHA256RSAPKCS, prepare: identityMessage}, nil
	}
	if slot.supports(ckmRSAPKCS) {
		return signPlan{mechanism: ckmRSAPKCS, prepare: sha256DigestInfo}, nil
	}
	return signPlan{}, errUnsupportedMechanism(ckmSHA256RSAPKCS)
}

// planRSAPSS picks the mechanism for RSASSA-PSS with SHA-256.
//
// The salt length is pinned to the digest size. The local backend signs with
// rsa.PSSSaltLengthAuto, which uses the maximum salt, so a signature made here
// and one made there differ in salt length; both verify under
// PSSSaltLengthAuto, which is what the verification paths use.
func planRSAPSS(slot *slotState) (signPlan, error) {
	params := pssParams{HashAlg: ckmSHA256, MGF: ckgMGF1SHA256, SaltLen: sha256.Size}
	if slot.supports(ckmSHA256RSAPKCSPSS) {
		return signPlan{mechanism: ckmSHA256RSAPKCSPSS, params: params, prepare: identityMessage}, nil
	}
	if slot.supports(ckmRSAPKCSPSS) {
		return signPlan{mechanism: ckmRSAPKCSPSS, params: params, prepare: sha256Digest}, nil
	}
	return signPlan{}, errUnsupportedMechanism(ckmSHA256RSAPKCSPSS)
}

// planEd25519 picks the mechanism for Ed25519. EdDSA is a pure signature
// scheme, so the message is passed whole and never pre-hashed.
func planEd25519(slot *slotState) (signPlan, error) {
	if err := slot.requireMechanism(ckmEdDSA); err != nil {
		return signPlan{}, err
	}
	// CKM_EDDSA takes no parameters in the specification, but several tokens
	// reject a NULL block and require CK_EDDSA_PARAMS instead.
	return signPlan{
		mechanism:   ckmEdDSA,
		prepare:     identityMessage,
		retryParams: eddsaParams{PhFlag: false},
	}, nil
}

// supportsInHardwareECDH reports whether the token can run the whole ECDH
// decrypt path without the derived secret ever leaving it.
func supportsInHardwareECDH(slot *slotState) bool {
	return slot.supports(ckmECDH1Derive) && slot.supports(ckmHKDFDerive) && slot.supports(ckmAESGCM)
}
