// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"errors"
	"fmt"
)

var (
	// ErrUnavailable is returned by every constructor when the package was
	// built without the "pkcs11" build tag or without cgo.
	ErrUnavailable = errors.New("pkcs11: support is not compiled in; rebuild with -tags pkcs11 and CGO_ENABLED=1")

	// ErrModuleRequired is returned when no PKCS#11 library path was supplied
	// through options or configuration.
	ErrModuleRequired = errors.New("pkcs11: module path is required")

	// ErrTokenRequired is returned when neither a token label nor a slot id
	// was supplied through options or configuration.
	ErrTokenRequired = errors.New("pkcs11: token label or slot id is required")

	// ErrPinRequired is returned when no PinProvider was supplied. The PIN is
	// never read from configuration.
	ErrPinRequired = errors.New("pkcs11: pin provider is required")

	// ErrKeyURIRequired is returned when an operation needs a key reference and
	// neither the request nor the configuration supplied one.
	ErrKeyURIRequired = errors.New("pkcs11: key uri is required")

	// ErrKeyNotFound is returned when no object on the token matches the
	// supplied key URI.
	ErrKeyNotFound = errors.New("pkcs11: no object matches the key uri")

	// ErrOAEPHashUnsupported is returned when the token rejects the SHA-256
	// OAEP parameters this package pins.
	//
	// The parameters are not negotiable: every other backend encrypts RSA-OAEP
	// with SHA-256 and MGF1-SHA256, so a token-side downgrade to SHA-1 would
	// produce ciphertext the local backend cannot read, besides being weaker.
	// SoftHSM2 is the common case, as it hardcodes OAEP to SHA-1.
	ErrOAEPHashUnsupported = errors.New("pkcs11: token does not accept RSA-OAEP with SHA-256; the parameters are fixed for cross-backend compatibility")

	// ErrSecretNotExtractable is returned when the token policy forbids reading
	// the derived shared secret, which makes the interoperable ECDH payload
	// format impossible to produce. See the ECDH_Decode documentation.
	ErrSecretNotExtractable = errors.New("pkcs11: token policy forbids extracting the derived secret; ECDH is unavailable on this token")
)

// unsupportedMechanismError reports that the token did not advertise a
// mechanism required by an operation. It is deliberately not a silent fallback
// to software: a caller asking for a hardware-backed operation must be told
// when the hardware cannot perform it.
type unsupportedMechanismError struct {
	mechanism mechanism
}

func (e unsupportedMechanismError) Error() string {
	return fmt.Sprintf("pkcs11: token does not support mechanism %s", e.mechanism)
}

func errUnsupportedMechanism(m mechanism) error {
	return unsupportedMechanismError{mechanism: m}
}

// returnValue is a PKCS#11 CK_RV result code.
type returnValue uint64

// The subset of CK_RV values the package maps to descriptive errors. Any other
// value is reported by its numeric code.
const (
	ckrOK                  returnValue = 0x00000000
	ckrCancel              returnValue = 0x00000001
	ckrHostMemory          returnValue = 0x00000002
	ckrSlotIDInvalid       returnValue = 0x00000003
	ckrGeneralError        returnValue = 0x00000005
	ckrFunctionFailed      returnValue = 0x00000006
	ckrArgumentsBad        returnValue = 0x00000007
	ckrAttributeReadOnly   returnValue = 0x00000010
	ckrAttributeSensitive  returnValue = 0x00000011
	ckrAttributeTypeInalid returnValue = 0x00000012
	ckrAttributeValueInval returnValue = 0x00000013
	ckrDataInvalid         returnValue = 0x00000020
	ckrDataLenRange        returnValue = 0x00000021
	ckrDeviceError         returnValue = 0x00000030
	ckrDeviceMemory        returnValue = 0x00000031
	ckrDeviceRemoved       returnValue = 0x00000032
	ckrEncryptedDataInval  returnValue = 0x00000040
	ckrEncryptedDataLenRng returnValue = 0x00000041
	ckrKeyHandleInvalid    returnValue = 0x00000060
	ckrKeySizeRange        returnValue = 0x00000062
	ckrKeyTypeInconsistent returnValue = 0x00000063
	ckrKeyFunctionNotPerm  returnValue = 0x00000068
	ckrKeyNotWrappable     returnValue = 0x00000069
	ckrKeyUnextractable    returnValue = 0x0000006A
	ckrMechanismInvalid    returnValue = 0x00000070
	ckrMechanismParamInval returnValue = 0x00000071
	ckrObjectHandleInvalid returnValue = 0x00000082
	ckrOperationActive     returnValue = 0x00000090
	ckrOperationNotInit    returnValue = 0x00000091
	ckrPinIncorrect        returnValue = 0x000000A0
	ckrPinInvalid          returnValue = 0x000000A1
	ckrPinLenRange         returnValue = 0x000000A2
	ckrPinExpired          returnValue = 0x000000A3
	ckrPinLocked           returnValue = 0x000000A4
	ckrSessionClosed       returnValue = 0x000000B0
	ckrSessionCount        returnValue = 0x000000B1
	ckrSessionHandleInval  returnValue = 0x000000B3
	ckrSessionReadOnly     returnValue = 0x000000B5
	ckrSignatureInvalid    returnValue = 0x000000C0
	ckrSignatureLenRange   returnValue = 0x000000C1
	ckrTemplateIncomplete  returnValue = 0x000000D0
	ckrTemplateInconsisten returnValue = 0x000000D1
	ckrTokenNotPresent     returnValue = 0x000000E0
	ckrTokenNotRecognized  returnValue = 0x000000E1
	ckrTokenWriteProtected returnValue = 0x000000E2
	ckrUserAlreadyLoggedIn returnValue = 0x00000100
	ckrUserNotLoggedIn     returnValue = 0x00000101
	ckrUserPinNotInitiated returnValue = 0x00000102
	ckrUserTypeInvalid     returnValue = 0x00000103
	ckrCryptokiNotInitiali returnValue = 0x00000190
	ckrCryptokiAlreadyInit returnValue = 0x00000191
	ckrBufferTooSmall      returnValue = 0x00000150
)

// ckrNames maps the CK_RV values above to their canonical spec names.
var ckrNames = map[returnValue]string{
	ckrCancel:              "CKR_CANCEL",
	ckrHostMemory:          "CKR_HOST_MEMORY",
	ckrSlotIDInvalid:       "CKR_SLOT_ID_INVALID",
	ckrGeneralError:        "CKR_GENERAL_ERROR",
	ckrFunctionFailed:      "CKR_FUNCTION_FAILED",
	ckrArgumentsBad:        "CKR_ARGUMENTS_BAD",
	ckrAttributeReadOnly:   "CKR_ATTRIBUTE_READ_ONLY",
	ckrAttributeSensitive:  "CKR_ATTRIBUTE_SENSITIVE",
	ckrAttributeTypeInalid: "CKR_ATTRIBUTE_TYPE_INVALID",
	ckrAttributeValueInval: "CKR_ATTRIBUTE_VALUE_INVALID",
	ckrDataInvalid:         "CKR_DATA_INVALID",
	ckrDataLenRange:        "CKR_DATA_LEN_RANGE",
	ckrDeviceError:         "CKR_DEVICE_ERROR",
	ckrDeviceMemory:        "CKR_DEVICE_MEMORY",
	ckrDeviceRemoved:       "CKR_DEVICE_REMOVED",
	ckrEncryptedDataInval:  "CKR_ENCRYPTED_DATA_INVALID",
	ckrEncryptedDataLenRng: "CKR_ENCRYPTED_DATA_LEN_RANGE",
	ckrKeyHandleInvalid:    "CKR_KEY_HANDLE_INVALID",
	ckrKeySizeRange:        "CKR_KEY_SIZE_RANGE",
	ckrKeyTypeInconsistent: "CKR_KEY_TYPE_INCONSISTENT",
	ckrKeyFunctionNotPerm:  "CKR_KEY_FUNCTION_NOT_PERMITTED",
	ckrKeyNotWrappable:     "CKR_KEY_NOT_WRAPPABLE",
	ckrKeyUnextractable:    "CKR_KEY_UNEXTRACTABLE",
	ckrMechanismInvalid:    "CKR_MECHANISM_INVALID",
	ckrMechanismParamInval: "CKR_MECHANISM_PARAM_INVALID",
	ckrObjectHandleInvalid: "CKR_OBJECT_HANDLE_INVALID",
	ckrOperationActive:     "CKR_OPERATION_ACTIVE",
	ckrOperationNotInit:    "CKR_OPERATION_NOT_INITIALIZED",
	ckrPinIncorrect:        "CKR_PIN_INCORRECT",
	ckrPinInvalid:          "CKR_PIN_INVALID",
	ckrPinLenRange:         "CKR_PIN_LEN_RANGE",
	ckrPinExpired:          "CKR_PIN_EXPIRED",
	ckrPinLocked:           "CKR_PIN_LOCKED",
	ckrSessionClosed:       "CKR_SESSION_CLOSED",
	ckrSessionCount:        "CKR_SESSION_COUNT",
	ckrSessionHandleInval:  "CKR_SESSION_HANDLE_INVALID",
	ckrSessionReadOnly:     "CKR_SESSION_READ_ONLY",
	ckrSignatureInvalid:    "CKR_SIGNATURE_INVALID",
	ckrSignatureLenRange:   "CKR_SIGNATURE_LEN_RANGE",
	ckrTemplateIncomplete:  "CKR_TEMPLATE_INCOMPLETE",
	ckrTemplateInconsisten: "CKR_TEMPLATE_INCONSISTENT",
	ckrTokenNotPresent:     "CKR_TOKEN_NOT_PRESENT",
	ckrTokenNotRecognized:  "CKR_TOKEN_NOT_RECOGNIZED",
	ckrTokenWriteProtected: "CKR_TOKEN_WRITE_PROTECTED",
	ckrUserAlreadyLoggedIn: "CKR_USER_ALREADY_LOGGED_IN",
	ckrUserNotLoggedIn:     "CKR_USER_NOT_LOGGED_IN",
	ckrUserPinNotInitiated: "CKR_USER_PIN_NOT_INITIALIZED",
	ckrUserTypeInvalid:     "CKR_USER_TYPE_INVALID",
	ckrCryptokiNotInitiali: "CKR_CRYPTOKI_NOT_INITIALIZED",
	ckrCryptokiAlreadyInit: "CKR_CRYPTOKI_ALREADY_INITIALIZED",
	ckrBufferTooSmall:      "CKR_BUFFER_TOO_SMALL",
}

// tokenError wraps a non-zero CK_RV together with the C function that produced
// it. It never carries key material, plaintext or ciphertext.
type tokenError struct {
	function string
	code     returnValue
}

func (e tokenError) Error() string {
	if name, ok := ckrNames[e.code]; ok {
		return fmt.Sprintf("pkcs11: %s failed: %s", e.function, name)
	}
	return fmt.Sprintf("pkcs11: %s failed: CK_RV 0x%08X", e.function, uint64(e.code))
}

// Is lets callers match a token error against the package sentinels for the
// two policy conditions worth branching on.
func (e tokenError) Is(target error) bool {
	switch target {
	case ErrSecretNotExtractable:
		return e.code == ckrAttributeSensitive || e.code == ckrKeyUnextractable
	case ErrKeyNotFound:
		return e.code == ckrObjectHandleInvalid || e.code == ckrKeyHandleInvalid
	default:
		return false
	}
}

// newTokenError returns nil for CKR_OK and a descriptive error otherwise.
func newTokenError(function string, code returnValue) error {
	if code == ckrOK {
		return nil
	}
	return tokenError{function: function, code: code}
}
