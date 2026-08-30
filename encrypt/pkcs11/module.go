// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

// sessionHandle is a CK_SESSION_HANDLE.
type sessionHandle uint64

// objectHandle is a CK_OBJECT_HANDLE.
type objectHandle uint64

// slotInfo is the subset of CK_SLOT_INFO and CK_TOKEN_INFO the package needs
// to resolve a token label to a slot id.
type slotInfo struct {
	// ID is the CK_SLOT_ID.
	ID uint64
	// TokenLabel is the CKA_LABEL of the token in the slot, space-trimmed.
	TokenLabel string
	// TokenPresent reports whether a token is currently in the slot.
	TokenPresent bool
	// MaxSessions is CK_TOKEN_INFO.ulMaxSessionCount, or 0 when the token
	// reports CK_EFFECTIVELY_INFINITE.
	MaxSessions uint64
}

// mechanismParams is implemented by the parameter block of every mechanism
// that takes one.
//
// The corresponding C structures (CK_GCM_PARAMS, CK_RSA_PKCS_OAEP_PARAMS,
// CK_ECDH1_DERIVE_PARAMS, CK_HKDF_PARAMS) all embed raw C pointers, so they
// can never be marshalled into a []byte on the Go side: storing a Go pointer
// in C-visible memory violates the cgo pointer rules and is caught by
// GODEBUG=cgocheck=2. The conversion therefore happens below this seam, in
// module_cgo.go, and everything above it stays pure Go and testable.
type mechanismParams interface {
	isMechanismParams()
}

// gcmParams carries CK_GCM_PARAMS. The package always supplies the IV itself
// rather than letting the token generate it, because vendors disagree on who
// owns IV generation and a caller-supplied IV keeps the wire format identical
// to the local backend.
type gcmParams struct {
	// IV is the nonce; always gcmNonceLength bytes.
	IV []byte
	// AAD is the additional authenticated data, possibly empty.
	AAD []byte
	// TagBits is the tag length in bits; always gcmTagBits.
	TagBits uint64
}

func (gcmParams) isMechanismParams() {}

// oaepParams carries CK_RSA_PKCS_OAEP_PARAMS, pinned to SHA-256 with
// MGF1-SHA256 and an empty label to match the local and cloud backends.
type oaepParams struct {
	// HashAlg is the CKM_ digest mechanism.
	HashAlg mechanism
	// MGF is the CKG_ mask generation function.
	MGF uint64
	// Source is the CKZ_ source type. It must be CKZ_DATA_SPECIFIED even with
	// an empty label, which is what the binding fills in.
	Source uint64
}

func (oaepParams) isMechanismParams() {}

// pssParams carries CK_RSA_PKCS_PSS_PARAMS.
type pssParams struct {
	// HashAlg is the CKM_ digest mechanism.
	HashAlg mechanism
	// MGF is the CKG_ mask generation function.
	MGF uint64
	// SaltLen is the salt length in bytes.
	SaltLen uint64
}

func (pssParams) isMechanismParams() {}

// ecdh1Params carries CK_ECDH1_DERIVE_PARAMS.
type ecdh1Params struct {
	// KDF is the CKD_ key derivation function; the package uses CKD_NULL and
	// performs HKDF as a separate derive step.
	KDF uint64
	// SharedData is the optional shared data; unused.
	SharedData []byte
	// PublicData is the peer public key point. PKCS#11 wants the bare SEC1
	// point here, which is the opposite convention to CKA_EC_POINT.
	PublicData []byte
}

func (ecdh1Params) isMechanismParams() {}

// hkdfParams carries CK_HKDF_PARAMS. Extract with a null salt is bit-for-bit
// RFC 5869 with a nil salt, which is what utilities.DeriveECCAESKey computes,
// so an HKDF performed inside the token yields the same key as the local
// backend derives in software.
type hkdfParams struct {
	// Extract enables the HKDF-Extract step.
	Extract bool
	// Expand enables the HKDF-Expand step.
	Expand bool
	// PRF is the CKM_ digest mechanism backing HMAC.
	PRF mechanism
	// SaltType is the CKF_HKDF_SALT_ constant; the package uses NULL.
	SaltType uint64
	// Info is the HKDF info string.
	Info []byte
}

func (hkdfParams) isMechanismParams() {}

// eddsaParams carries CK_EDDSA_PARAMS. Some tokens reject a NULL parameter for
// CKM_EDDSA and require this block instead.
type eddsaParams struct {
	// PhFlag selects prehashed Ed25519ph; always false here.
	PhFlag bool
}

func (eddsaParams) isMechanismParams() {}

// module is the whole PKCS#11 surface this package depends on, expressed in Go
// types. It is the single seam between the pure-Go repository logic and the
// cgo binding: every C type, every malloc, and the two-call
// size-then-fill convention stay below it, which keeps the repository
// testable with an in-memory fake.
type module interface {
	// Initialize calls C_Initialize with CKF_OS_LOCKING_OK and treats
	// CKR_CRYPTOKI_ALREADY_INITIALIZED as success, because another consumer in
	// the process may share the same library.
	Initialize() error
	// Finalize calls C_Finalize. It deliberately does not dlclose: several
	// vendor modules leave threads or atexit handlers behind and crash when
	// unloaded.
	Finalize() error
	// Slots lists the slots, optionally restricted to those holding a token.
	Slots(tokenPresent bool) ([]slotInfo, error)
	// Mechanisms lists the CKM_ values the slot advertises.
	Mechanisms(slot uint64) ([]mechanism, error)

	// OpenSession opens a read/write user session on slot.
	OpenSession(slot uint64) (sessionHandle, error)
	// CloseSession closes a session opened by OpenSession.
	CloseSession(session sessionHandle) error
	// Login authenticates the user on the session's slot. Login state is
	// per-token and shared across the application's sessions on that slot, so
	// this runs once. CKR_USER_ALREADY_LOGGED_IN counts as success.
	Login(session sessionHandle, pin string) error
	// Logout drops the login state for the session's slot.
	Logout(session sessionHandle) error

	// FindObjects returns the handles matching template.
	FindObjects(session sessionHandle, template []attribute) ([]objectHandle, error)
	// GetAttributes reads the requested attributes from an object. Attributes
	// the object does not carry are reported through the returned attribute's
	// Present field rather than failing the whole call.
	GetAttributes(session sessionHandle, object objectHandle, types []attributeType) ([]attribute, error)
	// SetAttributes writes attributes onto an existing object.
	SetAttributes(session sessionHandle, object objectHandle, template []attribute) error
	// DestroyObject removes an object from the token.
	DestroyObject(session sessionHandle, object objectHandle) error

	// GenerateKey creates a secret key object.
	GenerateKey(session sessionHandle, mech mechanism, template []attribute) (objectHandle, error)
	// GenerateKeyPair creates a key pair, returning the public handle first.
	GenerateKeyPair(session sessionHandle, mech mechanism, public, private []attribute) (objectHandle, objectHandle, error)
	// DeriveKey runs C_DeriveKey with mech and returns the derived handle. It
	// serves both CKM_ECDH1_DERIVE and CKM_HKDF_DERIVE.
	DeriveKey(session sessionHandle, mech mechanism, params mechanismParams, base objectHandle, template []attribute) (objectHandle, error)

	// Encrypt runs a single-part encryption.
	Encrypt(session sessionHandle, mech mechanism, params mechanismParams, key objectHandle, plaintext []byte) ([]byte, error)
	// Decrypt runs a single-part decryption.
	Decrypt(session sessionHandle, mech mechanism, params mechanismParams, key objectHandle, ciphertext []byte) ([]byte, error)

	// Sign runs a single-part signature. params may be nil for mechanisms that
	// take no parameter block.
	Sign(session sessionHandle, mech mechanism, params mechanismParams, key objectHandle, message []byte) ([]byte, error)
	// Verify runs a single-part verification. An invalid signature is reported
	// as an error carrying CKR_SIGNATURE_INVALID.
	Verify(session sessionHandle, mech mechanism, params mechanismParams, key objectHandle, message, signature []byte) error
}

// newModuleFn builds a module for a library path. It is a package variable so
// tests can substitute an in-memory fake, mirroring newKMSClientFn in the
// aws-kms backend.
var newModuleFn = newModule
