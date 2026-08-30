// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/internal/trace"
	"github.com/PointerByte/forge-go/encrypt/local"
	"github.com/PointerByte/forge-go/encrypt/models"
	"github.com/PointerByte/forge-go/encrypt/utilities"
)

// randReadFn is the entropy source for AES-GCM nonces and CKA_ID values. It is
// a package variable so tests can make key generation deterministic.
var randReadFn = rand.Read

type symmetricRepository struct {
	backend *backend
	local   local.SymmetricRepository
}

type asymmetricRepository struct {
	backend *backend
	local   local.AsymmetricRepository
}

type keyRepository struct {
	backend *backend
}

type hashRepository struct {
	backend *backend
	local   local.HashRepository
}

type signatureRepository struct {
	backend *backend
	local   local.SignatureRepository
}

type Repository struct {
	SymmetricRepository
	AsymmetricRepository
	KeyRepository
	SignatureRepository
	HashRepository

	backend *backend
}

func NewSymmetricRepository(opts ...Option) SymmetricRepository {
	return &symmetricRepository{backend: newBackend(opts...), local: local.NewSymmetricRepository()}
}

func NewHashRepository(opts ...Option) HashRepository {
	return &hashRepository{backend: newBackend(opts...), local: local.NewHashRepository()}
}

func NewKeyRepository(opts ...Option) KeyRepository {
	return &keyRepository{backend: newBackend(opts...)}
}

func NewAsymmetricRepository(opts ...Option) AsymmetricRepository {
	return &asymmetricRepository{backend: newBackend(opts...), local: local.NewAsymmetricRepository()}
}

func NewSignatureRepository(opts ...Option) SignatureRepository {
	return &signatureRepository{backend: newBackend(opts...), local: local.NewSignatureRepository()}
}

// NewRepository returns the composite token-backed repository. Called with no
// options it reads everything from viper, like the other backends; the PIN,
// which has no configuration key, must always come from WithPinProvider.
func NewRepository(opts ...Option) *Repository {
	shared := newBackend(opts...)
	return &Repository{
		SymmetricRepository:  &symmetricRepository{backend: shared, local: local.NewSymmetricRepository()},
		AsymmetricRepository: &asymmetricRepository{backend: shared, local: local.NewAsymmetricRepository()},
		KeyRepository:        &keyRepository{backend: shared},
		SignatureRepository:  &signatureRepository{backend: shared, local: local.NewSignatureRepository()},
		HashRepository:       &hashRepository{backend: shared, local: local.NewHashRepository()},
		backend:              shared,
	}
}

// Close releases this repository's share of the PKCS#11 library and closes its
// idle sessions.
//
// It is deliberately not part of any of the five interfaces: adding it there
// would force a no-op Close on the local and cloud backends, and
// encrypt.NewRepository erases the concrete type anyway, so a caller that needs
// it keeps its own *Repository. Close does not call C_Finalize, which tears
// down state shared by every user of the library in the process; Shutdown does
// that explicitly.
func (repository *Repository) Close() error {
	if repository.backend == nil {
		return nil
	}
	entry, err := acquireModule(repository.backend.cfg.modulePath)
	if err != nil {
		return nil
	}
	// acquireModule incremented the count, so drop that one plus our own.
	entry.refs.Add(-1)
	return entry.release()
}

// newObjectID returns a random CKA_ID for a freshly generated key.
func newObjectID() ([]byte, error) {
	id := make([]byte, 16)
	if _, err := randReadFn(id); err != nil {
		return nil, fmt.Errorf("pkcs11: generate key id: %w", err)
	}
	return id, nil
}

// newObjectLabel builds a CKA_LABEL following the "GoForge-*" convention the
// other backends use for generated keys.
func newObjectLabel(prefix, uid string) string {
	if uid != "" {
		return prefix + "-" + uid
	}
	return prefix + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

// tokenKeyTemplate is the attribute set every generated private or secret key
// carries: it lives on the token, it is sensitive, and it can never be read
// out. That non-extractability is the whole point of using an HSM.
func tokenKeyTemplate(label string, id []byte) []attribute {
	return []attribute{
		newBoolAttribute(ckaToken, true),
		newBoolAttribute(ckaPrivate, true),
		newBoolAttribute(ckaSensitive, true),
		newBoolAttribute(ckaExtractable, false),
		newBytesAttribute(ckaLabel, []byte(label)),
		newBytesAttribute(ckaID, id),
	}
}

// publicKeyTemplate is the attribute set every generated public key carries.
func publicKeyTemplate(label string, id []byte) []attribute {
	return []attribute{
		newBoolAttribute(ckaToken, true),
		newBoolAttribute(ckaPrivate, false),
		newBytesAttribute(ckaLabel, []byte(label)),
		newBytesAttribute(ckaID, id),
	}
}

func (repository *symmetricRepository) GenerateSymetrycKeys(ctx context.Context, input models.GenerateSymmetricKeyRequest) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "pkcs11/GenerateSymetrycKeys")
	defer end(err)

	valueLen, err := aesValueLen(input.Size)
	if err != nil {
		return nil, err
	}

	id, err := newObjectID()
	if err != nil {
		return nil, err
	}
	label := newObjectLabel(symmetricKeyPrefix, input.UID)

	err = repository.backend.withSession(ctx, func(mod module, slot *slotState, session sessionHandle) error {
		if err := slot.requireMechanism(ckmAESKeyGen); err != nil {
			return err
		}
		template := append(tokenKeyTemplate(label, id),
			newULongAttribute(ckaKeyType, uint64(ckkAES)),
			newULongAttribute(ckaClass, uint64(classSecretKey)),
			newULongAttribute(ckaValueLen, valueLen),
			newBoolAttribute(ckaEncrypt, true),
			newBoolAttribute(ckaDecrypt, true),
		)
		_, err := mod.GenerateKey(session, ckmAESKeyGen, template)
		return err
	})
	if err != nil {
		return nil, err
	}

	uri := &keyURI{Object: label, ID: id, Class: classSecretKey, HasClass: true}
	return keyDataFor(uri, ""), nil
}

func (repository *symmetricRepository) EncryptAES(ctx context.Context, input models.EncryptAESRequest) (out string, err error) {
	end := trace.Start(ctx, "pkcs11/EncryptAES")
	defer end(err)

	if utilities.IsLocalAESKey(input.SecretKey) {
		return repository.local.EncryptAES(ctx, input)
	}

	uri, err := repository.backend.cfg.resolveKeyURI(input.SecretKey)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcmNonceLength)
	if _, err := randReadFn(nonce); err != nil {
		return "", fmt.Errorf("pkcs11: generate nonce: %w", err)
	}

	var ciphertext []byte
	err = repository.backend.withSession(ctx, func(mod module, slot *slotState, session sessionHandle) error {
		if err := slot.requireMechanism(ckmAESGCM); err != nil {
			return err
		}
		handle, err := resolveObject(mod, session, uri, classSecretKey)
		if err != nil {
			return err
		}
		params := gcmParams{
			IV:      nonce,
			AAD:     utilities.BytesFromOptionalString(input.Additional),
			TagBits: gcmTagBits,
		}
		ciphertext, err = mod.Encrypt(session, ckmAESGCM, params, handle, []byte(input.Value))
		return err
	})
	if err != nil {
		return "", err
	}

	// nonce || ciphertext || tag, which is byte-for-byte what the local backend
	// produces, so either side can decrypt the other's output.
	return base64.StdEncoding.EncodeToString(append(nonce, ciphertext...)), nil
}

func (repository *symmetricRepository) DecryptAES(ctx context.Context, input models.DecryptAESRequest) (out string, err error) {
	end := trace.Start(ctx, "pkcs11/DecryptAES")
	defer end(err)

	if utilities.IsLocalAESKey(input.SecretKey) {
		return repository.local.DecryptAES(ctx, input)
	}

	uri, err := repository.backend.cfg.resolveKeyURI(input.SecretKey)
	if err != nil {
		return "", err
	}

	raw, err := base64.StdEncoding.DecodeString(input.CipherValue)
	if err != nil {
		return "", fmt.Errorf("pkcs11: decode base64 ciphertext: %w", err)
	}
	if len(raw) <= gcmNonceLength {
		return "", errors.New("pkcs11: ciphertext is shorter than the nonce")
	}

	var plaintext []byte
	err = repository.backend.withSession(ctx, func(mod module, slot *slotState, session sessionHandle) error {
		if err := slot.requireMechanism(ckmAESGCM); err != nil {
			return err
		}
		handle, err := resolveObject(mod, session, uri, classSecretKey)
		if err != nil {
			return err
		}
		params := gcmParams{
			IV:      raw[:gcmNonceLength],
			AAD:     utilities.BytesFromOptionalString(input.Additional),
			TagBits: gcmTagBits,
		}
		plaintext, err = mod.Decrypt(session, ckmAESGCM, params, handle, raw[gcmNonceLength:])
		return err
	})
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (repository *asymmetricRepository) GenerateRSAKeys(ctx context.Context, input models.GenerateRSAKeyRequest) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "pkcs11/GenerateRSAKeys")
	defer end(err)

	modulusBits, err := rsaModulusBits(input.Size)
	if err != nil {
		return nil, err
	}

	id, err := newObjectID()
	if err != nil {
		return nil, err
	}
	label := newObjectLabel(rsaKeyPrefix, input.UID)

	var publicKey string
	err = repository.backend.withSession(ctx, func(mod module, slot *slotState, session sessionHandle) error {
		if err := slot.requireMechanism(ckmRSAPKCSKeyPairGen); err != nil {
			return err
		}
		public := append(publicKeyTemplate(label, id),
			newULongAttribute(ckaModulusBits, modulusBits),
			// 65537, big-endian as PKCS#11 expects for CKA_PUBLIC_EXPONENT.
			newBytesAttribute(ckaPublicExpon, []byte{0x01, 0x00, 0x01}),
			newBoolAttribute(ckaEncrypt, true),
			newBoolAttribute(ckaVerify, true),
			newBoolAttribute(ckaWrap, true),
		)
		private := append(tokenKeyTemplate(label, id),
			newBoolAttribute(ckaDecrypt, true),
			newBoolAttribute(ckaSign, true),
			newBoolAttribute(ckaUnwrap, true),
		)

		publicHandle, _, err := mod.GenerateKeyPair(session, ckmRSAPKCSKeyPairGen, public, private)
		if err != nil {
			return err
		}
		attributes, err := mod.GetAttributes(session, publicHandle, []attributeType{ckaModulus, ckaPublicExpon})
		if err != nil {
			return err
		}
		publicKey, err = rsaPublicKeyFrom(attributes)
		return err
	})
	if err != nil {
		return nil, err
	}

	uri := &keyURI{Object: label, ID: id, Class: classPrivateKey, HasClass: true}
	return keyDataFor(uri, publicKey), nil
}

func (repository *asymmetricRepository) GenerateECDHCurveKeys(ctx context.Context, input models.GenerateECDHCurveKeyRequest) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "pkcs11/GenerateECDHCurveKeys")
	defer end(err)

	ecParams, err := ecParamsForCurve(input.Curve)
	if err != nil {
		return nil, err
	}

	id, err := newObjectID()
	if err != nil {
		return nil, err
	}
	label := newObjectLabel(ecdhKeyPrefix, input.UID)

	var publicKey string
	err = repository.backend.withSession(ctx, func(mod module, slot *slotState, session sessionHandle) error {
		if err := slot.requireMechanism(ckmECKeyPairGen); err != nil {
			return err
		}
		public := append(publicKeyTemplate(label, id),
			newBytesAttribute(ckaECParams, ecParams),
		)
		private := append(tokenKeyTemplate(label, id),
			newBoolAttribute(ckaDerive, true),
		)

		publicHandle, _, err := mod.GenerateKeyPair(session, ckmECKeyPairGen, public, private)
		if err != nil {
			return err
		}
		attributes, err := mod.GetAttributes(session, publicHandle, []attributeType{ckaECPoint, ckaECParams})
		if err != nil {
			return err
		}
		publicKey, err = ecdhPublicKeyFrom(attributes)
		return err
	})
	if err != nil {
		return nil, err
	}

	uri := &keyURI{Object: label, ID: id, Class: classPrivateKey, HasClass: true}
	return keyDataFor(uri, publicKey), nil
}

// fetchPublicKey reads the Base64 PKIX public key behind a token key URI,
// following the public-key then certificate chain.
func (b *backend) fetchPublicKey(ctx context.Context, uri *keyURI) (string, error) {
	var publicKey string
	err := b.withSession(ctx, func(mod module, _ *slotState, session sessionHandle) error {
		handle, class, err := publicObjectFor(mod, session, uri)
		if err != nil {
			return err
		}
		if class == classCertificate {
			attributes, err := mod.GetAttributes(session, handle, []attributeType{ckaValue})
			if err != nil {
				return err
			}
			publicKey, err = certificatePublicKey(attributes)
			return err
		}

		attributes, err := mod.GetAttributes(session, handle, []attributeType{
			ckaKeyType, ckaModulus, ckaPublicExpon, ckaECPoint, ckaECParams,
		})
		if err != nil {
			return err
		}
		publicKey, err = publicKeyFromAttributes(attributes)
		return err
	})
	return publicKey, err
}

// publicKeyFromAttributes materialises whichever key type the object holds.
func publicKeyFromAttributes(attributes []attribute) (string, error) {
	rawType, ok := findAttribute(attributes, ckaKeyType)
	if !ok {
		return "", fmt.Errorf("pkcs11: object has no CKA_KEY_TYPE")
	}
	decoded, ok := uLongValue(rawType)
	if !ok {
		return "", fmt.Errorf("pkcs11: CKA_KEY_TYPE is not a CK_ULONG")
	}

	switch keyType(decoded) {
	case ckkRSA:
		return rsaPublicKeyFrom(attributes)
	case ckkEC:
		return ecdhPublicKeyFrom(attributes)
	case ckkECEdwards:
		return ed25519PublicKeyFrom(attributes)
	default:
		return "", fmt.Errorf("pkcs11: unsupported key type %d", decoded)
	}
}

func (repository *asymmetricRepository) RSA_OAEP_Encode(ctx context.Context, input models.RSAOAEPEncodeRequest) (out string, err error) {
	end := trace.Start(ctx, "pkcs11/RSA_OAEP_Encode")
	defer end(err)

	if _, err := utilities.ParseRSAPublicKeyFromBase64(input.PublicKey); err == nil {
		return repository.local.RSA_OAEP_Encode(ctx, input)
	}

	uri, err := repository.backend.cfg.resolveKeyURI(input.PublicKey)
	if err != nil {
		return "", err
	}

	// Encrypting with a public key needs no secret, so the token is only asked
	// for the public half and the operation finishes locally. That keeps the
	// output format identical to the other backends and avoids
	// CK_RSA_PKCS_OAEP_PARAMS, which several tokens reject.
	publicKey, err := repository.backend.fetchPublicKey(ctx, uri)
	if err != nil {
		return "", err
	}
	return repository.local.RSA_OAEP_Encode(ctx, models.RSAOAEPEncodeRequest{
		UID:       input.UID,
		PublicKey: publicKey,
		Text:      input.Text,
	})
}

func (repository *asymmetricRepository) RSA_OAEP_Decode(ctx context.Context, input models.RSAOAEPDecodeRequest) (out string, err error) {
	end := trace.Start(ctx, "pkcs11/RSA_OAEP_Decode")
	defer end(err)

	if _, err := utilities.ParseRSAPrivateKeyFromBase64(input.PrivateKey); err == nil {
		return repository.local.RSA_OAEP_Decode(ctx, input)
	}

	uri, err := repository.backend.cfg.resolveKeyURI(input.PrivateKey)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(input.CipherText)
	if err != nil {
		return "", fmt.Errorf("pkcs11: decode base64 ciphertext: %w", err)
	}

	var plaintext []byte
	err = repository.backend.withSession(ctx, func(mod module, slot *slotState, session sessionHandle) error {
		if err := slot.requireMechanism(ckmRSAPKCSOAEP); err != nil {
			return err
		}
		handle, err := resolveObject(mod, session, uri, classPrivateKey)
		if err != nil {
			return err
		}
		// Source is CKZ_DATA_SPECIFIED even though the label is empty: a zero
		// source makes strict tokens reject C_DecryptInit outright.
		params := oaepParams{HashAlg: ckmSHA256, MGF: ckgMGF1SHA256, Source: ckzDataSpecified}
		plaintext, err = mod.Decrypt(session, ckmRSAPKCSOAEP, params, handle, ciphertext)
		if err != nil && isMechanismParamError(err) {
			// The token advertises CKM_RSA_PKCS_OAEP but refuses the digest,
			// which C_GetMechanismList cannot express. Say so plainly instead
			// of surfacing a bare CKR_ARGUMENTS_BAD.
			return fmt.Errorf("%w: %w", ErrOAEPHashUnsupported, err)
		}
		return err
	})
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (repository *asymmetricRepository) ECDH_Encode(ctx context.Context, input models.ECDHEncodeRequest) (out string, err error) {
	end := trace.Start(ctx, "pkcs11/ECDH_Encode")
	defer end(err)

	if _, err := utilities.ParseECDHPublicKeyFromBase64(input.PublicKey); err == nil {
		return repository.local.ECDH_Encode(ctx, input)
	}

	uri, err := repository.backend.cfg.resolveKeyURI(input.PublicKey)
	if err != nil {
		return "", err
	}

	publicKey, err := repository.backend.fetchPublicKey(ctx, uri)
	if err != nil {
		return "", err
	}
	return repository.local.ECDH_Encode(ctx, models.ECDHEncodeRequest{
		UID:       input.UID,
		PublicKey: publicKey,
		Text:      input.Text,
	})
}

// ECDH_Decode decrypts a payload produced by ECDH_Encode.
//
// The payload format is shared with the local and cloud backends: the AES key
// is HKDF-SHA256 over the raw shared secret with a nil salt and the curve label
// as info. Reproducing it on a token takes one of two paths.
//
// When the token implements CKM_HKDF_DERIVE (PKCS#11 v3.0), both the shared
// secret and the AES key stay inside the hardware: ECDH1 derives a generic
// secret, HKDF derives the AES key from it, and AES-GCM decrypts with that
// handle. HKDF-Extract with a null salt is exactly RFC 5869 with a nil salt, so
// the key matches the one the local backend computes in software.
//
// Otherwise the shared secret is read out and the derivation finishes locally,
// which is what the aws-kms and azure-key-vault backends already do. What
// leaves the token there is an ephemeral per-message secret, never long-term
// key material, but a token whose policy forbids it fails instead — the payload
// format is never silently changed.
func (repository *asymmetricRepository) ECDH_Decode(ctx context.Context, input models.ECDHDecodeRequest) (out string, err error) {
	end := trace.Start(ctx, "pkcs11/ECDH_Decode")
	defer end(err)

	if _, err := utilities.ParseECDHPrivateKeyFromBase64(input.PrivateKey); err == nil {
		return repository.local.ECDH_Decode(ctx, input)
	}

	uri, err := repository.backend.cfg.resolveKeyURI(input.PrivateKey)
	if err != nil {
		return "", err
	}

	payload, err := utilities.DecodeECCCipherPayload(input.CipherText)
	if err != nil {
		return "", err
	}
	peerPoint, err := ecdhPeerPoint(payload.EphemeralPublicKey)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("pkcs11: decode base64 ciphertext: %w", err)
	}
	if len(raw) <= gcmNonceLength {
		return "", errors.New("pkcs11: ciphertext is shorter than the nonce")
	}

	info := []byte(eccHKDFInfoPrefix + payload.Curve)

	var plaintext []byte
	var sharedSecret []byte
	err = repository.backend.withSession(ctx, func(mod module, slot *slotState, session sessionHandle) error {
		if err := slot.requireMechanism(ckmECDH1Derive); err != nil {
			return err
		}
		private, err := resolveObject(mod, session, uri, classPrivateKey)
		if err != nil {
			return err
		}

		if supportsInHardwareECDH(slot) {
			plaintext, err = decryptECDHInHardware(mod, session, private, peerPoint, info, payload.Curve, raw)
			if err == nil {
				return nil
			}
			// The mechanism list is optimistic on some tokens; fall through to
			// extraction only when extraction is permitted.
			if !repository.backend.cfg.allowSecretExtraction {
				return err
			}
		}

		if !repository.backend.cfg.allowSecretExtraction {
			return fmt.Errorf("%w: token lacks CKM_HKDF_DERIVE and extraction is disabled", ErrSecretNotExtractable)
		}
		sharedSecret, err = deriveExtractableSecret(mod, session, private, peerPoint)
		return err
	})
	if err != nil {
		return "", err
	}
	if plaintext != nil {
		return string(plaintext), nil
	}

	derivedKey, err := utilities.DeriveECCAESKey(sharedSecret, payload.Curve)
	if err != nil {
		return "", err
	}
	additional := payload.Curve
	return local.NewSymmetricRepository().DecryptAES(ctx, models.DecryptAESRequest{
		UID:         input.UID,
		SecretKey:   base64.StdEncoding.EncodeToString(derivedKey),
		CipherValue: payload.Ciphertext,
		Additional:  &additional,
	})
}

// decryptECDHInHardware runs the whole ECDH decrypt inside the token, so no
// derived material ever crosses the boundary.
func decryptECDHInHardware(mod module, session sessionHandle, private objectHandle, peerPoint, info []byte, curve string, raw []byte) ([]byte, error) {
	secretHandle, err := mod.DeriveKey(session, ckmECDH1Derive,
		ecdh1Params{KDF: ckdNULL, PublicData: peerPoint}, private,
		[]attribute{
			newULongAttribute(ckaClass, uint64(classSecretKey)),
			newULongAttribute(ckaKeyType, uint64(ckkGenericSecret)),
			newBoolAttribute(ckaToken, false),
			newBoolAttribute(ckaSensitive, true),
			newBoolAttribute(ckaExtractable, false),
			newBoolAttribute(ckaDerive, true),
		})
	if err != nil {
		return nil, err
	}
	defer func() { _ = mod.DestroyObject(session, secretHandle) }()

	aesHandle, err := mod.DeriveKey(session, ckmHKDFDerive,
		hkdfParams{
			Extract:  true,
			Expand:   true,
			PRF:      ckmSHA256,
			SaltType: ckfHKDFSaltNull,
			Info:     info,
		}, secretHandle,
		[]attribute{
			newULongAttribute(ckaClass, uint64(classSecretKey)),
			newULongAttribute(ckaKeyType, uint64(ckkAES)),
			newULongAttribute(ckaValueLen, uint64(common.Key256Bits)),
			newBoolAttribute(ckaToken, false),
			newBoolAttribute(ckaSensitive, true),
			newBoolAttribute(ckaExtractable, false),
			newBoolAttribute(ckaDecrypt, true),
		})
	if err != nil {
		return nil, err
	}
	defer func() { _ = mod.DestroyObject(session, aesHandle) }()

	return mod.Decrypt(session, ckmAESGCM, gcmParams{
		IV:      raw[:gcmNonceLength],
		AAD:     []byte(curve),
		TagBits: gcmTagBits,
	}, aesHandle, raw[gcmNonceLength:])
}

// deriveExtractableSecret derives the raw ECDH shared secret and reads it out.
func deriveExtractableSecret(mod module, session sessionHandle, private objectHandle, peerPoint []byte) ([]byte, error) {
	handle, err := mod.DeriveKey(session, ckmECDH1Derive,
		ecdh1Params{KDF: ckdNULL, PublicData: peerPoint}, private,
		[]attribute{
			newULongAttribute(ckaClass, uint64(classSecretKey)),
			newULongAttribute(ckaKeyType, uint64(ckkGenericSecret)),
			newBoolAttribute(ckaToken, false),
			newBoolAttribute(ckaSensitive, false),
			newBoolAttribute(ckaExtractable, true),
		})
	if err != nil {
		return nil, err
	}
	defer func() { _ = mod.DestroyObject(session, handle) }()

	attributes, err := mod.GetAttributes(session, handle, []attributeType{ckaValue})
	if err != nil {
		return nil, err
	}
	secret, ok := findAttribute(attributes, ckaValue)
	if !ok || len(secret) == 0 {
		return nil, ErrSecretNotExtractable
	}
	return secret, nil
}

// ecdhPeerPoint extracts the bare SEC1 point from the Base64 PKIX ephemeral
// public key in the payload. C_DeriveKey wants the bare point, which is the
// opposite convention to CKA_EC_POINT.
func ecdhPeerPoint(encoded string) ([]byte, error) {
	publicKey, err := utilities.ParseECDHPublicKeyFromBase64(encoded)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: parse ephemeral public key: %w", err)
	}
	return publicKey.Bytes(), nil
}

// RotateKey generates a replacement key and returns its reference.
//
// PKCS#11 has no native rotation, so this synthesises it: the descriptor of the
// existing object is read, an equivalent key is generated with a fresh CKA_ID,
// and the new reference is returned. The KeyRef therefore changes, and the
// previous key is left usable so existing ciphertext stays decryptable, unless
// WithRotateDisablesPrevious was set.
func (repository *keyRepository) RotateKey(ctx context.Context, input models.RotateKeyRequest) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "pkcs11/RotateKey")
	defer end(err)

	uri, err := repository.backend.cfg.resolveKeyURI(input.KeyID)
	if err != nil {
		return nil, err
	}

	id, err := newObjectID()
	if err != nil {
		return nil, err
	}

	var rotated *models.KeyData
	err = repository.backend.withSession(ctx, func(mod module, slot *slotState, session sessionHandle) error {
		handle, err := resolveObject(mod, session, uri, classPrivateKey)
		if err != nil {
			return err
		}
		attributes, err := mod.GetAttributes(session, handle, []attributeType{
			ckaClass, ckaKeyType, ckaLabel, ckaValueLen, ckaModulusBits, ckaECParams,
		})
		if err != nil {
			return err
		}

		label := newObjectLabel(rotationLabelBase(attributes, uri), input.UID)
		rotated, err = generateReplacement(mod, slot, session, attributes, label, id)
		if err != nil {
			return err
		}

		if repository.backend.cfg.rotateDisablesPrev {
			if err := disableObject(mod, session, handle); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rotated, nil
}

// rotationLabelBase strips a previously appended rotation suffix so repeated
// rotations do not accumulate timestamps.
func rotationLabelBase(attributes []attribute, uri *keyURI) string {
	label := uri.Object
	if raw, ok := findAttribute(attributes, ckaLabel); ok && len(raw) > 0 {
		label = string(raw)
	}
	for _, prefix := range []string{symmetricKeyPrefix, rsaKeyPrefix, ecdhKeyPrefix, ed25519KeyPrefix, hmacKeyPrefix} {
		if len(label) >= len(prefix) && label[:len(prefix)] == prefix {
			return prefix
		}
	}
	return label
}

// generateReplacement creates a key equivalent to the described object.
func generateReplacement(mod module, slot *slotState, session sessionHandle, attributes []attribute, label string, id []byte) (*models.KeyData, error) {
	rawType, ok := findAttribute(attributes, ckaKeyType)
	if !ok {
		return nil, fmt.Errorf("pkcs11: cannot rotate an object without CKA_KEY_TYPE")
	}
	decoded, ok := uLongValue(rawType)
	if !ok {
		return nil, fmt.Errorf("pkcs11: CKA_KEY_TYPE is not a CK_ULONG")
	}

	switch keyType(decoded) {
	case ckkAES:
		valueLen := uint64(common.Key256Bits)
		if raw, ok := findAttribute(attributes, ckaValueLen); ok {
			if parsed, ok := uLongValue(raw); ok && parsed > 0 {
				valueLen = parsed
			}
		}
		if err := slot.requireMechanism(ckmAESKeyGen); err != nil {
			return nil, err
		}
		template := append(tokenKeyTemplate(label, id),
			newULongAttribute(ckaKeyType, uint64(ckkAES)),
			newULongAttribute(ckaClass, uint64(classSecretKey)),
			newULongAttribute(ckaValueLen, valueLen),
			newBoolAttribute(ckaEncrypt, true),
			newBoolAttribute(ckaDecrypt, true),
		)
		if _, err := mod.GenerateKey(session, ckmAESKeyGen, template); err != nil {
			return nil, err
		}
		return keyDataFor(&keyURI{Object: label, ID: id, Class: classSecretKey, HasClass: true}, ""), nil

	case ckkRSA:
		modulusBits := uint64(common.Key2048Bits)
		if raw, ok := findAttribute(attributes, ckaModulusBits); ok {
			if parsed, ok := uLongValue(raw); ok && parsed > 0 {
				modulusBits = parsed
			}
		}
		if err := slot.requireMechanism(ckmRSAPKCSKeyPairGen); err != nil {
			return nil, err
		}
		public := append(publicKeyTemplate(label, id),
			newULongAttribute(ckaModulusBits, modulusBits),
			newBytesAttribute(ckaPublicExpon, []byte{0x01, 0x00, 0x01}),
			newBoolAttribute(ckaEncrypt, true),
			newBoolAttribute(ckaVerify, true),
		)
		private := append(tokenKeyTemplate(label, id),
			newBoolAttribute(ckaDecrypt, true),
			newBoolAttribute(ckaSign, true),
		)
		publicHandle, _, err := mod.GenerateKeyPair(session, ckmRSAPKCSKeyPairGen, public, private)
		if err != nil {
			return nil, err
		}
		fresh, err := mod.GetAttributes(session, publicHandle, []attributeType{ckaModulus, ckaPublicExpon})
		if err != nil {
			return nil, err
		}
		publicKey, err := rsaPublicKeyFrom(fresh)
		if err != nil {
			return nil, err
		}
		return keyDataFor(&keyURI{Object: label, ID: id, Class: classPrivateKey, HasClass: true}, publicKey), nil

	case ckkEC, ckkECEdwards:
		ecParams, ok := findAttribute(attributes, ckaECParams)
		if !ok {
			return nil, fmt.Errorf("pkcs11: cannot rotate an ec key without CKA_EC_PARAMS")
		}
		mech := ckmECKeyPairGen
		if keyType(decoded) == ckkECEdwards {
			mech = ckmECEdwardsKeyPairGe
		}
		if err := slot.requireMechanism(mech); err != nil {
			return nil, err
		}
		public := append(publicKeyTemplate(label, id), newBytesAttribute(ckaECParams, ecParams))
		private := append(tokenKeyTemplate(label, id),
			newBoolAttribute(ckaDerive, keyType(decoded) == ckkEC),
			newBoolAttribute(ckaSign, keyType(decoded) == ckkECEdwards),
		)
		publicHandle, _, err := mod.GenerateKeyPair(session, mech, public, private)
		if err != nil {
			return nil, err
		}
		fresh, err := mod.GetAttributes(session, publicHandle, []attributeType{ckaECPoint, ckaECParams})
		if err != nil {
			return nil, err
		}
		var publicKey string
		if keyType(decoded) == ckkECEdwards {
			publicKey, err = ed25519PublicKeyFrom(fresh)
		} else {
			publicKey, err = ecdhPublicKeyFrom(fresh)
		}
		if err != nil {
			return nil, err
		}
		return keyDataFor(&keyURI{Object: label, ID: id, Class: classPrivateKey, HasClass: true}, publicKey), nil

	default:
		return nil, fmt.Errorf("pkcs11: cannot rotate key type %d", decoded)
	}
}

func (repository *keyRepository) GetKey(ctx context.Context, input models.GetKeyRequest) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "pkcs11/GetKey")
	defer end(err)

	uri, err := repository.backend.cfg.resolveKeyURI(input.KeyID)
	if err != nil {
		return nil, err
	}

	resolved := &keyURI{Token: uri.Token, Object: uri.Object, ID: uri.ID, Class: uri.Class, HasClass: uri.HasClass}
	var publicKey string
	err = repository.backend.withSession(ctx, func(mod module, _ *slotState, session sessionHandle) error {
		handle, err := resolveObject(mod, session, uri, classPrivateKey)
		if err != nil {
			return err
		}
		attributes, err := mod.GetAttributes(session, handle, []attributeType{ckaLabel, ckaID, ckaClass})
		if err != nil {
			return err
		}
		if raw, ok := findAttribute(attributes, ckaLabel); ok && len(raw) > 0 {
			resolved.Object = string(raw)
		}
		if raw, ok := findAttribute(attributes, ckaID); ok && len(raw) > 0 {
			resolved.ID = raw
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// A key with no exportable public half (a bare AES key) is not an error;
	// the reference alone is what the caller needs.
	if fetched, fetchErr := repository.backend.fetchPublicKey(ctx, resolved); fetchErr == nil {
		publicKey = fetched
	}
	return keyDataFor(resolved, publicKey), nil
}

// deactivatableAttributes are the usage flags DeactivateKey clears.
var deactivatableAttributes = []attributeType{
	ckaEncrypt, ckaDecrypt, ckaSign, ckaVerify, ckaWrap, ckaUnwrap, ckaDerive,
}

// DeactivateKey clears the usage attributes of a token key.
//
// Unlike the cloud backends, this is effectively irreversible: PKCS#11 usage
// attributes are one-way on the great majority of tokens, so a key disabled
// here generally cannot be re-enabled. Tokens that refuse the write return an
// error rather than losing the key, unless WithDeactivateDestroys was set.
func (repository *keyRepository) DeactivateKey(ctx context.Context, input models.DeactivateKeyRequest) (err error) {
	end := trace.Start(ctx, "pkcs11/DeactivateKey")
	defer end(err)

	uri, err := repository.backend.cfg.resolveKeyURI(input.KeyID)
	if err != nil {
		return err
	}

	return repository.backend.withSession(ctx, func(mod module, _ *slotState, session sessionHandle) error {
		handle, err := resolveObject(mod, session, uri, classPrivateKey)
		if err != nil {
			return err
		}
		if err := disableObject(mod, session, handle); err == nil {
			return nil
		} else if !repository.backend.cfg.deactivateDestroys {
			return err
		}
		return mod.DestroyObject(session, handle)
	})
}

// disableObject clears every usage attribute the object actually carries.
//
// The probe is not optional: C_SetAttributeValue rejects the whole template
// with CKR_ATTRIBUTE_TYPE_INVALID if it names one attribute the object does not
// have, so sending the full set blindly fails on almost every real key.
func disableObject(mod module, session sessionHandle, handle objectHandle) error {
	present, err := mod.GetAttributes(session, handle, deactivatableAttributes)
	if err != nil {
		return err
	}

	template := make([]attribute, 0, len(deactivatableAttributes))
	for _, kind := range deactivatableAttributes {
		if hasAttribute(present, kind) {
			template = append(template, newBoolAttribute(kind, false))
		}
	}
	if len(template) == 0 {
		return fmt.Errorf("pkcs11: object carries no usage attribute to clear")
	}
	return mod.SetAttributes(session, handle, template)
}

func (repository *hashRepository) HMAC(ctx context.Context, secretKey, message string) string {
	defer trace.Start(ctx, "pkcs11/HMAC")(nil)

	if !isKeyURI(secretKey) {
		return repository.local.HMAC(ctx, secretKey, message)
	}

	uri, err := repository.backend.cfg.resolveKeyURI(secretKey)
	if err != nil {
		return ""
	}

	var signature []byte
	err = repository.backend.withSession(ctx, func(mod module, slot *slotState, session sessionHandle) error {
		if err := slot.requireMechanism(ckmSHA256HMAC); err != nil {
			return err
		}
		handle, err := resolveObject(mod, session, uri, classSecretKey)
		if err != nil {
			return err
		}
		signature, err = mod.Sign(session, ckmSHA256HMAC, nil, handle, []byte(message))
		return err
	})
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(signature)
}

func (repository *hashRepository) Sha256Hex(ctx context.Context, message string) string {
	defer trace.Start(ctx, "pkcs11/Sha256Hex")(nil)
	// Digesting public data on the token buys nothing and costs a round trip.
	return repository.local.Sha256Hex(ctx, message)
}

func (repository *hashRepository) Blake3(ctx context.Context, message string) string {
	defer trace.Start(ctx, "pkcs11/Blake3")(nil)
	// PKCS#11 has no BLAKE3 mechanism.
	return repository.local.Blake3(ctx, message)
}

func (repository *signatureRepository) GenerateEd255Keys(ctx context.Context) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "pkcs11/GenerateEd255Keys")
	defer end(err)

	ecParams, err := ecParamsForEd25519()
	if err != nil {
		return nil, err
	}

	id, err := newObjectID()
	if err != nil {
		return nil, err
	}
	label := newObjectLabel(ed25519KeyPrefix, "")

	var publicKey string
	err = repository.backend.withSession(ctx, func(mod module, slot *slotState, session sessionHandle) error {
		if err := slot.requireMechanism(ckmECEdwardsKeyPairGe); err != nil {
			return err
		}
		public := append(publicKeyTemplate(label, id),
			newBytesAttribute(ckaECParams, ecParams),
			newBoolAttribute(ckaVerify, true),
		)
		private := append(tokenKeyTemplate(label, id),
			newBoolAttribute(ckaSign, true),
		)

		publicHandle, _, err := mod.GenerateKeyPair(session, ckmECEdwardsKeyPairGe, public, private)
		if err != nil {
			return err
		}
		attributes, err := mod.GetAttributes(session, publicHandle, []attributeType{ckaECPoint})
		if err != nil {
			return err
		}
		publicKey, err = ed25519PublicKeyFrom(attributes)
		return err
	})
	if err != nil {
		return nil, err
	}

	uri := &keyURI{Object: label, ID: id, Class: classPrivateKey, HasClass: true}
	return keyDataFor(uri, publicKey), nil
}

// signWithToken resolves a private key on the token and signs with the plan the
// slot's mechanism list allows.
func (repository *signatureRepository) signWithToken(ctx context.Context, reference, message string, plan func(*slotState) (signPlan, error)) (string, error) {
	uri, err := repository.backend.cfg.resolveKeyURI(reference)
	if err != nil {
		return "", err
	}

	var signature []byte
	err = repository.backend.withSession(ctx, func(mod module, slot *slotState, session sessionHandle) error {
		chosen, err := plan(slot)
		if err != nil {
			return err
		}
		handle, err := resolveObject(mod, session, uri, classPrivateKey)
		if err != nil {
			return err
		}
		payload := chosen.prepare([]byte(message))
		signature, err = mod.Sign(session, chosen.mechanism, chosen.params, handle, payload)
		if err != nil && chosen.retryParams != nil && isMechanismParamError(err) {
			signature, err = mod.Sign(session, chosen.mechanism, chosen.retryParams, handle, payload)
		}
		return err
	})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (repository *signatureRepository) SignEd25519(ctx context.Context, privateKey, text string) (out string, err error) {
	end := trace.Start(ctx, "pkcs11/SignEd25519")
	defer end(err)

	if _, err := utilities.ParseEd25519PrivateKeyFromBase64(privateKey); err == nil {
		return repository.local.SignEd25519(ctx, privateKey, text)
	}
	return repository.signWithToken(ctx, privateKey, text, planEd25519)
}

// VerifyEd25519 verifies locally after fetching the token public key.
//
// Verification needs no secret, so completing it in software saves a round trip
// and removes CKM_EDDSA verification from the set of mechanisms a token must
// support. The gcp-kms backend documents the same reasoning.
func (repository *signatureRepository) VerifyEd25519(ctx context.Context, publicKey, text, signature string) (err error) {
	end := trace.Start(ctx, "pkcs11/VerifyEd25519")
	defer end(err)

	if _, err := utilities.ParseEd25519PublicKeyFromBase64(publicKey); err == nil {
		return repository.local.VerifyEd25519(ctx, publicKey, text, signature)
	}

	uri, err := repository.backend.cfg.resolveKeyURI(publicKey)
	if err != nil {
		return err
	}
	fetched, err := repository.backend.fetchPublicKey(ctx, uri)
	if err != nil {
		return err
	}
	return repository.local.VerifyEd25519(ctx, fetched, text, signature)
}

func (repository *signatureRepository) SignRSAPSS(ctx context.Context, privateKey, text string) (out string, err error) {
	end := trace.Start(ctx, "pkcs11/SignRSAPSS")
	defer end(err)

	if _, err := utilities.ParseRSAPrivateKeyFromBase64(privateKey); err == nil {
		return repository.local.SignRSAPSS(ctx, privateKey, text)
	}
	return repository.signWithToken(ctx, privateKey, text, planRSAPSS)
}

// VerifyRSAPSS verifies locally after fetching the token public key.
//
// The salt length is auto-detected, which matters here: this backend signs with
// a salt equal to the digest size while the local backend uses the maximum
// salt, and PSSSaltLengthAuto accepts both.
func (repository *signatureRepository) VerifyRSAPSS(ctx context.Context, publicKey, text, signature string) (err error) {
	end := trace.Start(ctx, "pkcs11/VerifyRSAPSS")
	defer end(err)

	if _, err := utilities.ParseRSAPublicKeyFromBase64(publicKey); err == nil {
		return repository.local.VerifyRSAPSS(ctx, publicKey, text, signature)
	}

	fetched, err := repository.fetchVerificationKey(ctx, publicKey)
	if err != nil {
		return err
	}
	return repository.local.VerifyRSAPSS(ctx, fetched, text, signature)
}

func (repository *signatureRepository) Sign_RSA_PKCS1v15_SHA256(ctx context.Context, privateKey, data string) (out string, err error) {
	end := trace.Start(ctx, "pkcs11/Sign_RSA_PKCS1v15_SHA256")
	defer end(err)

	if privateKey != "" && !isKeyURI(privateKey) {
		return repository.local.Sign_RSA_PKCS1v15_SHA256(ctx, privateKey, data)
	}
	return repository.signWithToken(ctx, privateKey, data, planRSAPKCS1v15)
}

func (repository *signatureRepository) Verify_RSA_PKCS1v15_SHA256(ctx context.Context, data, publicKey string, signature string) (err error) {
	end := trace.Start(ctx, "pkcs11/Verify_RSA_PKCS1v15_SHA256")
	defer end(err)

	if publicKey != "" && !isKeyURI(publicKey) {
		return repository.local.Verify_RSA_PKCS1v15_SHA256(ctx, data, publicKey, signature)
	}

	fetched, err := repository.fetchVerificationKey(ctx, publicKey)
	if err != nil {
		return err
	}
	return repository.local.Verify_RSA_PKCS1v15_SHA256(ctx, data, fetched, signature)
}

// isMechanismParamError reports whether the token rejected the parameter block
// rather than the operation, which is the signal to retry with the alternative
// form.
func isMechanismParamError(err error) bool {
	var tokenErr tokenError
	if !errors.As(err, &tokenErr) {
		return false
	}
	return tokenErr.code == ckrMechanismParamInval || tokenErr.code == ckrArgumentsBad
}

// fetchVerificationKey resolves a token reference to a Base64 public key.
func (repository *signatureRepository) fetchVerificationKey(ctx context.Context, reference string) (string, error) {
	uri, err := repository.backend.cfg.resolveKeyURI(reference)
	if err != nil {
		return "", err
	}
	return repository.backend.fetchPublicKey(ctx, uri)
}
