// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"

	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/models"
)

func TestRotateKeySymmetric(t *testing.T) {
	var generated []attribute
	fake := &fakeModule{
		getAttributesFn: func(_ sessionHandle, _ objectHandle, types []attributeType) ([]attribute, error) {
			all := map[attributeType]attribute{
				ckaClass:    newULongAttribute(ckaClass, uint64(classSecretKey)),
				ckaKeyType:  newULongAttribute(ckaKeyType, uint64(ckkAES)),
				ckaLabel:    newBytesAttribute(ckaLabel, []byte(symmetricKeyPrefix+"-1700000000")),
				ckaValueLen: newULongAttribute(ckaValueLen, 32),
			}
			return selectAttributes(all, types), nil
		},
		generateKeyFn: func(_ sessionHandle, _ mechanism, template []attribute) (objectHandle, error) {
			generated = template
			return 9, nil
		},
	}
	installFake(t, fake)

	repository := NewKeyRepository(testOptions()...)
	data, err := repository.RotateKey(context.Background(), models.RotateKeyRequest{
		KeyID: "pkcs11:object=" + symmetricKeyPrefix + "-1700000000;type=secret-key",
	})
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}

	// Rotation creates a new object, so the reference must change.
	if strings.Contains(data.KeyRef, "1700000000") {
		t.Fatalf("KeyRef = %q, want a fresh reference", data.KeyRef)
	}
	if data.Provider != providerName {
		t.Fatalf("Provider = %q", data.Provider)
	}

	// The replacement must preserve the original key size.
	valueLen, ok := findAttribute(generated, ckaValueLen)
	if !ok {
		t.Fatal("the replacement template has no CKA_VALUE_LEN")
	}
	decoded, _ := uLongValue(valueLen)
	if decoded != 32 {
		t.Fatalf("CKA_VALUE_LEN = %d, want the original 32", decoded)
	}
	assertBoolAttribute(t, generated, ckaExtractable, false)
}

func TestRotateKeyRSAPreservesModulusSize(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	var publicTemplate []attribute
	fake := &fakeModule{
		getAttributesFn: func(_ sessionHandle, _ objectHandle, types []attributeType) ([]attribute, error) {
			all := map[attributeType]attribute{
				ckaClass:       newULongAttribute(ckaClass, uint64(classPrivateKey)),
				ckaKeyType:     newULongAttribute(ckaKeyType, uint64(ckkRSA)),
				ckaLabel:       newBytesAttribute(ckaLabel, []byte(rsaKeyPrefix+"-old")),
				ckaModulusBits: newULongAttribute(ckaModulusBits, 3072),
				ckaModulus:     newBytesAttribute(ckaModulus, key.N.Bytes()),
				ckaPublicExpon: newBytesAttribute(ckaPublicExpon, []byte{0x01, 0x00, 0x01}),
			}
			return selectAttributes(all, types), nil
		},
		generateKeyPairFn: func(_ sessionHandle, _ mechanism, public, _ []attribute) (objectHandle, objectHandle, error) {
			publicTemplate = public
			return 1, 2, nil
		},
	}
	installFake(t, fake)

	repository := NewKeyRepository(testOptions()...)
	data, err := repository.RotateKey(context.Background(), models.RotateKeyRequest{
		KeyID: "pkcs11:object=" + rsaKeyPrefix + "-old;type=private",
	})
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	if data.PublicKey == "" {
		t.Fatal("RotateKey() must return the new public key")
	}

	bits, _ := findAttribute(publicTemplate, ckaModulusBits)
	decoded, _ := uLongValue(bits)
	if decoded != 3072 {
		t.Fatalf("CKA_MODULUS_BITS = %d, want the original 3072", decoded)
	}
}

func TestRotateKeyEC(t *testing.T) {
	params, _ := asn1.Marshal(oidP256)
	private, err := ecdhKeyFixture(t)
	if err != nil {
		t.Fatalf("fixture error = %v", err)
	}

	fake := &fakeModule{
		getAttributesFn: func(_ sessionHandle, _ objectHandle, types []attributeType) ([]attribute, error) {
			all := map[attributeType]attribute{
				ckaClass:    newULongAttribute(ckaClass, uint64(classPrivateKey)),
				ckaKeyType:  newULongAttribute(ckaKeyType, uint64(ckkEC)),
				ckaLabel:    newBytesAttribute(ckaLabel, []byte(ecdhKeyPrefix+"-old")),
				ckaECParams: newBytesAttribute(ckaECParams, params),
				ckaECPoint:  newBytesAttribute(ckaECPoint, private),
			}
			return selectAttributes(all, types), nil
		},
	}
	installFake(t, fake)

	repository := NewKeyRepository(testOptions()...)
	data, err := repository.RotateKey(context.Background(), models.RotateKeyRequest{
		KeyID: "pkcs11:object=" + ecdhKeyPrefix + "-old;type=private",
	})
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	if data.PublicKey == "" {
		t.Fatal("RotateKey() must return the new public key")
	}
}

func ecdhKeyFixture(t *testing.T) ([]byte, error) {
	t.Helper()
	fixture := newECDHFixture(t)
	return fixture.private.PublicKey().Bytes(), nil
}

func TestRotateKeyDisablesPreviousWhenAsked(t *testing.T) {
	var disabled bool
	fake := &fakeModule{
		getAttributesFn: func(_ sessionHandle, _ objectHandle, types []attributeType) ([]attribute, error) {
			all := map[attributeType]attribute{
				ckaKeyType:  newULongAttribute(ckaKeyType, uint64(ckkAES)),
				ckaLabel:    newBytesAttribute(ckaLabel, []byte(symmetricKeyPrefix)),
				ckaValueLen: newULongAttribute(ckaValueLen, 32),
				ckaEncrypt:  newBoolAttribute(ckaEncrypt, true),
				ckaDecrypt:  newBoolAttribute(ckaDecrypt, true),
			}
			return selectAttributes(all, types), nil
		},
		setAttributesFn: func(sessionHandle, objectHandle, []attribute) error {
			disabled = true
			return nil
		},
	}
	installFake(t, fake)

	repository := NewKeyRepository(testOptions(WithRotateDisablesPrevious(true))...)
	if _, err := repository.RotateKey(context.Background(), models.RotateKeyRequest{
		KeyID: "pkcs11:object=" + symmetricKeyPrefix + ";type=secret-key",
	}); err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	if !disabled {
		t.Fatal("WithRotateDisablesPrevious was set but the old key was not disabled")
	}
}

// TestRotateKeyLeavesPreviousUsableByDefault pins the default: old ciphertext
// must stay decryptable after a rotation.
func TestRotateKeyLeavesPreviousUsableByDefault(t *testing.T) {
	var disabled bool
	fake := &fakeModule{
		getAttributesFn: func(_ sessionHandle, _ objectHandle, types []attributeType) ([]attribute, error) {
			all := map[attributeType]attribute{
				ckaKeyType:  newULongAttribute(ckaKeyType, uint64(ckkAES)),
				ckaValueLen: newULongAttribute(ckaValueLen, 32),
			}
			return selectAttributes(all, types), nil
		},
		setAttributesFn: func(sessionHandle, objectHandle, []attribute) error {
			disabled = true
			return nil
		},
	}
	installFake(t, fake)

	repository := NewKeyRepository(testOptions()...)
	if _, err := repository.RotateKey(context.Background(), models.RotateKeyRequest{
		KeyID: "pkcs11:object=k;type=secret-key",
	}); err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	if disabled {
		t.Fatal("rotation must be non-destructive by default")
	}
}

func TestRotateKeyRejectsUnrotatableObjects(t *testing.T) {
	tests := []struct {
		name       string
		attributes map[attributeType]attribute
	}{
		{name: "no key type", attributes: map[attributeType]attribute{}},
		{name: "key type not a ulong", attributes: map[attributeType]attribute{
			ckaKeyType: {Type: ckaKeyType, Value: []byte{1}, Present: true},
		}},
		{name: "unsupported key type", attributes: map[attributeType]attribute{
			ckaKeyType: newULongAttribute(ckaKeyType, 0xbeef),
		}},
		{name: "ec without params", attributes: map[attributeType]attribute{
			ckaKeyType: newULongAttribute(ckaKeyType, uint64(ckkEC)),
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			installFake(t, &fakeModule{
				getAttributesFn: func(_ sessionHandle, _ objectHandle, types []attributeType) ([]attribute, error) {
					return selectAttributes(test.attributes, types), nil
				},
			})
			repository := NewKeyRepository(testOptions()...)
			if _, err := repository.RotateKey(context.Background(), models.RotateKeyRequest{
				KeyID: "pkcs11:object=k",
			}); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestRotationLabelBase(t *testing.T) {
	tests := []struct {
		name       string
		attributes []attribute
		uri        *keyURI
		want       string
	}{
		{
			name:       "strips a previous rotation suffix",
			attributes: []attribute{newBytesAttribute(ckaLabel, []byte(rsaKeyPrefix+"-1700000000"))},
			uri:        &keyURI{Object: "ignored"},
			want:       rsaKeyPrefix,
		},
		{
			name:       "keeps a custom label",
			attributes: []attribute{newBytesAttribute(ckaLabel, []byte("my-own-key"))},
			uri:        &keyURI{Object: "ignored"},
			want:       "my-own-key",
		},
		{
			name:       "falls back to the uri object",
			attributes: nil,
			uri:        &keyURI{Object: "from-uri"},
			want:       "from-uri",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := rotationLabelBase(test.attributes, test.uri); got != test.want {
				t.Fatalf("rotationLabelBase() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestGetKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	fake := &fakeModule{
		getAttributesFn: func(_ sessionHandle, _ objectHandle, types []attributeType) ([]attribute, error) {
			all := map[attributeType]attribute{
				ckaLabel:   newBytesAttribute(ckaLabel, []byte("resolved-label")),
				ckaID:      newBytesAttribute(ckaID, []byte{0xaa, 0xbb}),
				ckaClass:   newULongAttribute(ckaClass, uint64(classPrivateKey)),
				ckaKeyType: newULongAttribute(ckaKeyType, uint64(ckkRSA)),
			}
			for kind, attr := range rsaAttributeMap(key) {
				all[kind] = attr
			}
			return selectAttributes(all, types), nil
		},
	}
	installFake(t, fake)

	repository := NewKeyRepository(testOptions()...)
	data, err := repository.GetKey(context.Background(), models.GetKeyRequest{
		KeyID: "pkcs11:object=whatever;type=private",
	})
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	// The returned reference must carry what the token actually holds, not
	// what the caller guessed.
	if !strings.Contains(data.KeyRef, "resolved-label") {
		t.Fatalf("KeyRef = %q, want the token label", data.KeyRef)
	}
	if data.KeyID != "aabb" {
		t.Fatalf("KeyID = %q, want the hex CKA_ID", data.KeyID)
	}
	if data.PublicKey == "" {
		t.Fatal("GetKey() should have materialised the public key")
	}
}

func rsaAttributeMap(key *rsa.PrivateKey) map[attributeType]attribute {
	return map[attributeType]attribute{
		ckaModulus:     newBytesAttribute(ckaModulus, key.N.Bytes()),
		ckaPublicExpon: newBytesAttribute(ckaPublicExpon, []byte{0x01, 0x00, 0x01}),
	}
}

// TestGetKeyWithoutPublicHalf covers a bare AES key: having no exportable
// public material is normal, not an error.
func TestGetKeyWithoutPublicHalf(t *testing.T) {
	installFake(t, &fakeModule{
		getAttributesFn: func(_ sessionHandle, _ objectHandle, types []attributeType) ([]attribute, error) {
			all := map[attributeType]attribute{
				ckaLabel: newBytesAttribute(ckaLabel, []byte("aes-key")),
				ckaID:    newBytesAttribute(ckaID, []byte{0x01}),
			}
			return selectAttributes(all, types), nil
		},
	})

	repository := NewKeyRepository(testOptions()...)
	data, err := repository.GetKey(context.Background(), models.GetKeyRequest{KeyID: "pkcs11:object=aes-key"})
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}
	if data.PublicKey != "" {
		t.Fatalf("PublicKey = %q, want empty", data.PublicKey)
	}
	if !isKeyURI(data.KeyRef) {
		t.Fatalf("KeyRef = %q", data.KeyRef)
	}
}

func TestGetKeyPropagatesLookupFailure(t *testing.T) {
	installFake(t, &fakeModule{
		findObjectsFn: func(sessionHandle, []attribute) ([]objectHandle, error) { return nil, nil },
	})

	repository := NewKeyRepository(testOptions()...)
	if _, err := repository.GetKey(context.Background(), models.GetKeyRequest{
		KeyID: "pkcs11:object=absent",
	}); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("GetKey() = %v, want ErrKeyNotFound", err)
	}
}

// TestDeactivateKeyProbesBeforeWriting is the trap this covers:
// C_SetAttributeValue rejects the whole template if it names one attribute the
// object does not carry, so the usage flags must be probed first.
func TestDeactivateKeyProbesBeforeWriting(t *testing.T) {
	var written []attribute
	fake := &fakeModule{
		getAttributesFn: func(_ sessionHandle, _ objectHandle, types []attributeType) ([]attribute, error) {
			// This object only has CKA_SIGN and CKA_DECRYPT.
			all := map[attributeType]attribute{
				ckaSign:    newBoolAttribute(ckaSign, true),
				ckaDecrypt: newBoolAttribute(ckaDecrypt, true),
			}
			return selectAttributes(all, types), nil
		},
		setAttributesFn: func(_ sessionHandle, _ objectHandle, template []attribute) error {
			written = template
			return nil
		},
	}
	installFake(t, fake)

	repository := NewKeyRepository(testOptions()...)
	if err := repository.DeactivateKey(context.Background(), models.DeactivateKeyRequest{
		KeyID: "pkcs11:object=k;type=private",
	}); err != nil {
		t.Fatalf("DeactivateKey() error = %v", err)
	}

	if len(written) != 2 {
		t.Fatalf("wrote %d attributes, want only the two the object carries", len(written))
	}
	for _, attr := range written {
		if attr.Type != ckaSign && attr.Type != ckaDecrypt {
			t.Fatalf("wrote attribute %d, which the object does not carry", attr.Type)
		}
		value, _ := boolValue(attr.Value)
		if value {
			t.Fatalf("attribute %d was set to true, want false", attr.Type)
		}
	}
}

func TestDeactivateKeyFailsWhenNothingToClear(t *testing.T) {
	installFake(t, &fakeModule{
		getAttributesFn: func(_ sessionHandle, _ objectHandle, types []attributeType) ([]attribute, error) {
			return selectAttributes(map[attributeType]attribute{}, types), nil
		},
	})

	repository := NewKeyRepository(testOptions()...)
	if err := repository.DeactivateKey(context.Background(), models.DeactivateKeyRequest{
		KeyID: "pkcs11:object=k",
	}); err == nil {
		t.Fatal("expected an error when the object has no usage attributes")
	}
}

// TestDeactivateKeyDoesNotDestroyByDefault pins the safety default: a token
// that refuses the write must fail rather than lose the key.
func TestDeactivateKeyDoesNotDestroyByDefault(t *testing.T) {
	var destroyed bool
	setErr := newTokenError("C_SetAttributeValue", ckrAttributeReadOnly)
	installFake(t, &fakeModule{
		getAttributesFn: func(_ sessionHandle, _ objectHandle, types []attributeType) ([]attribute, error) {
			return selectAttributes(map[attributeType]attribute{
				ckaSign: newBoolAttribute(ckaSign, true),
			}, types), nil
		},
		setAttributesFn: func(sessionHandle, objectHandle, []attribute) error { return setErr },
		destroyObjectFn: func(sessionHandle, objectHandle) error { destroyed = true; return nil },
	})

	repository := NewKeyRepository(testOptions()...)
	err := repository.DeactivateKey(context.Background(), models.DeactivateKeyRequest{KeyID: "pkcs11:object=k"})
	if !errors.Is(err, setErr) {
		t.Fatalf("DeactivateKey() = %v, want the token error", err)
	}
	if destroyed {
		t.Fatal("the key was destroyed without WithDeactivateDestroys")
	}
}

func TestDeactivateKeyDestroysWhenAsked(t *testing.T) {
	var destroyed bool
	installFake(t, &fakeModule{
		getAttributesFn: func(_ sessionHandle, _ objectHandle, types []attributeType) ([]attribute, error) {
			return selectAttributes(map[attributeType]attribute{
				ckaSign: newBoolAttribute(ckaSign, true),
			}, types), nil
		},
		setAttributesFn: func(sessionHandle, objectHandle, []attribute) error {
			return newTokenError("C_SetAttributeValue", ckrAttributeReadOnly)
		},
		destroyObjectFn: func(sessionHandle, objectHandle) error { destroyed = true; return nil },
	})

	repository := NewKeyRepository(testOptions(WithDeactivateDestroys(true))...)
	if err := repository.DeactivateKey(context.Background(), models.DeactivateKeyRequest{
		KeyID: "pkcs11:object=k",
	}); err != nil {
		t.Fatalf("DeactivateKey() error = %v", err)
	}
	if !destroyed {
		t.Fatal("WithDeactivateDestroys was set but the key was not destroyed")
	}
}

func TestKeyRepositoryRequiresKeyReference(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewKeyRepository(testOptions()...)
	ctx := context.Background()

	if _, err := repository.RotateKey(ctx, models.RotateKeyRequest{}); !errors.Is(err, ErrKeyURIRequired) {
		t.Fatalf("RotateKey() = %v, want ErrKeyURIRequired", err)
	}
	if _, err := repository.GetKey(ctx, models.GetKeyRequest{}); !errors.Is(err, ErrKeyURIRequired) {
		t.Fatalf("GetKey() = %v, want ErrKeyURIRequired", err)
	}
	if err := repository.DeactivateKey(ctx, models.DeactivateKeyRequest{}); !errors.Is(err, ErrKeyURIRequired) {
		t.Fatalf("DeactivateKey() = %v, want ErrKeyURIRequired", err)
	}
}

func TestKeyDataForUsesConfiguredDefault(t *testing.T) {
	installFake(t, &fakeModule{
		getAttributesFn: func(_ sessionHandle, _ objectHandle, types []attributeType) ([]attribute, error) {
			return selectAttributes(map[attributeType]attribute{
				ckaLabel: newBytesAttribute(ckaLabel, []byte("cfg")),
			}, types), nil
		},
	})

	repository := NewKeyRepository(testOptions(WithKeyURI("pkcs11:object=configured"))...)
	data, err := repository.GetKey(context.Background(), models.GetKeyRequest{})
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}
	if !strings.Contains(data.KeyRef, "cfg") {
		t.Fatalf("KeyRef = %q", data.KeyRef)
	}
}

func TestGenerateSymetrycKeysAcceptsSmallKeys(t *testing.T) {
	installFake(t, &fakeModule{})
	repository := NewSymmetricRepository(testOptions()...)

	if _, err := repository.GenerateSymetrycKeys(context.Background(), models.GenerateSymmetricKeyRequest{
		Size: common.Key128Bits,
	}); err != nil {
		t.Fatalf("GenerateSymetrycKeys(128) error = %v", err)
	}
}
