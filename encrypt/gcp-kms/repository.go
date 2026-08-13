// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package gcpkms

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/internal/trace"
	"github.com/PointerByte/forge-go/encrypt/local"
	"github.com/PointerByte/forge-go/encrypt/models"
	"github.com/PointerByte/forge-go/encrypt/utilities"
	"github.com/spf13/viper"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

const (
	defaultGCPKeyIDKey     = "encrypt.vault.gcp-kms.key-id"
	legacyGCPKeyIDKey      = "encrypt.gcp-kms.key-id"
	gcpProviderName        = "gcp-kms"
	gcpSymmetricKeyPrefix  = "GoForge-symmetric"
	gcpAsymmetricKeyPrefix = "GoForge-rsa"
	gcpKEMKeyPrefix        = "GoForge-kem"
	gcpEd25519KeyPrefix    = "GoForge-ed25519" // gitleaks:allow
)

var (
	errGCPKMSKeyIDRequired   = errors.New("gcp-kms: key id is required")
	errGCPKMSKeyRingRequired = errors.New("gcp-kms: key ring path is required")
	errGCPKMSVersionRequired = errors.New("gcp-kms: crypto key version is required")
	errGCPECCUnsupported     = errors.New("gcp-kms: provider-backed ECDH is not supported; Cloud KMS uses key encapsulation")
	newGCPKMSClientFn        = kms.NewKeyManagementClient
	newGCPClientFn           = func(ctx context.Context) (gcpKMSClient, error) {
		client, err := newGCPKMSClientFn(ctx)
		if err != nil {
			return nil, fmt.Errorf("gcp-kms: create client: %w", err)
		}
		return &gcpClientAdapter{KeyManagementClient: client}, nil
	}
)

type gcpKMSClient interface {
	CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error)
	CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error)
	GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error)
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error)
	UpdateCryptoKeyVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error)
	UpdateCryptoKeyPrimaryVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyPrimaryVersionRequest) (*kmspb.CryptoKey, error)
	Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error)
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error)
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error)
	AsymmetricDecrypt(ctx context.Context, req *kmspb.AsymmetricDecryptRequest) (*kmspb.AsymmetricDecryptResponse, error)
	Decapsulate(ctx context.Context, req *kmspb.DecapsulateRequest) (*kmspb.DecapsulateResponse, error)
	MacSign(ctx context.Context, req *kmspb.MacSignRequest) (*kmspb.MacSignResponse, error)
	MacVerify(ctx context.Context, req *kmspb.MacVerifyRequest) (*kmspb.MacVerifyResponse, error)
	Close() error
}

type gcpClientAdapter struct{ *kms.KeyManagementClient }

func (adapter *gcpClientAdapter) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	return adapter.KeyManagementClient.CreateCryptoKey(ctx, req)
}
func (adapter *gcpClientAdapter) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	return adapter.KeyManagementClient.CreateCryptoKeyVersion(ctx, req)
}
func (adapter *gcpClientAdapter) GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	return adapter.KeyManagementClient.GetCryptoKey(ctx, req)
}
func (adapter *gcpClientAdapter) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	return adapter.KeyManagementClient.GetPublicKey(ctx, req)
}
func (adapter *gcpClientAdapter) UpdateCryptoKeyVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	return adapter.KeyManagementClient.UpdateCryptoKeyVersion(ctx, req)
}
func (adapter *gcpClientAdapter) UpdateCryptoKeyPrimaryVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyPrimaryVersionRequest) (*kmspb.CryptoKey, error) {
	return adapter.KeyManagementClient.UpdateCryptoKeyPrimaryVersion(ctx, req)
}
func (adapter *gcpClientAdapter) Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	return adapter.KeyManagementClient.Encrypt(ctx, req)
}
func (adapter *gcpClientAdapter) Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	return adapter.KeyManagementClient.Decrypt(ctx, req)
}
func (adapter *gcpClientAdapter) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	return adapter.KeyManagementClient.AsymmetricSign(ctx, req)
}
func (adapter *gcpClientAdapter) AsymmetricDecrypt(ctx context.Context, req *kmspb.AsymmetricDecryptRequest) (*kmspb.AsymmetricDecryptResponse, error) {
	return adapter.KeyManagementClient.AsymmetricDecrypt(ctx, req)
}
func (adapter *gcpClientAdapter) Decapsulate(ctx context.Context, req *kmspb.DecapsulateRequest) (*kmspb.DecapsulateResponse, error) {
	return adapter.KeyManagementClient.Decapsulate(ctx, req)
}
func (adapter *gcpClientAdapter) MacSign(ctx context.Context, req *kmspb.MacSignRequest) (*kmspb.MacSignResponse, error) {
	return adapter.KeyManagementClient.MacSign(ctx, req)
}
func (adapter *gcpClientAdapter) MacVerify(ctx context.Context, req *kmspb.MacVerifyRequest) (*kmspb.MacVerifyResponse, error) {
	return adapter.KeyManagementClient.MacVerify(ctx, req)
}

type symmetricRepository struct{ local local.SymmetricRepository }
type keyRepository struct{}
type hashRepository struct{ local local.HashRepository }
type asymmetricRepository struct{ local local.AsymmetricRepository }
type signatureRepository struct{ local local.SignatureRepository }

type Repository struct {
	SymmetricRepository
	AsymmetricRepository
	KeyRepository
	SignatureRepository
	HashRepository
}

func NewSymmetricRepository() SymmetricRepository {
	return &symmetricRepository{local: local.NewSymmetricRepository()}
}

func NewHashRepository() HashRepository {
	return &hashRepository{local: local.NewHashRepository()}
}

func NewKeyRepository() KeyRepository {
	return &keyRepository{}
}

func NewAsymmetricRepository() AsymmetricRepository {
	return &asymmetricRepository{local: local.NewAsymmetricRepository()}
}

func NewSignatureRepository() SignatureRepository {
	return &signatureRepository{local: local.NewSignatureRepository()}
}

func NewRepository() *Repository {
	return &Repository{
		SymmetricRepository:  NewSymmetricRepository(),
		AsymmetricRepository: NewAsymmetricRepository(),
		KeyRepository:        NewKeyRepository(),
		SignatureRepository:  NewSignatureRepository(),
		HashRepository:       NewHashRepository(),
	}
}

func (repository *symmetricRepository) GenerateSymetrycKeys(ctx context.Context, input models.GenerateSymmetricKeyRequest) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "gcp-kms/GenerateSymetrycKeys")
	defer end(err)
	if input.Size != common.Key256Bits {
		return nil, fmt.Errorf("gcp-kms: unsupported symmetric key size: %d", input.Size)
	}

	client, err := newGCPClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	parent, err := resolveGCPKeyRingName("")
	if err != nil {
		return nil, err
	}

	keyID := fmt.Sprintf("%s-%d", gcpSymmetricKeyPrefix, time.Now().UnixNano())
	cryptoKey, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      parent,
		CryptoKeyId: keyID,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
			Labels:  gcpUIDLabels(input.UID),
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: create symmetric key: %w", err)
	}
	return &models.KeyData{KeyID: keyID, KeyRef: cryptoKey.GetName(), Provider: gcpProviderName}, nil
}

func (repository *keyRepository) RotateKey(ctx context.Context, input models.RotateKeyRequest) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "gcp-kms/RotateKey")
	defer end(err)
	client, err := newGCPClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	keyName, _, err := resolveGCPKeyLookupNames(input.KeyID)
	if err != nil {
		return nil, err
	}
	cryptoKey, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: keyName})
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: get crypto key before rotation: %w", err)
	}

	algorithm, err := gcpRotationAlgorithm(cryptoKey)
	if err != nil {
		return nil, err
	}
	version, err := client.CreateCryptoKeyVersion(ctx, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: keyName,
		CryptoKeyVersion: &kmspb.CryptoKeyVersion{
			Algorithm: algorithm,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: rotate key: %w", err)
	}
	versionName := version.GetName()
	if versionName == "" {
		return nil, errors.New("gcp-kms: missing rotated crypto key version metadata")
	}

	if cryptoKey.GetPurpose() == kmspb.CryptoKey_ENCRYPT_DECRYPT {
		versionID, err := gcpCryptoKeyVersionID(versionName)
		if err != nil {
			return nil, err
		}
		cryptoKey, err = client.UpdateCryptoKeyPrimaryVersion(ctx, &kmspb.UpdateCryptoKeyPrimaryVersionRequest{
			Name:               keyName,
			CryptoKeyVersionId: versionID,
		})
		if err != nil {
			return nil, fmt.Errorf("gcp-kms: update primary crypto key version: %w", err)
		}
	}

	return gcpKeyDataFromCryptoKey(ctx, client, cryptoKey, keyName, versionName)
}

func (repository *keyRepository) GetKey(ctx context.Context, input models.GetKeyRequest) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "gcp-kms/GetKey")
	defer end(err)
	client, err := newGCPClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	keyName, versionName, err := resolveGCPKeyLookupNames(input.KeyID)
	if err != nil {
		return nil, err
	}
	cryptoKey, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: keyName})
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: get crypto key: %w", err)
	}
	return gcpKeyDataFromCryptoKey(ctx, client, cryptoKey, keyName, versionName)
}

func (repository *keyRepository) DeactivateKey(ctx context.Context, input models.DeactivateKeyRequest) (err error) {
	end := trace.Start(ctx, "gcp-kms/DeactivateKey")
	defer end(err)
	client, err := newGCPClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	keyName, versionName, err := resolveGCPKeyLookupNames(input.KeyID)
	if err != nil {
		return err
	}
	cryptoKey, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: keyName})
	if err != nil {
		return fmt.Errorf("gcp-kms: get crypto key before deactivation: %w", err)
	}

	versionName = gcpPublicVersionName(keyName, cryptoKey, versionName)
	if _, err := client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: &kmspb.CryptoKeyVersion{
			Name:  versionName,
			State: kmspb.CryptoKeyVersion_DISABLED,
		},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"state"}},
	}); err != nil {
		return fmt.Errorf("gcp-kms: deactivate key version: %w", err)
	}
	return nil
}

func (repository *symmetricRepository) EncryptAES(ctx context.Context, input models.EncryptAESRequest) (out string, err error) {
	end := trace.Start(ctx, "gcp-kms/EncryptAES")
	defer end(err)
	if utilities.IsLocalAESKey(input.SecretKey) {
		return repository.local.EncryptAES(ctx, input)
	}

	client, err := newGCPClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()

	keyName, err := resolveGCPCryptoKeyName(input.SecretKey)
	if err != nil {
		return "", err
	}
	response, err := client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:                        keyName,
		Plaintext:                   []byte(input.Value),
		AdditionalAuthenticatedData: gcpAuthenticatedData(input.UID, input.Additional),
	})
	if err != nil {
		return "", fmt.Errorf("gcp-kms: encrypt with symmetric key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(response.Ciphertext), nil
}

func (repository *symmetricRepository) DecryptAES(ctx context.Context, input models.DecryptAESRequest) (out string, err error) {
	end := trace.Start(ctx, "gcp-kms/DecryptAES")
	defer end(err)
	if utilities.IsLocalAESKey(input.SecretKey) {
		return repository.local.DecryptAES(ctx, input)
	}

	client, err := newGCPClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()

	keyName, err := resolveGCPCryptoKeyName(input.SecretKey)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(input.CipherValue)
	if err != nil {
		return "", fmt.Errorf("gcp-kms: decode ciphertext: %w", err)
	}
	response, err := client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:                        keyName,
		Ciphertext:                  ciphertext,
		AdditionalAuthenticatedData: gcpAuthenticatedData(input.UID, input.Additional),
	})
	if err != nil {
		return "", fmt.Errorf("gcp-kms: decrypt with symmetric key: %w", err)
	}
	return string(response.Plaintext), nil
}

func (repository *hashRepository) HMAC(ctx context.Context, secretKey, message string) string {
	defer trace.Start(ctx, "gcp-kms/HMAC")(nil)
	if !looksLikeGCPKMSKeyReference(secretKey) {
		return repository.local.HMAC(ctx, secretKey, message)
	}

	client, err := newGCPClient(ctx)
	if err != nil {
		return ""
	}
	defer client.Close()

	versionName, err := resolveGCPCryptoKeyVersionName(secretKey)
	if err != nil {
		return ""
	}
	response, err := client.MacSign(ctx, &kmspb.MacSignRequest{Name: versionName, Data: []byte(message)})
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(response.Mac)
}

func (repository *hashRepository) Sha256Hex(ctx context.Context, message string) string {
	defer trace.Start(ctx, "gcp-kms/Sha256Hex")(nil)
	return repository.local.Sha256Hex(ctx, message)
}

func (repository *hashRepository) Blake3(ctx context.Context, message string) string {
	defer trace.Start(ctx, "gcp-kms/Blake3")(nil)
	return repository.local.Blake3(ctx, message)
}

func (repository *asymmetricRepository) GenerateECDHCurveKeys(ctx context.Context, input models.GenerateECDHCurveKeyRequest) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "gcp-kms/GenerateECDHCurveKeys")
	defer end(err)
	algorithm, err := gcpKEMAlgorithm(input.Curve)
	if err != nil {
		return nil, err
	}

	client, err := newGCPClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	parent, err := resolveGCPKeyRingName("")
	if err != nil {
		return nil, err
	}
	keyID := fmt.Sprintf("%s-%d", gcpKEMKeyPrefix, time.Now().UnixNano())
	cryptoKey, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      parent,
		CryptoKeyId: keyID,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_KEY_ENCAPSULATION,
			Labels:  gcpUIDLabels(input.UID),
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: algorithm,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: create kem key: %w", err)
	}

	versionName, err := ensureGCPVersion(ctx, client, cryptoKey.GetName(), algorithm, cryptoKey.GetPrimary())
	if err != nil {
		return nil, err
	}
	publicKey, _, err := fetchGCPKEMPublicKey(ctx, client, versionName)
	if err != nil {
		return nil, err
	}
	return &models.KeyData{
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		KeyID:     keyID,
		KeyRef:    versionName,
		Provider:  gcpProviderName,
	}, nil
}

func (repository *asymmetricRepository) ECDH_Encode(ctx context.Context, input models.ECDHEncodeRequest) (out string, err error) {
	end := trace.Start(ctx, "gcp-kms/ECDH_Encode")
	defer end(err)
	if _, err := utilities.ParseECDHPublicKeyFromBase64(input.PublicKey); err == nil {
		return repository.local.ECDH_Encode(ctx, input)
	}
	if payload, err := encodeGCPKEMPayload(ctx, input.UID, input.PublicKey, input.Text); err == nil {
		return payload, nil
	}

	client, err := newGCPClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()

	versionName, err := resolveGCPCryptoKeyVersionName(input.PublicKey)
	if err != nil {
		return "", err
	}
	kemPublicKey, _, err := fetchGCPKEMPublicKey(ctx, client, versionName)
	if err != nil {
		return "", err
	}
	return encodeGCPKEMPayload(ctx, input.UID, base64.StdEncoding.EncodeToString(kemPublicKey), input.Text)
}

func (repository *asymmetricRepository) ECDH_Decode(ctx context.Context, input models.ECDHDecodeRequest) (out string, err error) {
	end := trace.Start(ctx, "gcp-kms/ECDH_Decode")
	defer end(err)
	if _, err := utilities.ParseECDHPrivateKeyFromBase64(input.PrivateKey); err == nil {
		return repository.local.ECDH_Decode(ctx, input)
	}
	payload, err := utilities.DecodeECCCipherPayload(input.CipherText)
	if err != nil {
		return "", err
	}
	kemCiphertext, err := base64.StdEncoding.DecodeString(payload.EphemeralPublicKey)
	if err != nil {
		return "", fmt.Errorf("gcp-kms: decode kem ciphertext: %w", err)
	}

	client, err := newGCPClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()

	versionName, err := resolveGCPCryptoKeyVersionName(input.PrivateKey)
	if err != nil {
		return "", err
	}
	response, err := client.Decapsulate(ctx, &kmspb.DecapsulateRequest{
		Name:       versionName,
		Ciphertext: kemCiphertext,
	})
	if err != nil {
		return "", fmt.Errorf("gcp-kms: decapsulate shared secret: %w", err)
	}
	derivedKey, err := utilities.DeriveECCAESKey(response.GetSharedSecret(), payload.Curve)
	if err != nil {
		return "", err
	}
	return local.NewSymmetricRepository().DecryptAES(ctx, models.DecryptAESRequest{
		UID:         input.UID,
		SecretKey:   base64.StdEncoding.EncodeToString(derivedKey),
		CipherValue: payload.Ciphertext,
		Additional:  &payload.Curve,
	})
}

func (repository *asymmetricRepository) GenerateRSAKeys(ctx context.Context, input models.GenerateRSAKeyRequest) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "gcp-kms/GenerateRSAKeys")
	defer end(err)
	algorithm, err := gcpRSADecryptAlgorithm(input.Size)
	if err != nil {
		return nil, err
	}

	client, err := newGCPClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	parent, err := resolveGCPKeyRingName("")
	if err != nil {
		return nil, err
	}
	keyID := fmt.Sprintf("%s-%d", gcpAsymmetricKeyPrefix, time.Now().UnixNano())
	cryptoKey, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      parent,
		CryptoKeyId: keyID,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
			Labels:  gcpUIDLabels(input.UID),
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: algorithm,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: create rsa key: %w", err)
	}

	versionName, err := ensureGCPVersion(ctx, client, cryptoKey.GetName(), algorithm, cryptoKey.GetPrimary())
	if err != nil {
		return nil, err
	}
	publicKey, err := fetchGCPPublicKey(ctx, client, versionName)
	if err != nil {
		return nil, err
	}

	return &models.KeyData{
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		KeyID:     keyID,
		KeyRef:    versionName,
		Provider:  gcpProviderName,
	}, nil
}

func (repository *asymmetricRepository) RSA_OAEP_Encode(ctx context.Context, input models.RSAOAEPEncodeRequest) (out string, err error) {
	end := trace.Start(ctx, "gcp-kms/RSA_OAEP_Encode")
	defer end(err)
	if _, err := utilities.ParseRSAPublicKeyFromBase64(input.PublicKey); err == nil {
		return repository.local.RSA_OAEP_Encode(ctx, input)
	}

	client, err := newGCPClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()

	versionName, err := resolveGCPCryptoKeyVersionName(input.PublicKey)
	if err != nil {
		return "", err
	}
	publicKeyDER, err := fetchGCPPublicKey(ctx, client, versionName)
	if err != nil {
		return "", err
	}
	return repository.local.RSA_OAEP_Encode(ctx, models.RSAOAEPEncodeRequest{
		UID:       input.UID,
		PublicKey: base64.StdEncoding.EncodeToString(publicKeyDER),
		Text:      input.Text,
	})
}

func (repository *asymmetricRepository) RSA_OAEP_Decode(ctx context.Context, input models.RSAOAEPDecodeRequest) (out string, err error) {
	end := trace.Start(ctx, "gcp-kms/RSA_OAEP_Decode")
	defer end(err)
	if _, err := utilities.ParseRSAPrivateKeyFromBase64(input.PrivateKey); err == nil {
		return repository.local.RSA_OAEP_Decode(ctx, input)
	}

	client, err := newGCPClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()

	versionName, err := resolveGCPCryptoKeyVersionName(input.PrivateKey)
	if err != nil {
		return "", err
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(input.CipherText)
	if err != nil {
		return "", fmt.Errorf("gcp-kms: decode ciphertext: %w", err)
	}
	response, err := client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{Name: versionName, Ciphertext: cipherBytes})
	if err != nil {
		return "", fmt.Errorf("gcp-kms: asymmetric decrypt: %w", err)
	}
	return string(response.Plaintext), nil
}

func (repository *signatureRepository) GenerateEd255Keys(ctx context.Context) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "gcp-kms/GenerateEd255Keys")
	defer end(err)

	client, err := newGCPClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	parent, err := resolveGCPKeyRingName("")
	if err != nil {
		return nil, err
	}
	keyID := fmt.Sprintf("%s-%d", gcpEd25519KeyPrefix, time.Now().UnixNano())
	cryptoKey, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      parent,
		CryptoKeyId: keyID,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: create ed25519 key: %w", err)
	}

	versionName, err := ensureGCPVersion(ctx, client, cryptoKey.GetName(), kmspb.CryptoKeyVersion_EC_SIGN_ED25519, cryptoKey.GetPrimary())
	if err != nil {
		return nil, err
	}
	publicKey, err := fetchGCPPublicKey(ctx, client, versionName)
	if err != nil {
		return nil, err
	}

	return &models.KeyData{
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		KeyID:     keyID,
		KeyRef:    versionName,
		Provider:  gcpProviderName,
	}, nil
}

func (repository *signatureRepository) SignEd25519(ctx context.Context, privateKey, text string) (out string, err error) {
	end := trace.Start(ctx, "gcp-kms/SignEd25519")
	defer end(err)
	if _, err := utilities.ParseEd25519PrivateKeyFromBase64(privateKey); err == nil {
		return repository.local.SignEd25519(ctx, privateKey, text)
	}

	client, err := newGCPClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()

	versionName, err := resolveGCPCryptoKeyVersionName(privateKey)
	if err != nil {
		return "", err
	}
	response, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{Name: versionName, Data: []byte(text)})
	if err != nil {
		return "", fmt.Errorf("gcp-kms: sign ed25519: %w", err)
	}
	return base64.StdEncoding.EncodeToString(response.Signature), nil
}

func (repository *signatureRepository) VerifyEd25519(ctx context.Context, publicKey, text, signature string) (err error) {
	end := trace.Start(ctx, "gcp-kms/VerifyEd25519")
	defer end(err)
	if _, err := utilities.ParseEd25519PublicKeyFromBase64(publicKey); err == nil {
		return repository.local.VerifyEd25519(ctx, publicKey, text, signature)
	}

	client, err := newGCPClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	versionName, err := resolveGCPCryptoKeyVersionName(publicKey)
	if err != nil {
		return err
	}
	publicKeyDER, err := fetchGCPPublicKey(ctx, client, versionName)
	if err != nil {
		return err
	}
	keyAny, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return fmt.Errorf("gcp-kms: parse public key: %w", err)
	}
	edPublicKey, ok := keyAny.(ed25519.PublicKey)
	if !ok {
		return errors.New("gcp-kms: public key is not an Ed25519 key")
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("gcp-kms: decode signature from base64: %w", err)
	}
	if !ed25519.Verify(edPublicKey, []byte(text), signatureBytes) {
		return errors.New("gcp-kms: invalid Ed25519 signature")
	}
	return nil
}

func (repository *signatureRepository) SignRSAPSS(ctx context.Context, privateKey, text string) (out string, err error) {
	end := trace.Start(ctx, "gcp-kms/SignRSAPSS")
	defer end(err)
	if _, err := utilities.ParseRSAPrivateKeyFromBase64(privateKey); err == nil {
		return repository.local.SignRSAPSS(ctx, privateKey, text)
	}

	client, err := newGCPClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()

	versionName, err := resolveGCPCryptoKeyVersionName(privateKey)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(text))
	response, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name:   versionName,
		Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest[:]}},
	})
	if err != nil {
		return "", fmt.Errorf("gcp-kms: sign rsa-pss-sha256: %w", err)
	}
	return base64.StdEncoding.EncodeToString(response.Signature), nil
}

func (repository *signatureRepository) VerifyRSAPSS(ctx context.Context, publicKey, text, signature string) (err error) {
	end := trace.Start(ctx, "gcp-kms/VerifyRSAPSS")
	defer end(err)
	if _, err := utilities.ParseRSAPublicKeyFromBase64(publicKey); err == nil {
		return repository.local.VerifyRSAPSS(ctx, publicKey, text, signature)
	}

	client, err := newGCPClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	versionName, err := resolveGCPCryptoKeyVersionName(publicKey)
	if err != nil {
		return err
	}
	publicKeyDER, err := fetchGCPPublicKey(ctx, client, versionName)
	if err != nil {
		return err
	}
	keyAny, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return fmt.Errorf("gcp-kms: parse public key: %w", err)
	}
	rsaPublicKey, ok := keyAny.(*rsa.PublicKey)
	if !ok {
		return errors.New("gcp-kms: public key is not an RSA key")
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("gcp-kms: decode signature from base64: %w", err)
	}
	digest := sha256.Sum256([]byte(text))
	if err := rsa.VerifyPSS(rsaPublicKey, crypto.SHA256, digest[:], signatureBytes, nil); err != nil {
		return fmt.Errorf("gcp-kms: invalid RSA-PSS signature: %w", err)
	}
	return nil
}

func (repository *signatureRepository) Sign_RSA_PKCS1v15_SHA256(ctx context.Context, privateKey, data string) (out string, err error) {
	end := trace.Start(ctx, "gcp-kms/Sign_RSA_PKCS1v15_SHA256")
	defer end(err)
	if privateKey != "" && !looksLikeGCPKMSKeyReference(privateKey) {
		return repository.local.Sign_RSA_PKCS1v15_SHA256(ctx, privateKey, data)
	}

	client, err := newGCPClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()

	versionName, err := resolveGCPCryptoKeyVersionName(privateKey)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(data))
	response, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name:   versionName,
		Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest[:]}},
	})
	if err != nil {
		return "", fmt.Errorf("gcp-kms: sign rsa-sha256: %w", err)
	}
	return base64.StdEncoding.EncodeToString(response.Signature), nil
}

func (repository *signatureRepository) Verify_RSA_PKCS1v15_SHA256(ctx context.Context, data, publicKey string, signature string) (err error) {
	end := trace.Start(ctx, "gcp-kms/Verify_RSA_PKCS1v15_SHA256")
	defer end(err)
	if publicKey != "" && !looksLikeGCPKMSKeyReference(publicKey) {
		return repository.local.Verify_RSA_PKCS1v15_SHA256(ctx, data, publicKey, signature)
	}

	client, err := newGCPClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	versionName, err := resolveGCPCryptoKeyVersionName(publicKey)
	if err != nil {
		return err
	}
	publicKeyDER, err := fetchGCPPublicKey(ctx, client, versionName)
	if err != nil {
		return err
	}
	keyAny, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return fmt.Errorf("gcp-kms: parse public key: %w", err)
	}
	rsaPublicKey, ok := keyAny.(*rsa.PublicKey)
	if !ok {
		return errors.New("gcp-kms: public key is not an RSA key")
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("gcp-kms: decode signature from base64: %w", err)
	}
	digest := sha256.Sum256([]byte(data))
	if err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, digest[:], signatureBytes); err != nil {
		return fmt.Errorf("gcp-kms: invalid RSA SHA-256 signature: %w", err)
	}
	return nil
}

func newGCPClient(ctx context.Context) (gcpKMSClient, error) {
	return newGCPClientFn(ctx)
}

func configuredGCPKeyID() string {
	if configured := strings.TrimSpace(viper.GetString(defaultGCPKeyIDKey)); configured != "" {
		return configured
	}
	return strings.TrimSpace(viper.GetString(legacyGCPKeyIDKey))
}

func resolveGCPKeyRingName(key string) (string, error) {
	rawKey := strings.TrimSpace(key)
	if rawKey == "" {
		rawKey = configuredGCPKeyID()
	}
	if rawKey == "" {
		return "", errGCPKMSKeyIDRequired
	}

	segments := strings.Split(strings.Trim(rawKey, "/"), "/")
	for i := range segments {
		if segments[i] == "cryptoKeys" && i >= 5 {
			return strings.Join(segments[:i], "/"), nil
		}
	}
	return "", errGCPKMSKeyRingRequired
}

func resolveGCPCryptoKeyName(key string) (string, error) {
	rawKey := strings.TrimSpace(key)
	if rawKey == "" {
		rawKey = configuredGCPKeyID()
	}
	if rawKey == "" {
		return "", errGCPKMSKeyIDRequired
	}
	if index := strings.Index(rawKey, "/cryptoKeyVersions/"); index >= 0 {
		return rawKey[:index], nil
	}
	if strings.Contains(rawKey, "/cryptoKeys/") {
		return rawKey, nil
	}
	return "", errGCPKMSKeyIDRequired
}

func resolveGCPCryptoKeyVersionName(key string) (string, error) {
	rawKey := strings.TrimSpace(key)
	if rawKey == "" {
		rawKey = configuredGCPKeyID()
	}
	if rawKey == "" {
		return "", errGCPKMSKeyIDRequired
	}
	if strings.Contains(rawKey, "/cryptoKeyVersions/") {
		return rawKey, nil
	}
	return "", errGCPKMSVersionRequired
}

func resolveGCPKeyLookupNames(key string) (string, string, error) {
	rawKey := strings.TrimSpace(key)
	if rawKey == "" {
		rawKey = configuredGCPKeyID()
	}
	if rawKey == "" {
		return "", "", errGCPKMSKeyIDRequired
	}
	if strings.Contains(rawKey, "/cryptoKeyVersions/") {
		keyName, err := resolveGCPCryptoKeyName(rawKey)
		if err != nil {
			return "", "", err
		}
		return keyName, rawKey, nil
	}
	if strings.Contains(rawKey, "/cryptoKeys/") {
		return rawKey, "", nil
	}

	keyRingName, err := resolveGCPKeyRingName("")
	if err != nil {
		return "", "", err
	}
	return strings.TrimRight(keyRingName, "/") + "/cryptoKeys/" + rawKey, "", nil
}

func ensureGCPVersion(ctx context.Context, client gcpKMSClient, cryptoKeyName string, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, primary *kmspb.CryptoKeyVersion) (string, error) {
	if primary != nil && primary.GetName() != "" {
		return primary.GetName(), nil
	}
	version, err := client.CreateCryptoKeyVersion(ctx, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: cryptoKeyName,
		CryptoKeyVersion: &kmspb.CryptoKeyVersion{
			Algorithm: algorithm,
		},
	})
	if err != nil {
		return "", fmt.Errorf("gcp-kms: create crypto key version: %w", err)
	}
	if version.GetName() == "" {
		return "", errors.New("gcp-kms: missing crypto key version metadata")
	}
	return version.GetName(), nil
}

func gcpKeyDataFromCryptoKey(ctx context.Context, client gcpKMSClient, cryptoKey *kmspb.CryptoKey, fallbackKeyName, versionName string) (*models.KeyData, error) {
	keyName := cryptoKey.GetName()
	if keyName == "" {
		keyName = fallbackKeyName
	}
	if keyName == "" {
		return nil, errors.New("gcp-kms: missing crypto key metadata")
	}

	keyData := &models.KeyData{
		KeyID:    gcpKeyIDFromName(keyName),
		KeyRef:   keyName,
		Provider: gcpProviderName,
	}

	switch cryptoKey.GetPurpose() {
	case kmspb.CryptoKey_ASYMMETRIC_DECRYPT, kmspb.CryptoKey_ASYMMETRIC_SIGN:
		publicVersionName := gcpPublicVersionName(keyName, cryptoKey, versionName)
		publicKey, err := fetchGCPPublicKey(ctx, client, publicVersionName)
		if err != nil {
			return nil, err
		}
		keyData.PublicKey = base64.StdEncoding.EncodeToString(publicKey)
		keyData.KeyRef = publicVersionName
	case kmspb.CryptoKey_KEY_ENCAPSULATION:
		publicVersionName := gcpPublicVersionName(keyName, cryptoKey, versionName)
		publicKey, _, err := fetchGCPKEMPublicKey(ctx, client, publicVersionName)
		if err != nil {
			return nil, err
		}
		keyData.PublicKey = base64.StdEncoding.EncodeToString(publicKey)
		keyData.KeyRef = publicVersionName
	default:
		keyData.KeyRef = keyName
	}
	return keyData, nil
}

func gcpRotationAlgorithm(cryptoKey *kmspb.CryptoKey) (kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, error) {
	if algorithm := cryptoKey.GetVersionTemplate().GetAlgorithm(); algorithm != 0 {
		return algorithm, nil
	}
	if cryptoKey.GetPurpose() == kmspb.CryptoKey_ENCRYPT_DECRYPT {
		return kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION, nil
	}
	return 0, errors.New("gcp-kms: missing crypto key version template algorithm")
}

func gcpPublicVersionName(keyName string, cryptoKey *kmspb.CryptoKey, versionName string) string {
	if strings.TrimSpace(versionName) != "" {
		return versionName
	}
	if primary := cryptoKey.GetPrimary(); primary != nil && primary.GetName() != "" {
		return primary.GetName()
	}
	return strings.TrimRight(keyName, "/") + "/cryptoKeyVersions/1"
}

func gcpKeyIDFromName(keyName string) string {
	segments := strings.Split(strings.Trim(keyName, "/"), "/")
	for i := range segments {
		if segments[i] == "cryptoKeys" && i+1 < len(segments) {
			return segments[i+1]
		}
	}
	return keyName
}

func gcpCryptoKeyVersionID(versionName string) (string, error) {
	segments := strings.Split(strings.Trim(versionName, "/"), "/")
	for i := range segments {
		if segments[i] == "cryptoKeyVersions" && i+1 < len(segments) {
			return segments[i+1], nil
		}
	}
	return "", errGCPKMSVersionRequired
}

func fetchGCPPublicKey(ctx context.Context, client gcpKMSClient, versionName string) ([]byte, error) {
	response, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: get public key: %w", err)
	}
	block, _ := pem.Decode([]byte(response.Pem))
	if block == nil {
		return nil, errors.New("gcp-kms: invalid PEM public key")
	}
	return block.Bytes, nil
}

func fetchGCPKEMPublicKey(ctx context.Context, client gcpKMSClient, versionName string) ([]byte, kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, error) {
	response, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name:            versionName,
		PublicKeyFormat: kmspb.PublicKey_NIST_PQC,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("gcp-kms: get kem public key: %w", err)
	}
	algorithm := response.GetAlgorithm()
	if _, err := gcpKEMAlgorithmName(algorithm); err != nil {
		return nil, 0, err
	}
	publicKey := response.GetPublicKey().GetData()
	if len(publicKey) == 0 {
		return nil, 0, errors.New("gcp-kms: missing kem public key material")
	}
	return publicKey, algorithm, nil
}

func gcpUIDLabels(uid string) map[string]string {
	value := gcpLabelValue(uid)
	if value == "" {
		return nil
	}
	return map[string]string{"uid": value}
}

func gcpLabelValue(value string) string {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-' || r == '_':
			builder.WriteRune(r)
		default:
			builder.WriteByte('-')
		}
	}
	label := strings.Trim(builder.String(), "-_")
	if len(label) > 63 {
		label = strings.TrimRight(label[:63], "-_")
	}
	return label
}

func gcpAuthenticatedData(uid string, additional *string) []byte {
	if strings.TrimSpace(uid) == "" {
		return utilities.BytesFromOptionalString(additional)
	}
	if additional == nil {
		return []byte(uid)
	}
	return []byte(uid + "\x00" + *additional)
}

func gcpRSADecryptAlgorithm(size common.SizeAsymetrycKey) (kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, error) {
	switch size {
	case common.Key2048Bits:
		return kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256, nil
	case common.Key3072Bits:
		return kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256, nil
	case common.Key4096Bits:
		return kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256, nil
	default:
		return 0, fmt.Errorf("gcp-kms: unsupported rsa key size: %d", size)
	}
}

func gcpKEMAlgorithm(curve common.CurveAsymmetricKey) (kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, error) {
	switch curve {
	case common.CurveP256:
		return kmspb.CryptoKeyVersion_ML_KEM_768, nil
	case common.CurveP384, common.CurveP521:
		return kmspb.CryptoKeyVersion_ML_KEM_1024, nil
	default:
		return 0, fmt.Errorf("gcp-kms: unsupported kem curve mapping: %q", curve)
	}
}

func gcpKEMAlgorithmName(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (string, error) {
	switch algorithm {
	case kmspb.CryptoKeyVersion_ML_KEM_768:
		return "ML_KEM_768", nil
	case kmspb.CryptoKeyVersion_ML_KEM_1024:
		return "ML_KEM_1024", nil
	default:
		return "", fmt.Errorf("%w: unsupported algorithm %s", errGCPECCUnsupported, algorithm.String())
	}
}

func gcpKEMAlgorithmFromPublicKey(publicKey []byte) (kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, error) {
	switch len(publicKey) {
	case mlkem.EncapsulationKeySize768:
		return kmspb.CryptoKeyVersion_ML_KEM_768, nil
	case mlkem.EncapsulationKeySize1024:
		return kmspb.CryptoKeyVersion_ML_KEM_1024, nil
	default:
		return 0, fmt.Errorf("gcp-kms: unsupported kem public key size: %d", len(publicKey))
	}
}

func encodeGCPKEMPayload(ctx context.Context, uid, publicKey, text string) (string, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("gcp-kms: decode kem public key: %w", err)
	}
	algorithm, err := gcpKEMAlgorithmFromPublicKey(publicKeyBytes)
	if err != nil {
		return "", err
	}
	algorithmName, err := gcpKEMAlgorithmName(algorithm)
	if err != nil {
		return "", err
	}
	sharedSecret, kemCiphertext, err := encapsulateGCPKEM(publicKeyBytes, algorithm)
	if err != nil {
		return "", err
	}
	derivedKey, err := utilities.DeriveECCAESKey(sharedSecret, algorithmName)
	if err != nil {
		return "", err
	}
	ciphertext, err := local.NewSymmetricRepository().EncryptAES(ctx, models.EncryptAESRequest{
		UID:        uid,
		SecretKey:  base64.StdEncoding.EncodeToString(derivedKey),
		Value:      text,
		Additional: &algorithmName,
	})
	if err != nil {
		return "", fmt.Errorf("gcp-kms: encrypt payload with kem shared secret: %w", err)
	}
	return utilities.EncodeECCCipherPayload(utilities.ECCCipherPayload{
		Curve:              algorithmName,
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(kemCiphertext),
		Ciphertext:         ciphertext,
	})
}

func encapsulateGCPKEM(publicKey []byte, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) ([]byte, []byte, error) {
	switch algorithm {
	case kmspb.CryptoKeyVersion_ML_KEM_768:
		encapsulationKey, err := mlkem.NewEncapsulationKey768(publicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("gcp-kms: parse ml-kem-768 public key: %w", err)
		}
		sharedSecret, ciphertext := encapsulationKey.Encapsulate()
		return sharedSecret, ciphertext, nil
	case kmspb.CryptoKeyVersion_ML_KEM_1024:
		encapsulationKey, err := mlkem.NewEncapsulationKey1024(publicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("gcp-kms: parse ml-kem-1024 public key: %w", err)
		}
		sharedSecret, ciphertext := encapsulationKey.Encapsulate()
		return sharedSecret, ciphertext, nil
	default:
		return nil, nil, fmt.Errorf("%w: unsupported algorithm %s", errGCPECCUnsupported, algorithm.String())
	}
}

func looksLikeGCPKMSKeyReference(key string) bool {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return configuredGCPKeyID() != ""
	}
	return strings.HasPrefix(trimmed, "projects/")
}
