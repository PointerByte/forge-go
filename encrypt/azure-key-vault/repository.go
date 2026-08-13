// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package azurekeyvault

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/internal/trace"
	"github.com/PointerByte/forge-go/encrypt/local"
	"github.com/PointerByte/forge-go/encrypt/models"
	"github.com/PointerByte/forge-go/encrypt/utilities"
	"github.com/spf13/viper"
)

const (
	defaultAzureKeyIDKey     = "encrypt.vault.azure-key-vault.key-id"
	legacyAzureKeyIDKey      = "encrypt.azure-key-vault.key-id"
	defaultAzureVaultURLKey  = "encrypt.vault.azure-key-vault.vault-url"
	legacyAzureVaultURLKey   = "encrypt.azure-key-vault.vault-url"
	azureProviderName        = "azure-key-vault"
	azureSymmetricKeyPrefix  = "GoForge-symmetric"
	azureAsymmetricKeyPrefix = "GoForge-rsa"
	azureECDHKeyPrefix       = "GoForge-ecdh"
)

var (
	errAzureKeyIDRequired      = errors.New("azure-key-vault: key id is required")
	errAzureVaultURLRequired   = errors.New("azure-key-vault: vault url is required")
	errAzureEd25519Unsupported = errors.New("azure-key-vault: Ed25519 provider-backed operations are not supported")
	newAzureCredentialFn       = func(options *azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) {
		return azidentity.NewDefaultAzureCredential(options)
	}
	newAzureClientFn = func(vaultURL string, credential azcore.TokenCredential) (azureKeysClient, error) {
		return azkeys.NewClient(vaultURL, credential, nil)
	}
	newAzureECDHDeriverFn = func(ctx context.Context, vaultURL string) (azureECDHDeriver, error) {
		credential, err := newAzureCredentialFn(nil)
		if err != nil {
			return nil, fmt.Errorf("azure-key-vault: create credential: %w", err)
		}
		return &httpAzureECDHDeriver{
			credential: credential,
			httpClient: http.DefaultClient,
		}, nil
	}
)

type azureKeysClient interface {
	CreateKey(ctx context.Context, name string, parameters azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error)
	Encrypt(ctx context.Context, name string, version string, parameters azkeys.KeyOperationParameters, options *azkeys.EncryptOptions) (azkeys.EncryptResponse, error)
	Decrypt(ctx context.Context, name string, version string, parameters azkeys.KeyOperationParameters, options *azkeys.DecryptOptions) (azkeys.DecryptResponse, error)
	GetKey(ctx context.Context, name string, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
	RotateKey(ctx context.Context, name string, options *azkeys.RotateKeyOptions) (azkeys.RotateKeyResponse, error)
	UpdateKey(ctx context.Context, name string, version string, parameters azkeys.UpdateKeyParameters, options *azkeys.UpdateKeyOptions) (azkeys.UpdateKeyResponse, error)
	Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
	Verify(ctx context.Context, name string, version string, parameters azkeys.VerifyParameters, options *azkeys.VerifyOptions) (azkeys.VerifyResponse, error)
}

type azureECDHDeriver interface {
	DeriveSharedSecret(ctx context.Context, reference azureKeyReference, publicKeyDER []byte) ([]byte, error)
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

type azureAEADPayload struct {
	Result string `json:"result"`
	IV     string `json:"iv,omitempty"`
	Tag    string `json:"tag,omitempty"`
}

type azureKeyReference struct {
	VaultURL string
	Name     string
	Version  string
	KID      string
}

type azureECDHDeriveRequest struct {
	Algorithm string           `json:"alg"`
	Public    azureECJWKPublic `json:"public"`
}

type azureECJWKPublic struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	X       string `json:"x"`
	Y       string `json:"y"`
}

type azureECDHDeriveResponse struct {
	Value string `json:"value"`
}

type httpAzureECDHDeriver struct {
	credential azcore.TokenCredential
	httpClient *http.Client
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
	end := trace.Start(ctx, "azure-key-vault/GenerateSymetrycKeys")
	defer end(err)
	if input.Size != common.Key256Bits {
		return nil, fmt.Errorf("azure-key-vault: unsupported symmetric key size: %d", input.Size)
	}

	client, vaultURL, err := newAzureKeysClient(ctx, "")
	if err != nil {
		return nil, err
	}

	keyName := fmt.Sprintf("%s-%d", azureSymmetricKeyPrefix, time.Now().UnixNano())
	response, err := client.CreateKey(ctx, keyName, azkeys.CreateKeyParameters{
		Kty: ptr(azkeys.KeyTypeOctHSM),
		KeyOps: []*azkeys.KeyOperation{
			ptr(azkeys.KeyOperationEncrypt),
			ptr(azkeys.KeyOperationDecrypt),
		},
		Tags: azureUIDTags(input.UID),
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: create symmetric key: %w", err)
	}

	keyID, keyRef, err := azureMetadataFromBundle(response.KeyBundle, vaultURL, keyName)
	if err != nil {
		return nil, err
	}
	return &models.KeyData{KeyID: keyID, KeyRef: keyRef, Provider: azureProviderName}, nil
}

func (repository *keyRepository) RotateKey(ctx context.Context, input models.RotateKeyRequest) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "azure-key-vault/RotateKey")
	defer end(err)
	reference, err := resolveAzureKeyLookupReference(input.KeyID)
	if err != nil {
		return nil, err
	}

	client, _, err := newAzureKeysClient(ctx, reference.VaultURL)
	if err != nil {
		return nil, err
	}

	response, err := client.RotateKey(ctx, reference.Name, nil)
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: rotate key: %w", err)
	}

	keyData, err := azureKeyDataFromBundle(response.KeyBundle, reference.VaultURL, reference.Name)
	if err != nil {
		return nil, err
	}
	rotatedReference, err := resolveAzureKeyReference(keyData.KeyRef)
	if err != nil {
		return keyData, nil
	}
	getResponse, err := client.GetKey(ctx, rotatedReference.Name, rotatedReference.Version, nil)
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: get rotated key: %w", err)
	}
	return azureKeyDataFromBundle(getResponse.KeyBundle, rotatedReference.VaultURL, rotatedReference.Name)
}

func (repository *keyRepository) GetKey(ctx context.Context, input models.GetKeyRequest) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "azure-key-vault/GetKey")
	defer end(err)
	reference, err := resolveAzureKeyLookupReference(input.KeyID)
	if err != nil {
		return nil, err
	}

	client, _, err := newAzureKeysClient(ctx, reference.VaultURL)
	if err != nil {
		return nil, err
	}

	response, err := client.GetKey(ctx, reference.Name, reference.Version, nil)
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: get key: %w", err)
	}
	return azureKeyDataFromBundle(response.KeyBundle, reference.VaultURL, reference.Name)
}

func (repository *keyRepository) DeactivateKey(ctx context.Context, input models.DeactivateKeyRequest) (err error) {
	end := trace.Start(ctx, "azure-key-vault/DeactivateKey")
	defer end(err)
	reference, err := resolveAzureKeyLookupReference(input.KeyID)
	if err != nil {
		return err
	}

	client, _, err := newAzureKeysClient(ctx, reference.VaultURL)
	if err != nil {
		return err
	}

	if reference.Version == "" {
		getResponse, err := client.GetKey(ctx, reference.Name, "", nil)
		if err != nil {
			return fmt.Errorf("azure-key-vault: get key before deactivation: %w", err)
		}
		keyData, err := azureKeyDataFromBundle(getResponse.KeyBundle, reference.VaultURL, reference.Name)
		if err != nil {
			return err
		}
		latestReference, err := resolveAzureKeyReference(keyData.KeyRef)
		if err != nil {
			return err
		}
		reference = latestReference
	}

	enabled := false
	if _, err := client.UpdateKey(ctx, reference.Name, reference.Version, azkeys.UpdateKeyParameters{
		KeyAttributes: &azkeys.KeyAttributes{
			Enabled: &enabled,
		},
	}, nil); err != nil {
		return fmt.Errorf("azure-key-vault: deactivate key: %w", err)
	}
	return nil
}

func (repository *symmetricRepository) EncryptAES(ctx context.Context, input models.EncryptAESRequest) (out string, err error) {
	end := trace.Start(ctx, "azure-key-vault/EncryptAES")
	defer end(err)
	if utilities.IsLocalAESKey(input.SecretKey) {
		return repository.local.EncryptAES(ctx, input)
	}

	reference, err := resolveAzureKeyReference(input.SecretKey)
	if err != nil {
		return "", err
	}
	client, _, err := newAzureKeysClient(ctx, reference.VaultURL)
	if err != nil {
		return "", err
	}

	response, err := client.Encrypt(ctx, reference.Name, reference.Version, azkeys.KeyOperationParameters{
		Algorithm:                   ptr(azkeys.EncryptionAlgorithmA256GCM),
		Value:                       []byte(input.Value),
		AdditionalAuthenticatedData: azureAuthenticatedData(input.UID, input.Additional),
	}, nil)
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: encrypt with symmetric key: %w", err)
	}

	payloadBytes, err := json.Marshal(azureAEADPayload{
		Result: base64.StdEncoding.EncodeToString(response.Result),
		IV:     base64.StdEncoding.EncodeToString(response.IV),
		Tag:    base64.StdEncoding.EncodeToString(response.AuthenticationTag),
	})
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: encode ciphertext payload: %w", err)
	}
	return base64.StdEncoding.EncodeToString(payloadBytes), nil
}

func (repository *symmetricRepository) DecryptAES(ctx context.Context, input models.DecryptAESRequest) (out string, err error) {
	end := trace.Start(ctx, "azure-key-vault/DecryptAES")
	defer end(err)
	if utilities.IsLocalAESKey(input.SecretKey) {
		return repository.local.DecryptAES(ctx, input)
	}

	reference, err := resolveAzureKeyReference(input.SecretKey)
	if err != nil {
		return "", err
	}
	client, _, err := newAzureKeysClient(ctx, reference.VaultURL)
	if err != nil {
		return "", err
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(input.CipherValue)
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: decode ciphertext payload: %w", err)
	}
	var payload azureAEADPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", fmt.Errorf("azure-key-vault: decode ciphertext json: %w", err)
	}

	resultBytes, err := base64.StdEncoding.DecodeString(payload.Result)
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: decode ciphertext bytes: %w", err)
	}
	ivBytes, err := base64.StdEncoding.DecodeString(payload.IV)
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: decode iv: %w", err)
	}
	tagBytes, err := base64.StdEncoding.DecodeString(payload.Tag)
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: decode authentication tag: %w", err)
	}

	response, err := client.Decrypt(ctx, reference.Name, reference.Version, azkeys.KeyOperationParameters{
		Algorithm:                   ptr(azkeys.EncryptionAlgorithmA256GCM),
		Value:                       resultBytes,
		IV:                          ivBytes,
		AuthenticationTag:           tagBytes,
		AdditionalAuthenticatedData: azureAuthenticatedData(input.UID, input.Additional),
	}, nil)
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: decrypt with symmetric key: %w", err)
	}
	return string(response.Result), nil
}

func (repository *hashRepository) HMAC(ctx context.Context, secretKey, message string) string {
	defer trace.Start(ctx, "azure-key-vault/HMAC")(nil)
	if !looksLikeAzureKeyReference(secretKey) {
		return repository.local.HMAC(ctx, secretKey, message)
	}

	reference, err := resolveAzureKeyReference(secretKey)
	if err != nil {
		return ""
	}
	client, _, err := newAzureKeysClient(ctx, reference.VaultURL)
	if err != nil {
		return ""
	}

	response, err := client.Sign(ctx, reference.Name, reference.Version, azkeys.SignParameters{
		Algorithm: ptr(azkeys.SignatureAlgorithmHS256),
		Value:     []byte(message),
	}, nil)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(response.Result)
}

func (repository *hashRepository) Sha256Hex(ctx context.Context, message string) string {
	defer trace.Start(ctx, "azure-key-vault/Sha256Hex")(nil)
	return repository.local.Sha256Hex(ctx, message)
}

func (repository *hashRepository) Blake3(ctx context.Context, message string) string {
	defer trace.Start(ctx, "azure-key-vault/Blake3")(nil)
	return repository.local.Blake3(ctx, message)
}

func (repository *asymmetricRepository) GenerateECDHCurveKeys(ctx context.Context, input models.GenerateECDHCurveKeyRequest) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "azure-key-vault/GenerateECDHCurveKeys")
	defer end(err)
	azureCurve, err := azureECDHCurveName(input.Curve)
	if err != nil {
		return nil, err
	}

	client, vaultURL, err := newAzureKeysClient(ctx, "")
	if err != nil {
		return nil, err
	}

	keyName := fmt.Sprintf("%s-%d", azureECDHKeyPrefix, time.Now().UnixNano())
	response, err := client.CreateKey(ctx, keyName, azkeys.CreateKeyParameters{
		Kty:   ptr(azkeys.KeyTypeEC),
		Curve: ptr(azureCurve),
		KeyOps: []*azkeys.KeyOperation{
			ptr(azkeys.KeyOperation("deriveKey")),
		},
		Tags: azureUIDTags(input.UID),
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: create ecdh key: %w", err)
	}

	publicKey, err := ecdhPublicKeyFromAzureBundle(response.KeyBundle)
	if err != nil {
		return nil, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: marshal ecdh public key: %w", err)
	}

	keyID, keyRef, err := azureMetadataFromBundle(response.KeyBundle, vaultURL, keyName)
	if err != nil {
		return nil, err
	}
	return &models.KeyData{
		PublicKey: base64.StdEncoding.EncodeToString(publicDER),
		KeyID:     keyID,
		KeyRef:    keyRef,
		Provider:  azureProviderName,
	}, nil
}

func (repository *asymmetricRepository) ECDH_Encode(ctx context.Context, input models.ECDHEncodeRequest) (out string, err error) {
	end := trace.Start(ctx, "azure-key-vault/ECDH_Encode")
	defer end(err)
	if _, err := utilities.ParseECDHPublicKeyFromBase64(input.PublicKey); err == nil {
		return repository.local.ECDH_Encode(ctx, input)
	}

	reference, err := resolveAzureKeyReference(input.PublicKey)
	if err != nil {
		return "", err
	}
	client, _, err := newAzureKeysClient(ctx, reference.VaultURL)
	if err != nil {
		return "", err
	}

	response, err := client.GetKey(ctx, reference.Name, reference.Version, nil)
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: get ecdh public key: %w", err)
	}
	recipientPublicKey, err := ecdhPublicKeyFromAzureBundle(response.KeyBundle)
	if err != nil {
		return "", err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(recipientPublicKey)
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: marshal ecdh public key: %w", err)
	}
	return repository.local.ECDH_Encode(ctx, models.ECDHEncodeRequest{
		UID:       input.UID,
		PublicKey: base64.StdEncoding.EncodeToString(publicDER),
		Text:      input.Text,
	})
}

func (repository *asymmetricRepository) ECDH_Decode(ctx context.Context, input models.ECDHDecodeRequest) (out string, err error) {
	end := trace.Start(ctx, "azure-key-vault/ECDH_Decode")
	defer end(err)
	if _, err := utilities.ParseECDHPrivateKeyFromBase64(input.PrivateKey); err == nil {
		return repository.local.ECDH_Decode(ctx, input)
	}

	reference, err := resolveAzureKeyReference(input.PrivateKey)
	if err != nil {
		return "", err
	}
	payload, err := utilities.DecodeECCCipherPayload(input.CipherText)
	if err != nil {
		return "", err
	}
	ephemeralPublicKeyDER, err := base64.StdEncoding.DecodeString(payload.EphemeralPublicKey)
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: decode ephemeral public key: %w", err)
	}

	deriver, err := newAzureECDHDeriverFn(ctx, reference.VaultURL)
	if err != nil {
		return "", err
	}
	sharedSecret, err := deriver.DeriveSharedSecret(ctx, *reference, ephemeralPublicKeyDER)
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: derive shared secret: %w", err)
	}
	derivedKey, err := utilities.DeriveECCAESKey(sharedSecret, payload.Curve)
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
	end := trace.Start(ctx, "azure-key-vault/GenerateRSAKeys")
	defer end(err)
	keySize, err := azureRSAKeySize(input.Size)
	if err != nil {
		return nil, err
	}

	client, vaultURL, err := newAzureKeysClient(ctx, "")
	if err != nil {
		return nil, err
	}

	keyName := fmt.Sprintf("%s-%d", azureAsymmetricKeyPrefix, time.Now().UnixNano())
	response, err := client.CreateKey(ctx, keyName, azkeys.CreateKeyParameters{
		Kty:     ptr(azkeys.KeyTypeRSA),
		KeySize: ptr(int32(keySize)), // #nosec G115 -- azureRSAKeySize only returns 2048/3072/4096, well within int32

		KeyOps: []*azkeys.KeyOperation{
			ptr(azkeys.KeyOperationEncrypt),
			ptr(azkeys.KeyOperationDecrypt),
			ptr(azkeys.KeyOperationSign),
			ptr(azkeys.KeyOperationVerify),
		},
		Tags: azureUIDTags(input.UID),
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: create rsa key: %w", err)
	}

	publicKey, err := rsaPublicKeyFromAzureBundle(response.KeyBundle)
	if err != nil {
		return nil, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: marshal public key: %w", err)
	}

	keyID, keyRef, err := azureMetadataFromBundle(response.KeyBundle, vaultURL, keyName)
	if err != nil {
		return nil, err
	}
	return &models.KeyData{
		PublicKey: base64.StdEncoding.EncodeToString(publicDER),
		KeyID:     keyID,
		KeyRef:    keyRef,
		Provider:  azureProviderName,
	}, nil
}

func (repository *asymmetricRepository) RSA_OAEP_Encode(ctx context.Context, input models.RSAOAEPEncodeRequest) (out string, err error) {
	end := trace.Start(ctx, "azure-key-vault/RSA_OAEP_Encode")
	defer end(err)
	if _, err := utilities.ParseRSAPublicKeyFromBase64(input.PublicKey); err == nil {
		return repository.local.RSA_OAEP_Encode(ctx, input)
	}

	reference, err := resolveAzureKeyReference(input.PublicKey)
	if err != nil {
		return "", err
	}
	client, _, err := newAzureKeysClient(ctx, reference.VaultURL)
	if err != nil {
		return "", err
	}

	response, err := client.Encrypt(ctx, reference.Name, reference.Version, azkeys.KeyOperationParameters{
		Algorithm: ptr(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     []byte(input.Text),
	}, nil)
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: encrypt with rsa-oaep-256: %w", err)
	}
	return base64.StdEncoding.EncodeToString(response.Result), nil
}

func (repository *asymmetricRepository) RSA_OAEP_Decode(ctx context.Context, input models.RSAOAEPDecodeRequest) (out string, err error) {
	end := trace.Start(ctx, "azure-key-vault/RSA_OAEP_Decode")
	defer end(err)
	if _, err := utilities.ParseRSAPrivateKeyFromBase64(input.PrivateKey); err == nil {
		return repository.local.RSA_OAEP_Decode(ctx, input)
	}

	reference, err := resolveAzureKeyReference(input.PrivateKey)
	if err != nil {
		return "", err
	}
	client, _, err := newAzureKeysClient(ctx, reference.VaultURL)
	if err != nil {
		return "", err
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(input.CipherText)
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: decode ciphertext: %w", err)
	}
	response, err := client.Decrypt(ctx, reference.Name, reference.Version, azkeys.KeyOperationParameters{
		Algorithm: ptr(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     cipherBytes,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: decrypt with rsa-oaep-256: %w", err)
	}
	return string(response.Result), nil
}

func (repository *signatureRepository) GenerateEd255Keys(ctx context.Context) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "azure-key-vault/GenerateEd255Keys")
	defer end(err)
	if ctx == nil {
		return nil, errors.New("context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errAzureEd25519Unsupported
}

func (repository *signatureRepository) SignEd25519(ctx context.Context, privateKey, text string) (out string, err error) {
	end := trace.Start(ctx, "azure-key-vault/SignEd25519")
	defer end(err)
	if _, err := utilities.ParseEd25519PrivateKeyFromBase64(privateKey); err == nil {
		return repository.local.SignEd25519(ctx, privateKey, text)
	}
	return "", errAzureEd25519Unsupported
}

func (repository *signatureRepository) VerifyEd25519(ctx context.Context, publicKey, text, signature string) (err error) {
	end := trace.Start(ctx, "azure-key-vault/VerifyEd25519")
	defer end(err)
	if _, err := utilities.ParseEd25519PublicKeyFromBase64(publicKey); err == nil {
		return repository.local.VerifyEd25519(ctx, publicKey, text, signature)
	}
	return errAzureEd25519Unsupported
}

func (repository *signatureRepository) SignRSAPSS(ctx context.Context, privateKey, text string) (out string, err error) {
	end := trace.Start(ctx, "azure-key-vault/SignRSAPSS")
	defer end(err)
	if _, err := utilities.ParseRSAPrivateKeyFromBase64(privateKey); err == nil {
		return repository.local.SignRSAPSS(ctx, privateKey, text)
	}

	reference, err := resolveAzureKeyReference(privateKey)
	if err != nil {
		return "", err
	}
	client, _, err := newAzureKeysClient(ctx, reference.VaultURL)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256([]byte(text))
	response, err := client.Sign(ctx, reference.Name, reference.Version, azkeys.SignParameters{
		Algorithm: ptr(azkeys.SignatureAlgorithmPS256),
		Value:     digest[:],
	}, nil)
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: sign rsa-pss-sha256: %w", err)
	}
	return base64.StdEncoding.EncodeToString(response.Result), nil
}

func (repository *signatureRepository) VerifyRSAPSS(ctx context.Context, publicKey, text, signature string) (err error) {
	end := trace.Start(ctx, "azure-key-vault/VerifyRSAPSS")
	defer end(err)
	if _, err := utilities.ParseRSAPublicKeyFromBase64(publicKey); err == nil {
		return repository.local.VerifyRSAPSS(ctx, publicKey, text, signature)
	}

	reference, err := resolveAzureKeyReference(publicKey)
	if err != nil {
		return err
	}
	client, _, err := newAzureKeysClient(ctx, reference.VaultURL)
	if err != nil {
		return err
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("azure-key-vault: decode signature from base64: %w", err)
	}
	digest := sha256.Sum256([]byte(text))
	response, err := client.Verify(ctx, reference.Name, reference.Version, azkeys.VerifyParameters{
		Algorithm: ptr(azkeys.SignatureAlgorithmPS256),
		Digest:    digest[:],
		Signature: signatureBytes,
	}, nil)
	if err != nil {
		return fmt.Errorf("azure-key-vault: verify rsa-pss-sha256: %w", err)
	}
	if !boolValue(response.Value) {
		return errors.New("azure-key-vault: invalid RSA-PSS signature")
	}
	return nil
}

func (repository *signatureRepository) Sign_RSA_PKCS1v15_SHA256(ctx context.Context, privateKey, data string) (out string, err error) {
	end := trace.Start(ctx, "azure-key-vault/Sign_RSA_PKCS1v15_SHA256")
	defer end(err)
	if privateKey != "" && !looksLikeAzureKeyReference(privateKey) {
		return repository.local.Sign_RSA_PKCS1v15_SHA256(ctx, privateKey, data)
	}

	reference, err := resolveAzureKeyReference(privateKey)
	if err != nil {
		return "", err
	}
	client, _, err := newAzureKeysClient(ctx, reference.VaultURL)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256([]byte(data))
	response, err := client.Sign(ctx, reference.Name, reference.Version, azkeys.SignParameters{
		Algorithm: ptr(azkeys.SignatureAlgorithmRS256),
		Value:     digest[:],
	}, nil)
	if err != nil {
		return "", fmt.Errorf("azure-key-vault: sign rsa-sha256: %w", err)
	}
	return base64.StdEncoding.EncodeToString(response.Result), nil
}

func (repository *signatureRepository) Verify_RSA_PKCS1v15_SHA256(ctx context.Context, data, publicKey string, signature string) (err error) {
	end := trace.Start(ctx, "azure-key-vault/Verify_RSA_PKCS1v15_SHA256")
	defer end(err)
	if publicKey != "" && !looksLikeAzureKeyReference(publicKey) {
		return repository.local.Verify_RSA_PKCS1v15_SHA256(ctx, data, publicKey, signature)
	}

	reference, err := resolveAzureKeyReference(publicKey)
	if err != nil {
		return err
	}
	client, _, err := newAzureKeysClient(ctx, reference.VaultURL)
	if err != nil {
		return err
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("azure-key-vault: decode signature from base64: %w", err)
	}
	digest := sha256.Sum256([]byte(data))
	response, err := client.Verify(ctx, reference.Name, reference.Version, azkeys.VerifyParameters{
		Algorithm: ptr(azkeys.SignatureAlgorithmRS256),
		Digest:    digest[:],
		Signature: signatureBytes,
	}, nil)
	if err != nil {
		return fmt.Errorf("azure-key-vault: verify rsa-sha256: %w", err)
	}
	if !boolValue(response.Value) {
		return errors.New("azure-key-vault: invalid RSA SHA-256 signature")
	}
	return nil
}

func newAzureKeysClient(_ context.Context, vaultURL string) (azureKeysClient, string, error) {
	resolvedVaultURL := strings.TrimSpace(vaultURL)
	if resolvedVaultURL == "" {
		var err error
		resolvedVaultURL, err = resolveAzureVaultURL()
		if err != nil {
			return nil, "", err
		}
	}

	credential, err := newAzureCredentialFn(nil)
	if err != nil {
		return nil, "", fmt.Errorf("azure-key-vault: create credential: %w", err)
	}
	client, err := newAzureClientFn(resolvedVaultURL, credential)
	if err != nil {
		return nil, "", fmt.Errorf("azure-key-vault: create client: %w", err)
	}
	return client, resolvedVaultURL, nil
}

func resolveAzureKeyReference(key string) (*azureKeyReference, error) {
	rawKey := strings.TrimSpace(key)
	if rawKey == "" {
		rawKey = configuredAzureKeyID()
	}
	if rawKey == "" {
		return nil, errAzureKeyIDRequired
	}

	parsed, err := url.Parse(rawKey)
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: parse key id: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("azure-key-vault: invalid key id %q", rawKey)
	}

	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(segments) < 2 || segments[0] != "keys" {
		return nil, fmt.Errorf("azure-key-vault: invalid key path %q", parsed.Path)
	}

	reference := &azureKeyReference{
		VaultURL: (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host}).String(),
		Name:     segments[1],
		KID:      rawKey,
	}
	if len(segments) > 2 {
		reference.Version = segments[2]
	}
	return reference, nil
}

func resolveAzureKeyLookupReference(key string) (*azureKeyReference, error) {
	rawKey := strings.TrimSpace(key)
	if rawKey == "" || strings.HasPrefix(rawKey, "https://") {
		return resolveAzureKeyReference(rawKey)
	}

	vaultURL, err := resolveAzureVaultURL()
	if err != nil {
		return nil, err
	}
	keyRef := strings.TrimRight(vaultURL, "/") + "/keys/" + url.PathEscape(rawKey)
	return &azureKeyReference{
		VaultURL: vaultURL,
		Name:     rawKey,
		KID:      keyRef,
	}, nil
}

func resolveAzureVaultURL() (string, error) {
	if configured := strings.TrimSpace(viper.GetString(defaultAzureVaultURLKey)); configured != "" {
		return configured, nil
	}
	if configured := strings.TrimSpace(viper.GetString(legacyAzureVaultURLKey)); configured != "" {
		return configured, nil
	}

	reference := configuredAzureKeyID()
	if reference == "" {
		return "", errAzureVaultURLRequired
	}
	parsed, err := resolveAzureKeyReference(reference)
	if err != nil {
		return "", err
	}
	return parsed.VaultURL, nil
}

func configuredAzureKeyID() string {
	if configured := strings.TrimSpace(viper.GetString(defaultAzureKeyIDKey)); configured != "" {
		return configured
	}
	return strings.TrimSpace(viper.GetString(legacyAzureKeyIDKey))
}

func azureRSAKeySize(size common.SizeAsymetrycKey) (int, error) {
	switch size {
	case common.Key2048Bits, common.Key3072Bits, common.Key4096Bits:
		return int(size), nil
	default:
		return 0, fmt.Errorf("azure-key-vault: unsupported rsa key size: %d", size)
	}
}

func azureECDHCurveName(curve common.CurveAsymmetricKey) (azkeys.CurveName, error) {
	switch curve {
	case common.CurveP256:
		return azkeys.CurveNameP256, nil
	case common.CurveP384:
		return azkeys.CurveNameP384, nil
	case common.CurveP521:
		return azkeys.CurveNameP521, nil
	default:
		return "", fmt.Errorf("azure-key-vault: unsupported ecdh curve: %q", curve)
	}
}

func azureMetadataFromBundle(bundle azkeys.KeyBundle, vaultURL, keyName string) (string, string, error) {
	if bundle.Key != nil && bundle.Key.KID != nil {
		keyRef := string(*bundle.Key.KID)
		return bundle.Key.KID.Name(), keyRef, nil
	}
	if strings.TrimSpace(vaultURL) == "" {
		return "", "", errors.New("azure-key-vault: missing key metadata from response")
	}
	keyRef := strings.TrimRight(vaultURL, "/") + "/keys/" + keyName
	return keyName, keyRef, nil
}

func azureKeyDataFromBundle(bundle azkeys.KeyBundle, vaultURL, keyName string) (*models.KeyData, error) {
	keyID, keyRef, err := azureMetadataFromBundle(bundle, vaultURL, keyName)
	if err != nil {
		return nil, err
	}

	keyData := &models.KeyData{
		KeyID:    keyID,
		KeyRef:   keyRef,
		Provider: azureProviderName,
	}
	if bundle.Key == nil {
		return keyData, nil
	}

	switch {
	case azureBundleHasRSAKey(bundle):
		publicKey, err := rsaPublicKeyFromAzureBundle(bundle)
		if err != nil {
			return nil, err
		}
		publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("azure-key-vault: marshal public key: %w", err)
		}
		keyData.PublicKey = base64.StdEncoding.EncodeToString(publicDER)
	case azureBundleHasECKey(bundle):
		publicKey, err := ecdhPublicKeyFromAzureBundle(bundle)
		if err != nil {
			return nil, err
		}
		publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("azure-key-vault: marshal ecdh public key: %w", err)
		}
		keyData.PublicKey = base64.StdEncoding.EncodeToString(publicDER)
	}
	return keyData, nil
}

func azureBundleHasRSAKey(bundle azkeys.KeyBundle) bool {
	if bundle.Key == nil {
		return false
	}
	if bundle.Key.Kty != nil && (*bundle.Key.Kty == azkeys.KeyTypeRSA || *bundle.Key.Kty == azkeys.KeyTypeRSAHSM) {
		return true
	}
	return len(bundle.Key.N) > 0 || len(bundle.Key.E) > 0
}

func azureBundleHasECKey(bundle azkeys.KeyBundle) bool {
	if bundle.Key == nil {
		return false
	}
	if bundle.Key.Kty != nil && (*bundle.Key.Kty == azkeys.KeyTypeEC || *bundle.Key.Kty == azkeys.KeyTypeECHSM) {
		return true
	}
	return bundle.Key.Crv != nil || len(bundle.Key.X) > 0 || len(bundle.Key.Y) > 0
}

func ecdhPublicKeyFromAzureBundle(bundle azkeys.KeyBundle) (*ecdh.PublicKey, error) {
	if bundle.Key == nil || bundle.Key.Crv == nil || len(bundle.Key.X) == 0 || len(bundle.Key.Y) == 0 {
		return nil, errors.New("azure-key-vault: missing ecdh public key material")
	}

	curve, coordinateSize, err := ecdhCurveFromAzureName(*bundle.Key.Crv)
	if err != nil {
		return nil, err
	}

	x, err := leftPadCoordinate(bundle.Key.X, coordinateSize)
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: invalid ecdh public key x coordinate: %w", err)
	}
	y, err := leftPadCoordinate(bundle.Key.Y, coordinateSize)
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: invalid ecdh public key y coordinate: %w", err)
	}

	sec1 := make([]byte, 1+len(x)+len(y))
	sec1[0] = 0x04
	copy(sec1[1:], x)
	copy(sec1[1+len(x):], y)

	publicKey, err := curve.NewPublicKey(sec1)
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: parse ecdh public key: %w", err)
	}
	return publicKey, nil
}

func azureECJWKFromPublicKeyDER(publicKeyDER []byte) (*azureECJWKPublic, error) {
	publicKeyAny, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return nil, fmt.Errorf("parse ecdh public key: %w", err)
	}

	switch publicKey := publicKeyAny.(type) {
	case *ecdh.PublicKey:
		curveName, coordinateSize, err := azureCurveNameFromECDH(publicKey.Curve())
		if err != nil {
			return nil, err
		}
		publicKeyBytes := publicKey.Bytes()
		if len(publicKeyBytes) != 1+2*coordinateSize || publicKeyBytes[0] != 0x04 {
			return nil, errors.New("invalid ECDH public key encoding")
		}

		return &azureECJWKPublic{
			KeyType: string(azkeys.KeyTypeEC),
			Curve:   string(curveName),
			X:       base64.RawURLEncoding.EncodeToString(publicKeyBytes[1 : 1+coordinateSize]),
			Y:       base64.RawURLEncoding.EncodeToString(publicKeyBytes[1+coordinateSize:]),
		}, nil
	case *ecdsa.PublicKey:
		curveName, coordinateSize, err := azureCurveNameFromECDSA(publicKey.Curve)
		if err != nil {
			return nil, err
		}
		x, err := leftPadCoordinate(publicKey.X.Bytes(), coordinateSize)
		if err != nil {
			return nil, fmt.Errorf("invalid ECDH public key x coordinate: %w", err)
		}
		y, err := leftPadCoordinate(publicKey.Y.Bytes(), coordinateSize)
		if err != nil {
			return nil, fmt.Errorf("invalid ECDH public key y coordinate: %w", err)
		}
		return &azureECJWKPublic{
			KeyType: string(azkeys.KeyTypeEC),
			Curve:   string(curveName),
			X:       base64.RawURLEncoding.EncodeToString(x),
			Y:       base64.RawURLEncoding.EncodeToString(y),
		}, nil
	default:
		return nil, errors.New("public key is not an ECDH key")
	}
}

func ecdhCurveFromAzureName(curve azkeys.CurveName) (ecdh.Curve, int, error) {
	switch curve {
	case azkeys.CurveNameP256:
		return ecdh.P256(), 32, nil
	case azkeys.CurveNameP384:
		return ecdh.P384(), 48, nil
	case azkeys.CurveNameP521:
		return ecdh.P521(), 66, nil
	default:
		return nil, 0, fmt.Errorf("azure-key-vault: unsupported ecdh curve: %q", curve)
	}
}

func azureCurveNameFromECDH(curve ecdh.Curve) (azkeys.CurveName, int, error) {
	switch curve {
	case ecdh.P256():
		return azkeys.CurveNameP256, 32, nil
	case ecdh.P384():
		return azkeys.CurveNameP384, 48, nil
	case ecdh.P521():
		return azkeys.CurveNameP521, 66, nil
	default:
		return "", 0, errors.New("unsupported ECDH curve")
	}
}

func azureCurveNameFromECDSA(curve elliptic.Curve) (azkeys.CurveName, int, error) {
	switch curve {
	case elliptic.P256():
		return azkeys.CurveNameP256, 32, nil
	case elliptic.P384():
		return azkeys.CurveNameP384, 48, nil
	case elliptic.P521():
		return azkeys.CurveNameP521, 66, nil
	default:
		return "", 0, errors.New("unsupported ECDH curve")
	}
}

func leftPadCoordinate(coordinate []byte, size int) ([]byte, error) {
	if len(coordinate) > size {
		return nil, fmt.Errorf("coordinate has %d bytes, max %d", len(coordinate), size)
	}
	padded := make([]byte, size)
	copy(padded[size-len(coordinate):], coordinate)
	return padded, nil
}

func (deriver *httpAzureECDHDeriver) DeriveSharedSecret(ctx context.Context, reference azureKeyReference, publicKeyDER []byte) ([]byte, error) {
	publicKey, err := azureECJWKFromPublicKeyDER(publicKeyDER)
	if err != nil {
		return nil, err
	}
	requestBody, err := json.Marshal(azureECDHDeriveRequest{
		Algorithm: "ECDH",
		Public:    *publicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("encode derivekey request: %w", err)
	}

	deriveURL := strings.TrimRight(reference.VaultURL, "/") + "/keys/" + url.PathEscape(reference.Name) + "/" + url.PathEscape(reference.Version) + "/derivekey?api-version=7.6"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, deriveURL, bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")

	token, err := deriver.credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://vault.azure.net/.default"},
	})
	if err != nil {
		return nil, fmt.Errorf("get access token: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token.Token)

	response, err := deriver.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read derivekey response: %w", err)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("derivekey returned status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}

	var result azureECDHDeriveResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode derivekey response: %w", err)
	}
	if strings.TrimSpace(result.Value) == "" {
		return nil, errors.New("derivekey response missing shared secret")
	}
	sharedSecret, err := decodeAzureBase64URL(result.Value)
	if err != nil {
		return nil, fmt.Errorf("decode derivekey shared secret: %w", err)
	}
	return sharedSecret, nil
}

func decodeAzureBase64URL(value string) ([]byte, error) {
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.URLEncoding.DecodeString(value)
}

func rsaPublicKeyFromAzureBundle(bundle azkeys.KeyBundle) (*rsa.PublicKey, error) {
	if bundle.Key == nil || len(bundle.Key.N) == 0 || len(bundle.Key.E) == 0 {
		return nil, errors.New("azure-key-vault: missing rsa public key material")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(bundle.Key.N),
		E: int(new(big.Int).SetBytes(bundle.Key.E).Int64()),
	}, nil
}

func looksLikeAzureKeyReference(key string) bool {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return configuredAzureKeyID() != ""
	}
	return strings.HasPrefix(trimmed, "https://") && strings.Contains(trimmed, "/keys/")
}

func azureUIDTags(uid string) map[string]*string {
	if strings.TrimSpace(uid) == "" {
		return nil
	}
	return map[string]*string{"uid": ptr(uid)}
}

func azureAuthenticatedData(uid string, additional *string) []byte {
	if strings.TrimSpace(uid) == "" {
		return utilities.BytesFromOptionalString(additional)
	}
	if additional == nil {
		return []byte(uid)
	}
	return []byte(uid + "\x00" + *additional)
}

func boolValue(value *bool) bool {
	return value != nil && *value
}

func ptr[T any](value T) *T {
	return &value
}
