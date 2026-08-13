// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package awskms

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/internal/trace"
	"github.com/PointerByte/forge-go/encrypt/local"
	"github.com/PointerByte/forge-go/encrypt/models"
	"github.com/PointerByte/forge-go/encrypt/utilities"
	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	kms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/spf13/viper"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-sdk-go-v2/otelaws"
)

const (
	defaultKMSARNKey = "encrypt.vault.aws-kms.arn"
	awsProviderName  = "aws-kms"
)

var (
	errAWSKMSKeyARNRequired = errors.New("aws-kms: key arn or id is required")
	loadDefaultAWSConfigFn  = awsconfig.LoadDefaultConfig
	appendOTelMiddlewaresFn = otelaws.AppendMiddlewares
	loadAWSConfigFn         = loadAWSConfig
	newKMSClientFn          = func(cfg sdkaws.Config) kmsClient {
		return kms.NewFromConfig(cfg)
	}
)

type kmsClient interface {
	CreateKey(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	DeriveSharedSecret(ctx context.Context, params *kms.DeriveSharedSecretInput, optFns ...func(*kms.Options)) (*kms.DeriveSharedSecretOutput, error)
	DisableKey(ctx context.Context, params *kms.DisableKeyInput, optFns ...func(*kms.Options)) (*kms.DisableKeyOutput, error)
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
	GenerateMac(ctx context.Context, params *kms.GenerateMacInput, optFns ...func(*kms.Options)) (*kms.GenerateMacOutput, error)
	RotateKeyOnDemand(ctx context.Context, params *kms.RotateKeyOnDemandInput, optFns ...func(*kms.Options)) (*kms.RotateKeyOnDemandOutput, error)
	VerifyMac(ctx context.Context, params *kms.VerifyMacInput, optFns ...func(*kms.Options)) (*kms.VerifyMacOutput, error)
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
}

type symmetricRepository struct{ local local.SymmetricRepository }
type keyRepository struct{}
type hashRepository struct{ local local.HashRepository }

type asymmetricRepository struct {
	local local.AsymmetricRepository
}

type signatureRepository struct {
	local local.SignatureRepository
}

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
	return &asymmetricRepository{
		local: local.NewAsymmetricRepository(),
	}
}

func NewSignatureRepository() SignatureRepository {
	return &signatureRepository{
		local: local.NewSignatureRepository(),
	}
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
	end := trace.Start(ctx, "aws-kms/GenerateSymetrycKeys")
	defer end(err)
	keySpec, err := toAWSSymmetricKeySpec(input.Size)
	if err != nil {
		return nil, err
	}

	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.CreateKey(ctx, &kms.CreateKeyInput{
		KeyUsage: types.KeyUsageTypeEncryptDecrypt,
		KeySpec:  keySpec,
		Origin:   types.OriginTypeAwsKms,
		Tags:     awsUIDTags(input.UID),
	})
	if err != nil {
		return nil, fmt.Errorf("aws-kms: create symmetric key: %w", err)
	}
	if output.KeyMetadata == nil || output.KeyMetadata.KeyId == nil || output.KeyMetadata.Arn == nil {
		return nil, errors.New("aws-kms: missing key metadata from create symmetric key response")
	}

	keyID := sdkaws.ToString(output.KeyMetadata.KeyId)
	keyRef := sdkaws.ToString(output.KeyMetadata.Arn)

	return &models.KeyData{
		KeyID:    keyID,
		KeyRef:   keyRef,
		Provider: awsProviderName,
	}, nil
}

func (repository *keyRepository) RotateKey(ctx context.Context, input models.RotateKeyRequest) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "aws-kms/RotateKey")
	defer end(err)
	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return nil, err
	}

	keyID, err := resolveAWSKMSKeyID(input.KeyID)
	if err != nil {
		return nil, err
	}

	describeOutput, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: sdkaws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("aws-kms: describe key before rotation: %w", err)
	}
	if describeOutput.KeyMetadata == nil {
		return nil, errors.New("aws-kms: missing key metadata from describe key response")
	}
	if describeOutput.KeyMetadata.KeyUsage != types.KeyUsageTypeEncryptDecrypt ||
		describeOutput.KeyMetadata.KeySpec != types.KeySpecSymmetricDefault {
		return nil, errors.New("aws-kms: key rotation is supported only for symmetric encryption keys")
	}

	if _, err := client.RotateKeyOnDemand(ctx, &kms.RotateKeyOnDemandInput{KeyId: sdkaws.String(keyID)}); err != nil {
		return nil, fmt.Errorf("aws-kms: rotate key: %w", err)
	}

	return awsKeyDataFromDescribe(ctx, client, keyID)
}

func (repository *keyRepository) GetKey(ctx context.Context, input models.GetKeyRequest) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "aws-kms/GetKey")
	defer end(err)
	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return nil, err
	}

	keyID, err := resolveAWSKMSKeyID(input.KeyID)
	if err != nil {
		return nil, err
	}

	return awsKeyDataFromDescribe(ctx, client, keyID)
}

func (repository *keyRepository) DeactivateKey(ctx context.Context, input models.DeactivateKeyRequest) (err error) {
	end := trace.Start(ctx, "aws-kms/DeactivateKey")
	defer end(err)
	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return err
	}

	keyID, err := resolveAWSKMSKeyID(input.KeyID)
	if err != nil {
		return err
	}

	if _, err := client.DisableKey(ctx, &kms.DisableKeyInput{KeyId: sdkaws.String(keyID)}); err != nil {
		return fmt.Errorf("aws-kms: deactivate key: %w", err)
	}
	return nil
}

func (repository *symmetricRepository) EncryptAES(ctx context.Context, input models.EncryptAESRequest) (out string, err error) {
	end := trace.Start(ctx, "aws-kms/EncryptAES")
	defer end(err)
	if utilities.IsLocalAESKey(input.SecretKey) {
		return repository.local.EncryptAES(ctx, input)
	}

	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return "", err
	}

	keyID, err := resolveAWSKMSKeyID(input.SecretKey)
	if err != nil {
		return "", err
	}

	encryptInput := &kms.EncryptInput{
		KeyId:     sdkaws.String(keyID),
		Plaintext: []byte(input.Value),
	}
	if encryptionContext := awsKMSEncryptionContext(input.UID, input.Additional); len(encryptionContext) > 0 {
		encryptInput.EncryptionContext = encryptionContext
	}

	output, err := client.Encrypt(ctx, encryptInput)
	if err != nil {
		return "", fmt.Errorf("aws-kms: encrypt with symmetric key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(output.CiphertextBlob), nil
}

func (repository *symmetricRepository) DecryptAES(ctx context.Context, input models.DecryptAESRequest) (out string, err error) {
	end := trace.Start(ctx, "aws-kms/DecryptAES")
	defer end(err)
	if utilities.IsLocalAESKey(input.SecretKey) {
		return repository.local.DecryptAES(ctx, input)
	}

	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return "", err
	}

	keyID, err := resolveAWSKMSKeyID(input.SecretKey)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(input.CipherValue)
	if err != nil {
		return "", fmt.Errorf("aws-kms: decode base64 ciphertext: %w", err)
	}

	decryptInput := &kms.DecryptInput{
		KeyId:          sdkaws.String(keyID),
		CiphertextBlob: ciphertext,
	}
	if encryptionContext := awsKMSEncryptionContext(input.UID, input.Additional); len(encryptionContext) > 0 {
		decryptInput.EncryptionContext = encryptionContext
	}

	output, err := client.Decrypt(ctx, decryptInput)
	if err != nil {
		return "", fmt.Errorf("aws-kms: decrypt with symmetric key: %w", err)
	}
	return string(output.Plaintext), nil
}

func (repository *hashRepository) HMAC(ctx context.Context, secretKey, message string) string {
	defer trace.Start(ctx, "aws-kms/HMAC")(nil)
	if !looksLikeAWSKMSKeyReference(secretKey) {
		return repository.local.HMAC(ctx, secretKey, message)
	}

	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return ""
	}

	keyID, err := resolveAWSKMSKeyID(secretKey)
	if err != nil {
		return ""
	}

	output, err := client.GenerateMac(ctx, &kms.GenerateMacInput{
		KeyId:        sdkaws.String(keyID),
		Message:      []byte(message),
		MacAlgorithm: types.MacAlgorithmSpecHmacSha256,
	})
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(output.Mac)
}

func (repository *hashRepository) Sha256Hex(ctx context.Context, message string) string {
	defer trace.Start(ctx, "aws-kms/Sha256Hex")(nil)
	return repository.local.Sha256Hex(ctx, message)
}

func (repository *hashRepository) Blake3(ctx context.Context, message string) string {
	defer trace.Start(ctx, "aws-kms/Blake3")(nil)
	return repository.local.Blake3(ctx, message)
}

func (repository *asymmetricRepository) GenerateECDHCurveKeys(ctx context.Context, input models.GenerateECDHCurveKeyRequest) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "aws-kms/GenerateECDHCurveKeys")
	defer end(err)
	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return nil, err
	}

	keySpec, err := toAWSECCKeySpec(input.Curve)
	if err != nil {
		return nil, err
	}

	output, err := client.CreateKey(ctx, &kms.CreateKeyInput{
		KeyUsage: types.KeyUsageTypeKeyAgreement,
		KeySpec:  keySpec,
		Origin:   types.OriginTypeAwsKms,
		Tags:     awsUIDTags(input.UID),
	})
	if err != nil {
		return nil, fmt.Errorf("aws-kms: create ecc key: %w", err)
	}
	if output.KeyMetadata == nil || output.KeyMetadata.KeyId == nil || output.KeyMetadata.Arn == nil {
		return nil, errors.New("aws-kms: missing key metadata from create ecc key response")
	}

	publicKeyOutput, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: output.KeyMetadata.KeyId})
	if err != nil {
		return nil, fmt.Errorf("aws-kms: get ecc public key: %w", err)
	}

	return &models.KeyData{
		PublicKey: base64.StdEncoding.EncodeToString(publicKeyOutput.PublicKey),
		KeyID:     sdkaws.ToString(output.KeyMetadata.KeyId),
		KeyRef:    sdkaws.ToString(output.KeyMetadata.Arn),
		Provider:  awsProviderName,
	}, nil
}

func (repository *asymmetricRepository) ECDH_Encode(ctx context.Context, input models.ECDHEncodeRequest) (out string, err error) {
	end := trace.Start(ctx, "aws-kms/ECDH_Encode")
	defer end(err)
	if _, err := utilities.ParseECDHPublicKeyFromBase64(input.PublicKey); err == nil {
		return repository.local.ECDH_Encode(ctx, input)
	}

	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return "", err
	}

	keyID, err := resolveAWSKMSKeyID(input.PublicKey)
	if err != nil {
		return "", err
	}

	publicKeyOutput, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: sdkaws.String(keyID)})
	if err != nil {
		return "", fmt.Errorf("aws-kms: get ecc public key: %w", err)
	}

	return repository.local.ECDH_Encode(ctx, models.ECDHEncodeRequest{
		UID:       input.UID,
		PublicKey: base64.StdEncoding.EncodeToString(publicKeyOutput.PublicKey),
		Text:      input.Text,
	})
}

func (repository *asymmetricRepository) ECDH_Decode(ctx context.Context, input models.ECDHDecodeRequest) (out string, err error) {
	end := trace.Start(ctx, "aws-kms/ECDH_Decode")
	defer end(err)
	if _, err := utilities.ParseECDHPrivateKeyFromBase64(input.PrivateKey); err == nil {
		return repository.local.ECDH_Decode(ctx, input)
	}

	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return "", err
	}

	keyID, err := resolveAWSKMSKeyID(input.PrivateKey)
	if err != nil {
		return "", err
	}

	payload, err := utilities.DecodeECCCipherPayload(input.CipherText)
	if err != nil {
		return "", err
	}

	ephemeralPublicKeyDER, err := base64.StdEncoding.DecodeString(payload.EphemeralPublicKey)
	if err != nil {
		return "", fmt.Errorf("aws-kms: decode ephemeral public key: %w", err)
	}

	sharedSecretOutput, err := client.DeriveSharedSecret(ctx, &kms.DeriveSharedSecretInput{
		KeyAgreementAlgorithm: types.KeyAgreementAlgorithmSpecEcdh,
		KeyId:                 sdkaws.String(keyID),
		PublicKey:             ephemeralPublicKeyDER,
	})
	if err != nil {
		return "", fmt.Errorf("aws-kms: derive shared secret: %w", err)
	}

	derivedKey, err := utilities.DeriveECCAESKey(sharedSecretOutput.SharedSecret, payload.Curve)
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
	end := trace.Start(ctx, "aws-kms/GenerateRSAKeys")
	defer end(err)
	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return nil, err
	}

	keySpec, err := toAWSRSAKeySpec(input.Size)
	if err != nil {
		return nil, err
	}

	output, err := client.CreateKey(ctx, &kms.CreateKeyInput{
		KeyUsage: types.KeyUsageTypeEncryptDecrypt,
		KeySpec:  keySpec,
		Tags:     awsUIDTags(input.UID),
	})
	if err != nil {
		return nil, fmt.Errorf("aws-kms: create rsa key: %w", err)
	}
	if output.KeyMetadata == nil || output.KeyMetadata.KeyId == nil || output.KeyMetadata.Arn == nil {
		return nil, errors.New("aws-kms: missing key metadata from create key response")
	}

	publicKeyOutput, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: output.KeyMetadata.KeyId,
	})
	if err != nil {
		return nil, fmt.Errorf("aws-kms: get public key: %w", err)
	}

	keyID := sdkaws.ToString(output.KeyMetadata.KeyId)
	keyRef := sdkaws.ToString(output.KeyMetadata.Arn)
	publicKey := base64.StdEncoding.EncodeToString(publicKeyOutput.PublicKey)
	return &models.KeyData{
		PublicKey: publicKey,
		KeyID:     keyID,
		KeyRef:    keyRef,
		Provider:  awsProviderName,
	}, nil
}

func (repository *asymmetricRepository) RSA_OAEP_Encode(ctx context.Context, input models.RSAOAEPEncodeRequest) (out string, err error) {
	end := trace.Start(ctx, "aws-kms/RSA_OAEP_Encode")
	defer end(err)
	if _, err := utilities.ParseRSAPublicKeyFromBase64(input.PublicKey); err == nil {
		return repository.local.RSA_OAEP_Encode(ctx, input)
	}

	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return "", err
	}

	keyID, err := resolveAWSKMSKeyID(input.PublicKey)
	if err != nil {
		return "", err
	}

	output, err := client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:               sdkaws.String(keyID),
		Plaintext:           []byte(input.Text),
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
	})
	if err != nil {
		return "", fmt.Errorf("aws-kms: encrypt with rsa-oaep-sha256: %w", err)
	}
	return base64.StdEncoding.EncodeToString(output.CiphertextBlob), nil
}

func (repository *asymmetricRepository) RSA_OAEP_Decode(ctx context.Context, input models.RSAOAEPDecodeRequest) (out string, err error) {
	end := trace.Start(ctx, "aws-kms/RSA_OAEP_Decode")
	defer end(err)
	if _, err := utilities.ParseRSAPrivateKeyFromBase64(input.PrivateKey); err == nil {
		return repository.local.RSA_OAEP_Decode(ctx, input)
	}

	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return "", err
	}

	keyID, err := resolveAWSKMSKeyID(input.PrivateKey)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(input.CipherText)
	if err != nil {
		return "", fmt.Errorf("aws-kms: decode base64 ciphertext: %w", err)
	}

	output, err := client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:               sdkaws.String(keyID),
		CiphertextBlob:      ciphertext,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
	})
	if err != nil {
		return "", fmt.Errorf("aws-kms: decrypt with rsa-oaep-sha256: %w", err)
	}
	return string(output.Plaintext), nil
}

func (repository *signatureRepository) GenerateEd255Keys(ctx context.Context) (data *models.KeyData, err error) {
	end := trace.Start(ctx, "aws-kms/GenerateEd255Keys")
	defer end(err)
	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.CreateKey(ctx, &kms.CreateKeyInput{
		KeyUsage: types.KeyUsageTypeSignVerify,
		KeySpec:  types.KeySpecEccNistEdwards25519,
		Origin:   types.OriginTypeAwsKms,
	})
	if err != nil {
		return nil, fmt.Errorf("aws-kms: create ed25519 key: %w", err)
	}
	if output.KeyMetadata == nil || output.KeyMetadata.KeyId == nil || output.KeyMetadata.Arn == nil {
		return nil, errors.New("aws-kms: missing key metadata from create ed25519 key response")
	}

	publicKeyOutput, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: output.KeyMetadata.KeyId,
	})
	if err != nil {
		return nil, fmt.Errorf("aws-kms: get ed25519 public key: %w", err)
	}

	keyID := sdkaws.ToString(output.KeyMetadata.KeyId)
	keyRef := sdkaws.ToString(output.KeyMetadata.Arn)
	publicKey := base64.StdEncoding.EncodeToString(publicKeyOutput.PublicKey)
	return &models.KeyData{
		PublicKey: publicKey,
		KeyID:     keyID,
		KeyRef:    keyRef,
		Provider:  awsProviderName,
	}, nil
}

func (repository *signatureRepository) SignEd25519(ctx context.Context, privateKey, text string) (out string, err error) {
	end := trace.Start(ctx, "aws-kms/SignEd25519")
	defer end(err)
	if _, err := utilities.ParseEd25519PrivateKeyFromBase64(privateKey); err == nil {
		return repository.local.SignEd25519(ctx, privateKey, text)
	}

	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return "", err
	}

	keyID, err := resolveAWSKMSKeyID(privateKey)
	if err != nil {
		return "", err
	}

	output, err := client.Sign(ctx, &kms.SignInput{
		KeyId:            sdkaws.String(keyID),
		Message:          []byte(text),
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512,
	})
	if err != nil {
		return "", fmt.Errorf("aws-kms: sign ed25519: %w", err)
	}
	return base64.StdEncoding.EncodeToString(output.Signature), nil
}

func (repository *signatureRepository) VerifyEd25519(ctx context.Context, publicKey, text, signature string) (err error) {
	end := trace.Start(ctx, "aws-kms/VerifyEd25519")
	defer end(err)
	if _, err := utilities.ParseEd25519PublicKeyFromBase64(publicKey); err == nil {
		return repository.local.VerifyEd25519(ctx, publicKey, text, signature)
	}

	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return err
	}

	keyID, err := resolveAWSKMSKeyID(publicKey)
	if err != nil {
		return err
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("aws-kms: decode signature from base64: %w", err)
	}

	output, err := client.Verify(ctx, &kms.VerifyInput{
		KeyId:            sdkaws.String(keyID),
		Message:          []byte(text),
		MessageType:      types.MessageTypeRaw,
		Signature:        signatureBytes,
		SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512,
	})
	if err != nil {
		return fmt.Errorf("aws-kms: verify ed25519: %w", err)
	}
	if !output.SignatureValid {
		return errors.New("aws-kms: invalid Ed25519 signature")
	}
	return nil
}

func (repository *signatureRepository) SignRSAPSS(ctx context.Context, privateKey, text string) (out string, err error) {
	end := trace.Start(ctx, "aws-kms/SignRSAPSS")
	defer end(err)
	if _, err := utilities.ParseRSAPrivateKeyFromBase64(privateKey); err == nil {
		return repository.local.SignRSAPSS(ctx, privateKey, text)
	}

	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return "", err
	}

	keyID, err := resolveAWSKMSKeyID(privateKey)
	if err != nil {
		return "", err
	}

	output, err := client.Sign(ctx, &kms.SignInput{
		KeyId:            sdkaws.String(keyID),
		Message:          []byte(text),
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPssSha256,
	})
	if err != nil {
		return "", fmt.Errorf("aws-kms: sign rsa-pss-sha256: %w", err)
	}
	return base64.StdEncoding.EncodeToString(output.Signature), nil
}

func (repository *signatureRepository) VerifyRSAPSS(ctx context.Context, publicKey, text, signature string) (err error) {
	end := trace.Start(ctx, "aws-kms/VerifyRSAPSS")
	defer end(err)
	if _, err := utilities.ParseRSAPublicKeyFromBase64(publicKey); err == nil {
		return repository.local.VerifyRSAPSS(ctx, publicKey, text, signature)
	}

	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return err
	}

	keyID, err := resolveAWSKMSKeyID(publicKey)
	if err != nil {
		return err
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("aws-kms: decode signature from base64: %w", err)
	}

	output, err := client.Verify(ctx, &kms.VerifyInput{
		KeyId:            sdkaws.String(keyID),
		Message:          []byte(text),
		MessageType:      types.MessageTypeRaw,
		Signature:        signatureBytes,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPssSha256,
	})
	if err != nil {
		return fmt.Errorf("aws-kms: verify rsa-pss-sha256: %w", err)
	}
	if !output.SignatureValid {
		return errors.New("aws-kms: invalid RSA-PSS signature")
	}
	return nil
}

func (repository *signatureRepository) Sign_RSA_PKCS1v15_SHA256(ctx context.Context, privateKey, data string) (out string, err error) {
	end := trace.Start(ctx, "aws-kms/Sign_RSA_PKCS1v15_SHA256")
	defer end(err)
	if privateKey != "" && !looksLikeAWSKMSKeyReference(privateKey) {
		return repository.local.Sign_RSA_PKCS1v15_SHA256(ctx, privateKey, data)
	}

	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return "", err
	}

	keyID, err := resolveAWSKMSKeyID(privateKey)
	if err != nil {
		return "", err
	}

	output, err := client.Sign(ctx, &kms.SignInput{
		KeyId:            sdkaws.String(keyID),
		Message:          []byte(data),
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return "", fmt.Errorf("aws-kms: sign rsa-pkcs1v15-sha256: %w", err)
	}
	return base64.StdEncoding.EncodeToString(output.Signature), nil
}

func (repository *signatureRepository) Verify_RSA_PKCS1v15_SHA256(ctx context.Context, data, publicKey string, signature string) (err error) {
	end := trace.Start(ctx, "aws-kms/Verify_RSA_PKCS1v15_SHA256")
	defer end(err)
	if publicKey != "" && !looksLikeAWSKMSKeyReference(publicKey) {
		return repository.local.Verify_RSA_PKCS1v15_SHA256(ctx, data, publicKey, signature)
	}

	client, err := newAWSKMSClient(ctx)
	if err != nil {
		return err
	}

	keyID, err := resolveAWSKMSKeyID(publicKey)
	if err != nil {
		return err
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("aws-kms: decode signature from base64: %w", err)
	}

	output, err := client.Verify(ctx, &kms.VerifyInput{
		KeyId:            sdkaws.String(keyID),
		Message:          []byte(data),
		MessageType:      types.MessageTypeRaw,
		Signature:        signatureBytes,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return fmt.Errorf("aws-kms: verify rsa-pkcs1v15-sha256: %w", err)
	}
	if !output.SignatureValid {
		return errors.New("aws-kms: invalid RSA SHA-256 signature")
	}
	return nil
}

func newAWSKMSClient(ctx context.Context) (kmsClient, error) {
	cfg, err := loadAWSConfigFn(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws-kms: load aws config: %w", err)
	}
	return newKMSClientFn(cfg), nil
}

func loadAWSConfig(ctx context.Context) (sdkaws.Config, error) {
	cfg, err := loadDefaultAWSConfigFn(ctx)
	if err != nil {
		return cfg, err
	}
	appendOTelMiddlewaresFn(&cfg.APIOptions)
	return cfg, nil
}

func resolveAWSKMSKeyID(key string) (string, error) {
	if trimmed := strings.TrimSpace(key); trimmed != "" {
		return trimmed, nil
	}
	if configured := strings.TrimSpace(viper.GetString(defaultKMSARNKey)); configured != "" {
		return configured, nil
	}
	return "", errAWSKMSKeyARNRequired
}

func awsUIDTags(uid string) []types.Tag {
	if strings.TrimSpace(uid) == "" {
		return nil
	}
	return []types.Tag{{
		TagKey:   sdkaws.String("uid"),
		TagValue: sdkaws.String(uid),
	}}
}

func awsKMSEncryptionContext(uid string, additional *string) map[string]string {
	context := make(map[string]string, 2)
	if strings.TrimSpace(uid) != "" {
		context["uid"] = uid
	}
	if additional != nil {
		context["additional"] = *additional
	}
	if len(context) == 0 {
		return nil
	}
	return context
}

func awsKeyDataFromDescribe(ctx context.Context, client kmsClient, keyID string) (*models.KeyData, error) {
	output, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: sdkaws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("aws-kms: describe key: %w", err)
	}
	return awsKeyDataFromMetadata(ctx, client, output.KeyMetadata)
}

func awsKeyDataFromMetadata(ctx context.Context, client kmsClient, metadata *types.KeyMetadata) (*models.KeyData, error) {
	if metadata == nil || metadata.KeyId == nil {
		return nil, errors.New("aws-kms: missing key metadata from describe key response")
	}

	keyID := sdkaws.ToString(metadata.KeyId)
	keyRef := sdkaws.ToString(metadata.Arn)
	if keyRef == "" {
		keyRef = keyID
	}

	keyData := &models.KeyData{
		KeyID:    keyID,
		KeyRef:   keyRef,
		Provider: awsProviderName,
	}
	if !awsKeySpecHasPublicKey(metadata.KeySpec) {
		return keyData, nil
	}

	publicKeyOutput, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: sdkaws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("aws-kms: get public key: %w", err)
	}
	keyData.PublicKey = base64.StdEncoding.EncodeToString(publicKeyOutput.PublicKey)
	return keyData, nil
}

func awsKeySpecHasPublicKey(keySpec types.KeySpec) bool {
	switch keySpec {
	case types.KeySpecRsa2048,
		types.KeySpecRsa3072,
		types.KeySpecRsa4096,
		types.KeySpecEccNistP256,
		types.KeySpecEccNistP384,
		types.KeySpecEccNistP521,
		types.KeySpecEccNistEdwards25519:
		return true
	default:
		return false
	}
}

func toAWSRSAKeySpec(size common.SizeAsymetrycKey) (types.KeySpec, error) {
	switch size {
	case common.Key2048Bits:
		return types.KeySpecRsa2048, nil
	case common.Key3072Bits:
		return types.KeySpecRsa3072, nil
	case common.Key4096Bits:
		return types.KeySpecRsa4096, nil
	default:
		return "", fmt.Errorf("aws-kms: unsupported rsa key size: %d", size)
	}
}

func toAWSECCKeySpec(curve common.CurveAsymmetricKey) (types.KeySpec, error) {
	switch curve {
	case common.CurveP256:
		return types.KeySpecEccNistP256, nil
	case common.CurveP384:
		return types.KeySpecEccNistP384, nil
	case common.CurveP521:
		return types.KeySpecEccNistP521, nil
	default:
		return "", fmt.Errorf("aws-kms: unsupported ecc curve: %q", curve)
	}
}

func toAWSSymmetricKeySpec(size common.SizeSymetrycKey) (types.KeySpec, error) {
	switch size {
	case common.Key256Bits:
		return types.KeySpecSymmetricDefault, nil
	default:
		return "", fmt.Errorf("aws-kms: unsupported symmetric key size: %d", size)
	}
}

func looksLikeAWSKMSKeyReference(key string) bool {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return strings.TrimSpace(viper.GetString(defaultKMSARNKey)) != ""
	}
	return strings.HasPrefix(trimmed, "arn:aws:kms:") ||
		strings.HasPrefix(trimmed, "alias/") ||
		strings.HasPrefix(trimmed, "mrk-") ||
		strings.Count(trimmed, "-") >= 4
}
