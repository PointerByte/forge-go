// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package awskms

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/PointerByte/forge-go/encrypt/common"
	"github.com/PointerByte/forge-go/encrypt/local"
	"github.com/PointerByte/forge-go/encrypt/models"
	"github.com/PointerByte/forge-go/encrypt/utilities"
	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	kms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/spf13/viper"
)

type fakeKMSClient struct {
	createKeyFn          func(context.Context, *kms.CreateKeyInput, ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	describeKeyFn        func(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	deriveSharedSecretFn func(context.Context, *kms.DeriveSharedSecretInput, ...func(*kms.Options)) (*kms.DeriveSharedSecretOutput, error)
	disableKeyFn         func(context.Context, *kms.DisableKeyInput, ...func(*kms.Options)) (*kms.DisableKeyOutput, error)
	getPublicKeyFn       func(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	encryptFn            func(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error)
	decryptFn            func(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
	generateMacFn        func(context.Context, *kms.GenerateMacInput, ...func(*kms.Options)) (*kms.GenerateMacOutput, error)
	rotateKeyOnDemandFn  func(context.Context, *kms.RotateKeyOnDemandInput, ...func(*kms.Options)) (*kms.RotateKeyOnDemandOutput, error)
	verifyMacFn          func(context.Context, *kms.VerifyMacInput, ...func(*kms.Options)) (*kms.VerifyMacOutput, error)
	signFn               func(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
	verifyFn             func(context.Context, *kms.VerifyInput, ...func(*kms.Options)) (*kms.VerifyOutput, error)
}

var testContext = context.Background()

func (fake fakeKMSClient) CreateKey(ctx context.Context, in *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	return fake.createKeyFn(ctx, in, optFns...)
}
func (fake fakeKMSClient) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if fake.describeKeyFn == nil {
		return nil, errors.New("describe key not implemented")
	}
	return fake.describeKeyFn(ctx, in, optFns...)
}
func (fake fakeKMSClient) DeriveSharedSecret(ctx context.Context, in *kms.DeriveSharedSecretInput, optFns ...func(*kms.Options)) (*kms.DeriveSharedSecretOutput, error) {
	if fake.deriveSharedSecretFn == nil {
		return nil, errors.New("derive shared secret not implemented")
	}
	return fake.deriveSharedSecretFn(ctx, in, optFns...)
}
func (fake fakeKMSClient) DisableKey(ctx context.Context, in *kms.DisableKeyInput, optFns ...func(*kms.Options)) (*kms.DisableKeyOutput, error) {
	if fake.disableKeyFn == nil {
		return nil, errors.New("disable key not implemented")
	}
	return fake.disableKeyFn(ctx, in, optFns...)
}
func (fake fakeKMSClient) GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return fake.getPublicKeyFn(ctx, in, optFns...)
}
func (fake fakeKMSClient) Encrypt(ctx context.Context, in *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	return fake.encryptFn(ctx, in, optFns...)
}
func (fake fakeKMSClient) Decrypt(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	return fake.decryptFn(ctx, in, optFns...)
}
func (fake fakeKMSClient) GenerateMac(ctx context.Context, in *kms.GenerateMacInput, optFns ...func(*kms.Options)) (*kms.GenerateMacOutput, error) {
	return fake.generateMacFn(ctx, in, optFns...)
}
func (fake fakeKMSClient) RotateKeyOnDemand(ctx context.Context, in *kms.RotateKeyOnDemandInput, optFns ...func(*kms.Options)) (*kms.RotateKeyOnDemandOutput, error) {
	if fake.rotateKeyOnDemandFn == nil {
		return nil, errors.New("rotate key not implemented")
	}
	return fake.rotateKeyOnDemandFn(ctx, in, optFns...)
}
func (fake fakeKMSClient) VerifyMac(ctx context.Context, in *kms.VerifyMacInput, optFns ...func(*kms.Options)) (*kms.VerifyMacOutput, error) {
	return fake.verifyMacFn(ctx, in, optFns...)
}
func (fake fakeKMSClient) Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	return fake.signFn(ctx, in, optFns...)
}
func (fake fakeKMSClient) Verify(ctx context.Context, in *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	return fake.verifyFn(ctx, in, optFns...)
}

func TestNewRepositoryBuildsAllRepositories(t *testing.T) {
	repository := NewRepository()
	if repository.SymmetricRepository == nil || repository.AsymmetricRepository == nil || repository.KeyRepository == nil || repository.SignatureRepository == nil || repository.HashRepository == nil {
		t.Fatal("expected all repositories to be initialized")
	}
}

func TestUIDMetadataHelpers(t *testing.T) {
	if tags := awsUIDTags(""); tags != nil {
		t.Fatalf("awsUIDTags() = %#v, want nil", tags)
	}
	tags := awsUIDTags("user-123")
	if len(tags) != 1 || sdkaws.ToString(tags[0].TagKey) != "uid" || sdkaws.ToString(tags[0].TagValue) != "user-123" {
		t.Fatalf("awsUIDTags() = %#v, want uid tag", tags)
	}

	additional := "aad"
	encryptionContext := awsKMSEncryptionContext("user-123", &additional)
	if encryptionContext["uid"] != "user-123" || encryptionContext["additional"] != "aad" {
		t.Fatalf("awsKMSEncryptionContext() = %#v, want uid and additional", encryptionContext)
	}
}

func TestKeyRepositoryRotateAndGetKey(t *testing.T) {
	t.Cleanup(viper.Reset)
	previousLoad := loadAWSConfigFn
	previousClient := newKMSClientFn
	t.Cleanup(func() {
		loadAWSConfigFn = previousLoad
		newKMSClientFn = previousClient
	})

	publicDER, err := x509.MarshalPKIXPublicKey(&mustRSAKey(t).PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}

	rotated := false
	deactivated := false
	loadAWSConfigFn = func(context.Context) (sdkaws.Config, error) { return sdkaws.Config{}, nil }
	newKMSClientFn = func(sdkaws.Config) kmsClient {
		return fakeKMSClient{
			describeKeyFn: func(_ context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
				switch sdkaws.ToString(in.KeyId) {
				case "symmetric-key":
					return &kms.DescribeKeyOutput{KeyMetadata: &types.KeyMetadata{
						Arn:      sdkaws.String("arn:aws:kms:test:symmetric-key"),
						KeyId:    sdkaws.String("symmetric-key"),
						KeySpec:  types.KeySpecSymmetricDefault,
						KeyUsage: types.KeyUsageTypeEncryptDecrypt,
					}}, nil
				case "rsa-key":
					return &kms.DescribeKeyOutput{KeyMetadata: &types.KeyMetadata{
						Arn:      sdkaws.String("arn:aws:kms:test:rsa-key"),
						KeyId:    sdkaws.String("rsa-key"),
						KeySpec:  types.KeySpecRsa2048,
						KeyUsage: types.KeyUsageTypeEncryptDecrypt,
					}}, nil
				default:
					return nil, errors.New("unexpected key id")
				}
			},
			getPublicKeyFn: func(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
				if sdkaws.ToString(in.KeyId) != "rsa-key" {
					t.Fatalf("GetPublicKey() key id = %q, want rsa-key", sdkaws.ToString(in.KeyId))
				}
				return &kms.GetPublicKeyOutput{PublicKey: publicDER}, nil
			},
			rotateKeyOnDemandFn: func(_ context.Context, in *kms.RotateKeyOnDemandInput, _ ...func(*kms.Options)) (*kms.RotateKeyOnDemandOutput, error) {
				if sdkaws.ToString(in.KeyId) != "symmetric-key" {
					t.Fatalf("RotateKeyOnDemand() key id = %q, want symmetric-key", sdkaws.ToString(in.KeyId))
				}
				rotated = true
				return &kms.RotateKeyOnDemandOutput{}, nil
			},
			disableKeyFn: func(_ context.Context, in *kms.DisableKeyInput, _ ...func(*kms.Options)) (*kms.DisableKeyOutput, error) {
				if sdkaws.ToString(in.KeyId) != "symmetric-key" {
					t.Fatalf("DisableKey() key id = %q, want symmetric-key", sdkaws.ToString(in.KeyId))
				}
				deactivated = true
				return &kms.DisableKeyOutput{}, nil
			},
		}
	}

	repository := NewKeyRepository()
	rotatedKey, err := repository.RotateKey(testContext, models.RotateKeyRequest{KeyID: "symmetric-key"})
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	if !rotated || rotatedKey.KeyID != "symmetric-key" || rotatedKey.KeyRef != "arn:aws:kms:test:symmetric-key" || rotatedKey.PublicKey != "" {
		t.Fatalf("RotateKey() = %#v, rotated=%v", rotatedKey, rotated)
	}

	rsaKey, err := repository.GetKey(testContext, models.GetKeyRequest{KeyID: "rsa-key"})
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}
	if rsaKey.KeyID != "rsa-key" || rsaKey.PublicKey != base64.StdEncoding.EncodeToString(publicDER) || rsaKey.Provider != awsProviderName {
		t.Fatalf("GetKey() = %#v, want RSA key metadata", rsaKey)
	}

	if _, err := repository.RotateKey(testContext, models.RotateKeyRequest{KeyID: "rsa-key"}); err == nil {
		t.Fatal("expected RotateKey() unsupported RSA error")
	}

	if err := repository.DeactivateKey(testContext, models.DeactivateKeyRequest{KeyID: "symmetric-key"}); err != nil {
		t.Fatalf("DeactivateKey() error = %v", err)
	}
	if !deactivated {
		t.Fatal("DeactivateKey() did not disable the key")
	}
}

func TestDelegatedLocalHelpers(t *testing.T) {
	t.Cleanup(viper.Reset)
	previousLoad := loadAWSConfigFn
	previousClient := newKMSClientFn
	t.Cleanup(func() {
		loadAWSConfigFn = previousLoad
		newKMSClientFn = previousClient
	})

	loadAWSConfigFn = func(context.Context) (sdkaws.Config, error) { return sdkaws.Config{}, nil }
	newKMSClientFn = func(cfg sdkaws.Config) kmsClient {
		return fakeKMSClient{
			createKeyFn: func(_ context.Context, in *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
				if in.KeySpec != types.KeySpecSymmetricDefault {
					t.Fatalf("CreateKey() KeySpec = %q, want %q", in.KeySpec, types.KeySpecSymmetricDefault)
				}
				return &kms.CreateKeyOutput{
					KeyMetadata: &types.KeyMetadata{
						Arn:   sdkaws.String("arn:aws:kms:test-symmetric"),
						KeyId: sdkaws.String("kms-symmetric-id"),
					},
				}, nil
			},
			encryptFn: func(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
				if got := in.EncryptionContext["additional"]; got != "aad" {
					t.Fatalf("Encrypt() encryption context additional = %q, want aad", got)
				}
				return &kms.EncryptOutput{CiphertextBlob: []byte("cipher")}, nil
			},
			decryptFn: func(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
				if got := in.EncryptionContext["additional"]; got != "aad" {
					t.Fatalf("Decrypt() encryption context additional = %q, want aad", got)
				}
				return &kms.DecryptOutput{Plaintext: []byte("hello")}, nil
			},
			generateMacFn: func(_ context.Context, in *kms.GenerateMacInput, _ ...func(*kms.Options)) (*kms.GenerateMacOutput, error) {
				if in.MacAlgorithm != types.MacAlgorithmSpecHmacSha256 {
					t.Fatalf("GenerateMac() algorithm = %q, want %q", in.MacAlgorithm, types.MacAlgorithmSpecHmacSha256)
				}
				return &kms.GenerateMacOutput{Mac: []byte("mac")}, nil
			},
			verifyMacFn: func(_ context.Context, in *kms.VerifyMacInput, _ ...func(*kms.Options)) (*kms.VerifyMacOutput, error) {
				if in.MacAlgorithm != types.MacAlgorithmSpecHmacSha256 {
					t.Fatalf("VerifyMac() algorithm = %q, want %q", in.MacAlgorithm, types.MacAlgorithmSpecHmacSha256)
				}
				return &kms.VerifyMacOutput{MacValid: true}, nil
			},
		}
	}

	repository := NewRepository()
	key, err := repository.GenerateSymetrycKeys(testContext, models.GenerateSymmetricKeyRequest{Size: common.Key256Bits})
	if err != nil {
		t.Fatalf("GenerateSymetrycKeys() error = %v", err)
	}
	if key == nil || key.KeyID != "kms-symmetric-id" || key.KeyRef != "arn:aws:kms:test-symmetric" || key.Provider != "aws-kms" {
		t.Fatalf("GenerateSymetrycKeys() = %#v, want KMS symmetric key metadata", key)
	}

	additional := "aad"
	ciphertext, err := repository.EncryptAES(testContext, models.EncryptAESRequest{SecretKey: key.KeyRef, Value: "hello", Additional: &additional})
	if err != nil {
		t.Fatalf("EncryptAES() error = %v", err)
	}
	plaintext, err := repository.DecryptAES(testContext, models.DecryptAESRequest{SecretKey: key.KeyRef, CipherValue: ciphertext, Additional: &additional})
	if err != nil {
		t.Fatalf("DecryptAES() error = %v", err)
	}
	if plaintext != "hello" {
		t.Fatalf("DecryptAES() = %q, want %q", plaintext, "hello")
	}
	if got := repository.HMAC(testContext, key.KeyRef, "message"); got == "" {
		t.Fatal("expected HMAC() to return a KMS MAC")
	}
	if repository.Sha256Hex(testContext, "message") == "" || repository.Blake3(testContext, "message") == "" {
		t.Fatal("expected digest helpers to return values")
	}
	localRepository := local.NewSymmetricRepository()
	localKey, err := localRepository.GenerateSymetrycKeys(testContext, models.GenerateSymmetricKeyRequest{Size: common.Key256Bits})
	if err != nil {
		t.Fatalf("local GenerateSymetrycKeys() error = %v", err)
	}
	if _, err := repository.EncryptAES(testContext, models.EncryptAESRequest{SecretKey: localKey.KeyID, Value: "hello", Additional: &additional}); err != nil {
		t.Fatalf("EncryptAES() local fallback error = %v", err)
	}
}

func TestGenerateSymetrycKeysUsesConfiguredKeyMetadata(t *testing.T) {
	t.Cleanup(viper.Reset)
	previousLoad := loadAWSConfigFn
	previousClient := newKMSClientFn
	t.Cleanup(func() {
		loadAWSConfigFn = previousLoad
		newKMSClientFn = previousClient
	})

	loadAWSConfigFn = func(context.Context) (sdkaws.Config, error) { return sdkaws.Config{}, nil }
	newKMSClientFn = func(cfg sdkaws.Config) kmsClient {
		return fakeKMSClient{
			createKeyFn: func(_ context.Context, _ *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
				return &kms.CreateKeyOutput{
					KeyMetadata: &types.KeyMetadata{
						Arn:   sdkaws.String("arn:aws:kms:us-east-1:123456789012:key/test-key"),
						KeyId: sdkaws.String("test-key-id"),
					},
				}, nil
			},
		}
	}

	repository := NewRepository()
	key, err := repository.GenerateSymetrycKeys(testContext, models.GenerateSymmetricKeyRequest{Size: common.Key256Bits})
	if err != nil {
		t.Fatalf("GenerateSymetrycKeys() error = %v", err)
	}
	if key == nil || key.Provider != "aws-kms" || key.KeyID != "test-key-id" || key.KeyRef != "arn:aws:kms:us-east-1:123456789012:key/test-key" {
		t.Fatalf("GenerateSymetrycKeys() = %#v, want aws-kms metadata", key)
	}
}

func TestResolveAWSKMSKeyIDAndKeySpec(t *testing.T) {
	t.Cleanup(viper.Reset)
	if _, err := resolveAWSKMSKeyID(""); err == nil {
		t.Fatal("expected resolveAWSKMSKeyID() error")
	}
	viper.Set(defaultKMSARNKey, "arn:aws:kms:test")
	if got, err := resolveAWSKMSKeyID(""); err != nil || got != "arn:aws:kms:test" {
		t.Fatalf("resolveAWSKMSKeyID() = %q, %v", got, err)
	}
	if got, err := resolveAWSKMSKeyID("direct"); err != nil || got != "direct" {
		t.Fatalf("resolveAWSKMSKeyID() direct = %q, %v", got, err)
	}
	if _, err := toAWSRSAKeySpec(common.Key3072Bits); err != nil {
		t.Fatalf("toAWSRSAKeySpec(3072) error = %v", err)
	}
	if _, err := toAWSRSAKeySpec(common.Key4096Bits); err != nil {
		t.Fatalf("toAWSRSAKeySpec(4096) error = %v", err)
	}
	if _, err := toAWSRSAKeySpec(0); err == nil {
		t.Fatal("expected toAWSRSAKeySpec() error")
	}
	if _, err := toAWSSymmetricKeySpec(common.Key256Bits); err != nil {
		t.Fatalf("toAWSSymmetricKeySpec(256) error = %v", err)
	}
	if _, err := toAWSSymmetricKeySpec(common.Key128Bits); err == nil {
		t.Fatal("expected toAWSSymmetricKeySpec(128) error")
	}
}

func TestNewAWSKMSClientError(t *testing.T) {
	previous := loadAWSConfigFn
	t.Cleanup(func() { loadAWSConfigFn = previous })

	loadAWSConfigFn = func(context.Context) (sdkaws.Config, error) {
		return sdkaws.Config{}, errors.New("boom")
	}

	if _, err := newAWSKMSClient(context.Background()); err == nil {
		t.Fatal("expected newAWSKMSClient() error")
	}
}

func TestAsymmetricAndSignatureProviderFlows(t *testing.T) {
	t.Cleanup(viper.Reset)
	previousLoad := loadAWSConfigFn
	previousClient := newKMSClientFn
	t.Cleanup(func() {
		loadAWSConfigFn = previousLoad
		newKMSClientFn = previousClient
	})

	privateKey := mustRSAKey(t)
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	eccPrivateKey := mustECCKey(t, ecdh.P256())
	eccPublicDER, err := x509.MarshalPKIXPublicKey(eccPrivateKey.PublicKey())
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	edPublicDER, err := x509.MarshalPKIXPublicKey(edPublic)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	edPrivateDER, err := x509.MarshalPKCS8PrivateKey(edPrivate)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	localEdPrivate := base64.StdEncoding.EncodeToString(edPrivateDER)
	localEdPublic := base64.StdEncoding.EncodeToString(edPublicDER)

	loadAWSConfigFn = func(context.Context) (sdkaws.Config, error) { return sdkaws.Config{}, nil }
	newKMSClientFn = func(cfg sdkaws.Config) kmsClient {
		return fakeKMSClient{
			createKeyFn: func(_ context.Context, in *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
				if in.KeySpec == types.KeySpecEccNistEdwards25519 {
					return &kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{Arn: sdkaws.String("arn:aws:kms:ed25519"), KeyId: sdkaws.String("ed25519-key-id")}}, nil
				}
				if in.KeyUsage == types.KeyUsageTypeKeyAgreement {
					return &kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{Arn: sdkaws.String("arn:aws:kms:ecc"), KeyId: sdkaws.String("ecc-key-id")}}, nil
				}
				return &kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{Arn: sdkaws.String("arn:aws:kms:test"), KeyId: sdkaws.String("key-id")}}, nil
			},
			deriveSharedSecretFn: func(_ context.Context, in *kms.DeriveSharedSecretInput, _ ...func(*kms.Options)) (*kms.DeriveSharedSecretOutput, error) {
				peerPublicKey, err := utilities.ParseECDHPublicKeyFromBase64(base64.StdEncoding.EncodeToString(in.PublicKey))
				if err != nil {
					return nil, err
				}
				sharedSecret, err := eccPrivateKey.ECDH(peerPublicKey)
				if err != nil {
					return nil, err
				}
				return &kms.DeriveSharedSecretOutput{SharedSecret: sharedSecret}, nil
			},
			getPublicKeyFn: func(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
				if sdkaws.ToString(in.KeyId) == "ed25519-key-id" {
					return &kms.GetPublicKeyOutput{PublicKey: edPublicDER}, nil
				}
				if sdkaws.ToString(in.KeyId) == "ecc-key-id" || sdkaws.ToString(in.KeyId) == "arn:aws:kms:ecc" {
					return &kms.GetPublicKeyOutput{PublicKey: eccPublicDER}, nil
				}
				return &kms.GetPublicKeyOutput{PublicKey: publicDER}, nil
			},
			encryptFn: func(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error) {
				return &kms.EncryptOutput{CiphertextBlob: []byte("cipher")}, nil
			},
			decryptFn: func(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error) {
				return &kms.DecryptOutput{Plaintext: []byte("plain")}, nil
			},
			generateMacFn: func(context.Context, *kms.GenerateMacInput, ...func(*kms.Options)) (*kms.GenerateMacOutput, error) {
				return &kms.GenerateMacOutput{Mac: []byte("mac")}, nil
			},
			verifyMacFn: func(context.Context, *kms.VerifyMacInput, ...func(*kms.Options)) (*kms.VerifyMacOutput, error) {
				return &kms.VerifyMacOutput{MacValid: true}, nil
			},
			signFn: func(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
				if in.SigningAlgorithm == types.SigningAlgorithmSpecEd25519Sha512 {
					return &kms.SignOutput{Signature: []byte("ed-sig-" + string(in.Message))}, nil
				}
				return &kms.SignOutput{Signature: []byte("sig-" + string(in.Message))}, nil
			},
			verifyFn: func(_ context.Context, in *kms.VerifyInput, _ ...func(*kms.Options)) (*kms.VerifyOutput, error) {
				if in.SigningAlgorithm == types.SigningAlgorithmSpecEd25519Sha512 {
					return &kms.VerifyOutput{SignatureValid: true}, nil
				}
				return &kms.VerifyOutput{SignatureValid: true}, nil
			},
		}
	}

	asymmetricRepository := NewAsymmetricRepository()
	signatureRepository := NewSignatureRepository()

	keyData, err := asymmetricRepository.GenerateRSAKeys(testContext, models.GenerateRSAKeyRequest{Size: common.Key2048Bits})
	if err != nil {
		t.Fatalf("GenerateRSAKeys() error = %v", err)
	}
	if keyData == nil || keyData.PublicKey == "" || keyData.KeyID == "" || keyData.KeyRef == "" || keyData.Provider != "aws-kms" {
		t.Fatalf("GenerateRSAKeys() = %#v, want public key metadata", keyData)
	}

	ciphertext, err := asymmetricRepository.RSA_OAEP_Encode(testContext, models.RSAOAEPEncodeRequest{PublicKey: keyData.KeyRef, Text: "payload"})
	if err != nil {
		t.Fatalf("RSA_OAEP_Encode() error = %v", err)
	}
	if ciphertext == "" {
		t.Fatal("expected ciphertext")
	}
	plaintext, err := asymmetricRepository.RSA_OAEP_Decode(testContext, models.RSAOAEPDecodeRequest{PrivateKey: keyData.KeyRef, CipherText: base64.StdEncoding.EncodeToString([]byte("cipher"))})
	if err != nil {
		t.Fatalf("RSA_OAEP_Decode() error = %v", err)
	}
	if plaintext != "plain" {
		t.Fatalf("RSA_OAEP_Decode() = %q, want %q", plaintext, "plain")
	}

	eccKeyData, err := asymmetricRepository.GenerateECDHCurveKeys(testContext, models.GenerateECDHCurveKeyRequest{Curve: common.CurveP256})
	if err != nil {
		t.Fatalf("GenerateECDHCurveKeys() error = %v", err)
	}
	if eccKeyData == nil || eccKeyData.PublicKey == "" || eccKeyData.KeyRef == "" || eccKeyData.Provider != "aws-kms" {
		t.Fatalf("GenerateECDHCurveKeys() = %#v, want public key metadata", eccKeyData)
	}
	eccCiphertext, err := asymmetricRepository.ECDH_Encode(testContext, models.ECDHEncodeRequest{PublicKey: eccKeyData.KeyRef, Text: "payload"})
	if err != nil {
		t.Fatalf("ECDH_Encode() error = %v", err)
	}
	eccPlaintext, err := asymmetricRepository.ECDH_Decode(testContext, models.ECDHDecodeRequest{PrivateKey: eccKeyData.KeyRef, CipherText: eccCiphertext})
	if err != nil {
		t.Fatalf("ECDH_Decode() error = %v", err)
	}
	if eccPlaintext != "payload" {
		t.Fatalf("ECDH_Decode() = %q, want %q", eccPlaintext, "payload")
	}

	signature, err := signatureRepository.SignRSAPSS(testContext, keyData.KeyRef, "payload")
	if err != nil {
		t.Fatalf("SignRSAPSS() error = %v", err)
	}
	if signature == "" {
		t.Fatal("expected signature")
	}
	if err := signatureRepository.VerifyRSAPSS(testContext, keyData.KeyRef, "payload", base64.StdEncoding.EncodeToString([]byte("signature"))); err != nil {
		t.Fatalf("VerifyRSAPSS() error = %v", err)
	}

	viper.Set(defaultKMSARNKey, keyData.KeyRef)
	signature, err = signatureRepository.Sign_RSA_PKCS1v15_SHA256(testContext, "", "payload")
	if err != nil {
		t.Fatalf("Sign_RSA_PKCS1v15_SHA256() error = %v", err)
	}
	if err := signatureRepository.Verify_RSA_PKCS1v15_SHA256(testContext, "payload", "", signature); err != nil {
		t.Fatalf("Verify_RSA_PKCS1v15_SHA256() error = %v", err)
	}

	edKeyData, err := signatureRepository.GenerateEd255Keys(testContext)
	if err != nil {
		t.Fatalf("GenerateEd255Keys() error = %v", err)
	}
	if edKeyData == nil || edKeyData.PublicKey == "" || edKeyData.KeyID == "" || edKeyData.KeyRef == "" || edKeyData.Provider != "aws-kms" {
		t.Fatalf("GenerateEd255Keys() = %#v, want public key metadata", edKeyData)
	}
	edSignature, err := signatureRepository.SignEd25519(testContext, edKeyData.KeyRef, "payload")
	if err != nil {
		t.Fatalf("SignEd25519() error = %v", err)
	}
	if err := signatureRepository.VerifyEd25519(testContext, edKeyData.KeyRef, "payload", edSignature); err != nil {
		t.Fatalf("VerifyEd25519() error = %v", err)
	}

	edSignature, err = signatureRepository.SignEd25519(testContext, localEdPrivate, "payload")
	if err != nil {
		t.Fatalf("SignEd25519() local fallback error = %v", err)
	}
	if err := signatureRepository.VerifyEd25519(testContext, localEdPublic, "payload", edSignature); err != nil {
		t.Fatalf("VerifyEd25519() local fallback error = %v", err)
	}
}

func TestAWSKMSProviderErrorsAndFallbacks(t *testing.T) {
	t.Cleanup(viper.Reset)
	previousLoad := loadAWSConfigFn
	previousClient := newKMSClientFn
	t.Cleanup(func() {
		loadAWSConfigFn = previousLoad
		newKMSClientFn = previousClient
	})

	loadAWSConfigFn = func(context.Context) (sdkaws.Config, error) { return sdkaws.Config{}, nil }
	newKMSClientFn = func(cfg sdkaws.Config) kmsClient {
		return fakeKMSClient{
			createKeyFn: func(context.Context, *kms.CreateKeyInput, ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
				return nil, errors.New("create boom")
			},
			getPublicKeyFn: func(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
				return nil, errors.New("get boom")
			},
			encryptFn: func(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error) {
				return nil, errors.New("encrypt boom")
			},
			decryptFn: func(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error) {
				return nil, errors.New("decrypt boom")
			},
			generateMacFn: func(context.Context, *kms.GenerateMacInput, ...func(*kms.Options)) (*kms.GenerateMacOutput, error) {
				return nil, errors.New("generate mac boom")
			},
			verifyMacFn: func(context.Context, *kms.VerifyMacInput, ...func(*kms.Options)) (*kms.VerifyMacOutput, error) {
				return nil, errors.New("verify mac boom")
			},
			signFn: func(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error) {
				return nil, errors.New("sign boom")
			},
			verifyFn: func(context.Context, *kms.VerifyInput, ...func(*kms.Options)) (*kms.VerifyOutput, error) {
				return &kms.VerifyOutput{SignatureValid: false}, nil
			},
		}
	}

	asymmetricRepository := NewAsymmetricRepository()
	symmetricRepository := NewSymmetricRepository()
	signatureRepository := NewSignatureRepository()

	if _, err := symmetricRepository.GenerateSymetrycKeys(testContext, models.GenerateSymmetricKeyRequest{Size: common.Key128Bits}); err == nil {
		t.Fatal("expected GenerateSymetrycKeys() symmetric key spec error")
	}
	if _, err := symmetricRepository.GenerateSymetrycKeys(testContext, models.GenerateSymmetricKeyRequest{Size: common.Key256Bits}); err == nil {
		t.Fatal("expected GenerateSymetrycKeys() create error")
	}
	if _, err := asymmetricRepository.GenerateRSAKeys(testContext, models.GenerateRSAKeyRequest{Size: 0}); err == nil {
		t.Fatal("expected GenerateRSAKeys() key spec error")
	}
	if _, err := asymmetricRepository.GenerateRSAKeys(testContext, models.GenerateRSAKeyRequest{Size: common.Key2048Bits}); err == nil {
		t.Fatal("expected GenerateRSAKeys() create error")
	}

	newKMSClientFn = func(cfg sdkaws.Config) kmsClient {
		return fakeKMSClient{
			createKeyFn: func(context.Context, *kms.CreateKeyInput, ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
				return &kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{}}, nil
			},
			getPublicKeyFn: func(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
				return nil, nil
			},
			encryptFn: func(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error) {
				return nil, nil
			},
			decryptFn: func(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error) {
				return nil, nil
			},
			generateMacFn: func(context.Context, *kms.GenerateMacInput, ...func(*kms.Options)) (*kms.GenerateMacOutput, error) {
				return nil, nil
			},
			verifyMacFn: func(context.Context, *kms.VerifyMacInput, ...func(*kms.Options)) (*kms.VerifyMacOutput, error) {
				return nil, nil
			},
			signFn: func(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error) { return nil, nil },
			verifyFn: func(context.Context, *kms.VerifyInput, ...func(*kms.Options)) (*kms.VerifyOutput, error) {
				return nil, nil
			},
		}
	}
	if _, err := symmetricRepository.GenerateSymetrycKeys(testContext, models.GenerateSymmetricKeyRequest{Size: common.Key256Bits}); err == nil {
		t.Fatal("expected GenerateSymetrycKeys() missing metadata error")
	}
	if _, err := asymmetricRepository.GenerateRSAKeys(testContext, models.GenerateRSAKeyRequest{Size: common.Key2048Bits}); err == nil {
		t.Fatal("expected GenerateRSAKeys() missing metadata error")
	}

	newKMSClientFn = func(cfg sdkaws.Config) kmsClient {
		return fakeKMSClient{
			createKeyFn: func(context.Context, *kms.CreateKeyInput, ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
				return &kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{Arn: sdkaws.String("arn"), KeyId: sdkaws.String("id")}}, nil
			},
			getPublicKeyFn: func(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
				return nil, errors.New("public boom")
			},
			encryptFn: func(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error) {
				return nil, nil
			},
			decryptFn: func(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error) {
				return nil, nil
			},
			generateMacFn: func(context.Context, *kms.GenerateMacInput, ...func(*kms.Options)) (*kms.GenerateMacOutput, error) {
				return nil, nil
			},
			verifyMacFn: func(context.Context, *kms.VerifyMacInput, ...func(*kms.Options)) (*kms.VerifyMacOutput, error) {
				return nil, nil
			},
			signFn: func(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error) { return nil, nil },
			verifyFn: func(context.Context, *kms.VerifyInput, ...func(*kms.Options)) (*kms.VerifyOutput, error) {
				return nil, nil
			},
		}
	}
	if _, err := asymmetricRepository.GenerateRSAKeys(testContext, models.GenerateRSAKeyRequest{Size: common.Key2048Bits}); err == nil {
		t.Fatal("expected GenerateRSAKeys() get public key error")
	}

	newKMSClientFn = func(cfg sdkaws.Config) kmsClient {
		return fakeKMSClient{
			createKeyFn: func(context.Context, *kms.CreateKeyInput, ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
				return nil, errors.New("create boom")
			},
			getPublicKeyFn: func(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
				return nil, errors.New("get boom")
			},
			encryptFn: func(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error) {
				return nil, errors.New("encrypt boom")
			},
			decryptFn: func(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error) {
				return nil, errors.New("decrypt boom")
			},
			generateMacFn: func(context.Context, *kms.GenerateMacInput, ...func(*kms.Options)) (*kms.GenerateMacOutput, error) {
				return nil, errors.New("generate mac boom")
			},
			verifyMacFn: func(context.Context, *kms.VerifyMacInput, ...func(*kms.Options)) (*kms.VerifyMacOutput, error) {
				return nil, errors.New("verify mac boom")
			},
			signFn: func(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error) {
				return nil, errors.New("sign boom")
			},
			verifyFn: func(context.Context, *kms.VerifyInput, ...func(*kms.Options)) (*kms.VerifyOutput, error) {
				return &kms.VerifyOutput{SignatureValid: false}, nil
			},
		}
	}
	if _, err := asymmetricRepository.RSA_OAEP_Encode(testContext, models.RSAOAEPEncodeRequest{PublicKey: "", Text: "payload"}); err == nil {
		t.Fatal("expected RSA_OAEP_Encode() key id error")
	}
	if _, err := asymmetricRepository.GenerateECDHCurveKeys(testContext, models.GenerateECDHCurveKeyRequest{Curve: common.CurveAsymmetricKey(99)}); err == nil {
		t.Fatal("expected GenerateECDHCurveKeys() curve error")
	}
	viper.Set(defaultKMSARNKey, "arn:aws:kms:test")
	if _, err := symmetricRepository.EncryptAES(testContext, models.EncryptAESRequest{SecretKey: "", Value: "payload", Additional: nil}); err == nil {
		t.Fatal("expected EncryptAES() provider error")
	}
	additional := "aad"
	if _, err := symmetricRepository.DecryptAES(testContext, models.DecryptAESRequest{SecretKey: "", CipherValue: "%%%", Additional: &additional}); err == nil {
		t.Fatal("expected DecryptAES() decode error")
	}
	if _, err := symmetricRepository.DecryptAES(testContext, models.DecryptAESRequest{SecretKey: "", CipherValue: base64.StdEncoding.EncodeToString([]byte("cipher")), Additional: &additional}); err == nil {
		t.Fatal("expected DecryptAES() provider error")
	}
	if got := NewHashRepository().HMAC(testContext, "arn:aws:kms:test", "message"); got != "" {
		t.Fatalf("HMAC() = %q, want empty string on provider error", got)
	}
	if _, err := asymmetricRepository.RSA_OAEP_Encode(testContext, models.RSAOAEPEncodeRequest{PublicKey: "", Text: "payload"}); err == nil {
		t.Fatal("expected RSA_OAEP_Encode() provider error")
	}
	if _, err := asymmetricRepository.RSA_OAEP_Decode(testContext, models.RSAOAEPDecodeRequest{PrivateKey: "", CipherText: "%%%"}); err == nil {
		t.Fatal("expected RSA_OAEP_Decode() decode error")
	}
	if _, err := asymmetricRepository.RSA_OAEP_Decode(testContext, models.RSAOAEPDecodeRequest{PrivateKey: "", CipherText: base64.StdEncoding.EncodeToString([]byte("cipher"))}); err == nil {
		t.Fatal("expected RSA_OAEP_Decode() provider error")
	}
	if _, err := asymmetricRepository.ECDH_Encode(testContext, models.ECDHEncodeRequest{PublicKey: "", Text: "payload"}); err == nil {
		t.Fatal("expected ECDH_Encode() provider error")
	}
	if _, err := asymmetricRepository.ECDH_Decode(testContext, models.ECDHDecodeRequest{PrivateKey: "", CipherText: "%%%"}); err == nil {
		t.Fatal("expected ECDH_Decode() payload error")
	}
	if _, err := asymmetricRepository.ECDH_Decode(testContext, models.ECDHDecodeRequest{PrivateKey: "", CipherText: base64.StdEncoding.EncodeToString([]byte("{}"))}); err == nil {
		t.Fatal("expected ECDH_Decode() provider error")
	}

	if _, err := signatureRepository.GenerateEd255Keys(testContext); err == nil {
		t.Fatal("expected GenerateEd255Keys() create error")
	}
	if _, err := signatureRepository.SignEd25519(testContext, "", "payload"); err == nil {
		t.Fatal("expected SignEd25519() key id error")
	}
	if err := signatureRepository.VerifyEd25519(testContext, "", "payload", "sig"); err == nil {
		t.Fatal("expected VerifyEd25519() key id error")
	}
	if _, err := signatureRepository.SignEd25519(testContext, "arn:aws:kms:test", "payload"); err == nil {
		t.Fatal("expected SignEd25519() provider error")
	}
	if err := signatureRepository.VerifyEd25519(testContext, "arn:aws:kms:test", "payload", "%%%"); err == nil {
		t.Fatal("expected VerifyEd25519() decode error")
	}
	if err := signatureRepository.VerifyEd25519(testContext, "arn:aws:kms:test", "payload", base64.StdEncoding.EncodeToString([]byte("sig"))); err == nil {
		t.Fatal("expected VerifyEd25519() provider error")
	}
	if _, err := signatureRepository.SignRSAPSS(testContext, "", "payload"); err == nil {
		t.Fatal("expected SignRSAPSS() provider error")
	}
	if err := signatureRepository.VerifyRSAPSS(testContext, "", "payload", "%%%"); err == nil {
		t.Fatal("expected VerifyRSAPSS() decode error")
	}
	if err := signatureRepository.VerifyRSAPSS(testContext, "", "payload", base64.StdEncoding.EncodeToString([]byte("sig"))); err == nil {
		t.Fatal("expected VerifyRSAPSS() invalid signature error")
	}
	if _, err := signatureRepository.Sign_RSA_PKCS1v15_SHA256(testContext, "", "payload"); err == nil {
		t.Fatal("expected Sign_RSA_PKCS1v15_SHA256() provider error")
	}
	if err := signatureRepository.Verify_RSA_PKCS1v15_SHA256(testContext, "payload", "", "%%%"); err == nil {
		t.Fatal("expected Verify_RSA_PKCS1v15_SHA256() decode error")
	}
	if err := signatureRepository.Verify_RSA_PKCS1v15_SHA256(testContext, "payload", "", base64.StdEncoding.EncodeToString([]byte("sig"))); err == nil {
		t.Fatal("expected Verify_RSA_PKCS1v15_SHA256() invalid signature error")
	}

	privateKey := mustRSAKey(t)
	publicKey := &privateKey.PublicKey
	publicB64 := mustMarshalPKIXRSAPublicKey(t, publicKey)
	privateB64 := mustMarshalPKCS8RSAPrivateKey(t, privateKey)
	eccPrivateB64 := mustECCPrivateKeyBase64(t, ecdh.P256())
	eccPublicB64 := mustECCPublicKeyBase64(t, eccPrivateB64)

	if _, err := asymmetricRepository.RSA_OAEP_Encode(testContext, models.RSAOAEPEncodeRequest{PublicKey: publicB64, Text: "payload"}); err != nil {
		t.Fatalf("RSA_OAEP_Encode() local fallback error = %v", err)
	}
	ciphertext, err := asymmetricRepository.RSA_OAEP_Encode(testContext, models.RSAOAEPEncodeRequest{PublicKey: publicB64, Text: "payload"})
	if err != nil {
		t.Fatalf("RSA_OAEP_Encode() local fallback error = %v", err)
	}
	if _, err := asymmetricRepository.RSA_OAEP_Decode(testContext, models.RSAOAEPDecodeRequest{PrivateKey: privateB64, CipherText: ciphertext}); err != nil {
		t.Fatalf("RSA_OAEP_Decode() local fallback error = %v", err)
	}
	eccCiphertext, err := asymmetricRepository.ECDH_Encode(testContext, models.ECDHEncodeRequest{PublicKey: eccPublicB64, Text: "payload"})
	if err != nil {
		t.Fatalf("ECDH_Encode() local fallback error = %v", err)
	}
	if plaintext, err := asymmetricRepository.ECDH_Decode(testContext, models.ECDHDecodeRequest{PrivateKey: eccPrivateB64, CipherText: eccCiphertext}); err != nil || plaintext != "payload" {
		t.Fatalf("ECDH_Decode() local fallback = %q, %v", plaintext, err)
	}
	signature, err := signatureRepository.SignRSAPSS(testContext, privateB64, "payload")
	if err != nil {
		t.Fatalf("SignRSAPSS() local fallback error = %v", err)
	}
	if err := signatureRepository.VerifyRSAPSS(testContext, publicB64, "payload", signature); err != nil {
		t.Fatalf("VerifyRSAPSS() local fallback error = %v", err)
	}
	signature, err = signatureRepository.Sign_RSA_PKCS1v15_SHA256(testContext, privateB64, "payload")
	if err != nil {
		t.Fatalf("Sign_RSA_PKCS1v15_SHA256() local fallback error = %v", err)
	}
	if err := signatureRepository.Verify_RSA_PKCS1v15_SHA256(testContext, "payload", publicB64, signature); err != nil {
		t.Fatalf("Verify_RSA_PKCS1v15_SHA256() local fallback error = %v", err)
	}
}

func TestAWSKMSOperationsReturnLoadConfigErrors(t *testing.T) {
	t.Cleanup(viper.Reset)
	previousLoad := loadAWSConfigFn
	t.Cleanup(func() { loadAWSConfigFn = previousLoad })

	loadAWSConfigFn = func(context.Context) (sdkaws.Config, error) {
		return sdkaws.Config{}, errors.New("config boom")
	}

	symmetricRepository := NewSymmetricRepository()
	asymmetricRepository := NewAsymmetricRepository()
	keyRepository := NewKeyRepository()
	signatureRepository := NewSignatureRepository()

	if _, err := symmetricRepository.GenerateSymetrycKeys(testContext, models.GenerateSymmetricKeyRequest{Size: common.Key256Bits}); err == nil {
		t.Fatal("expected GenerateSymetrycKeys() config error")
	}
	if _, err := asymmetricRepository.GenerateRSAKeys(testContext, models.GenerateRSAKeyRequest{Size: common.Key2048Bits}); err == nil {
		t.Fatal("expected GenerateRSAKeys() config error")
	}
	if _, err := asymmetricRepository.GenerateECDHCurveKeys(testContext, models.GenerateECDHCurveKeyRequest{Curve: common.CurveP256}); err == nil {
		t.Fatal("expected GenerateECDHCurveKeys() config error")
	}
	if _, err := keyRepository.RotateKey(testContext, models.RotateKeyRequest{KeyID: "arn"}); err == nil {
		t.Fatal("expected RotateKey() config error")
	}
	if _, err := keyRepository.GetKey(testContext, models.GetKeyRequest{KeyID: "arn"}); err == nil {
		t.Fatal("expected GetKey() config error")
	}
	if err := keyRepository.DeactivateKey(testContext, models.DeactivateKeyRequest{KeyID: "arn"}); err == nil {
		t.Fatal("expected DeactivateKey() config error")
	}
	if _, err := asymmetricRepository.RSA_OAEP_Encode(testContext, models.RSAOAEPEncodeRequest{PublicKey: "arn", Text: "payload"}); err == nil {
		t.Fatal("expected RSA_OAEP_Encode() config error")
	}
	if _, err := asymmetricRepository.RSA_OAEP_Decode(testContext, models.RSAOAEPDecodeRequest{PrivateKey: "arn", CipherText: base64.StdEncoding.EncodeToString([]byte("cipher"))}); err == nil {
		t.Fatal("expected RSA_OAEP_Decode() config error")
	}
	if _, err := asymmetricRepository.ECDH_Encode(testContext, models.ECDHEncodeRequest{PublicKey: "arn", Text: "payload"}); err == nil {
		t.Fatal("expected ECDH_Encode() config error")
	}
	if _, err := asymmetricRepository.ECDH_Decode(testContext, models.ECDHDecodeRequest{PrivateKey: "arn", CipherText: base64.StdEncoding.EncodeToString([]byte("{}"))}); err == nil {
		t.Fatal("expected ECDH_Decode() config error")
	}
	if _, err := signatureRepository.SignRSAPSS(testContext, "arn", "payload"); err == nil {
		t.Fatal("expected SignRSAPSS() config error")
	}
	if _, err := signatureRepository.SignEd25519(testContext, "arn", "payload"); err == nil {
		t.Fatal("expected SignEd25519() config error")
	}
	if err := signatureRepository.VerifyEd25519(testContext, "arn", "payload", base64.StdEncoding.EncodeToString([]byte("sig"))); err == nil {
		t.Fatal("expected VerifyEd25519() config error")
	}
	if err := signatureRepository.VerifyRSAPSS(testContext, "arn", "payload", base64.StdEncoding.EncodeToString([]byte("sig"))); err == nil {
		t.Fatal("expected VerifyRSAPSS() config error")
	}
	if _, err := signatureRepository.Sign_RSA_PKCS1v15_SHA256(testContext, "", "payload"); err == nil {
		t.Fatal("expected Sign_RSA_PKCS1v15_SHA256() config error")
	}
	if err := signatureRepository.Verify_RSA_PKCS1v15_SHA256(testContext, "payload", "", base64.StdEncoding.EncodeToString([]byte("sig"))); err == nil {
		t.Fatal("expected Verify_RSA_PKCS1v15_SHA256() config error")
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return privateKey
}

func mustECCKey(t *testing.T, curve ecdh.Curve) *ecdh.PrivateKey {
	t.Helper()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh.GenerateKey() error = %v", err)
	}
	return privateKey
}

func mustMarshalPKCS8RSAPrivateKey(t *testing.T, privateKey *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func mustECCPrivateKeyBase64(t *testing.T, curve ecdh.Curve) string {
	t.Helper()
	privateKey := mustECCKey(t, curve)
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func mustECCPublicKeyBase64(t *testing.T, privateKeyBase64 string) string {
	t.Helper()
	privateKey, err := utilities.ParseECDHPrivateKeyFromBase64(privateKeyBase64)
	if err != nil {
		t.Fatalf("ParseECDHPrivateKeyFromBase64() error = %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func mustMarshalPKIXRSAPublicKey(t *testing.T, publicKey *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}
