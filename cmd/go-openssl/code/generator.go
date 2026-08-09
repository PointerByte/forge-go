// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	encryptedPEMBlockType        = "GoForge ENCRYPTED PEM"
	legacyEncryptedPEMVersion    = 1
	encryptedPEMVersion          = 2
	encryptedPEMAlgorithm        = "AES-256-GCM"
	encryptedPEMKDF              = "ARGON2ID"
	encryptedKindCertificate     = "certificate"
	encryptedKindPrivateKey      = "private-key"
	encryptedKindPublicKey       = "public-key"
	minimumEncryptionSecretBytes = 32
	encryptedPEMSaltBytes        = 16
	encryptedPEMKDFTime          = uint32(3)
	encryptedPEMKDFMemory        = uint32(64 * 1024)
	encryptedPEMKDFThreads       = uint8(2)
	encryptedPEMKDFKeyBytes      = uint32(32)
)

type encryptedPEMPayload struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	KDF        string `json:"kdf,omitempty"`
	KDFSalt    string `json:"kdfSalt,omitempty"`
	KDFTime    uint32 `json:"kdfTime,omitempty"`
	KDFMemory  uint32 `json:"kdfMemory,omitempty"`
	KDFThreads uint8  `json:"kdfThreads,omitempty"`
	KDFKeySize uint32 `json:"kdfKeySize,omitempty"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// Options configures the generated certificate, keys, output paths, and algorithm-specific settings.
type Options struct {
	// Algorithm selects the key algorithm used to generate the certificate.
	Algorithm string
	// OutputDir is the directory where the PEM files are written.
	OutputDir string
	// CommonName is the subject common name included in the certificate.
	CommonName string
	// DNSNames lists the DNS subject alternative names included in the certificate.
	DNSNames []string
	// IPAddresses lists the IP subject alternative names included in the certificate.
	IPAddresses []string
	// Organization is the subject organization included in the certificate.
	Organization string
	// ValidForDays controls the certificate validity period in days.
	ValidForDays int
	// RSAKeySize is the RSA key size in bits when Algorithm is rsa.
	RSAKeySize int
	// ECCCurve selects the elliptic curve when Algorithm is ecc.
	ECCCurve string
	// Salt mixes additional data into the random source used for generation.
	Salt string
	// CertFileName is the certificate PEM file name written inside OutputDir.
	CertFileName string
	// KeyFileName is the private key PEM file name written inside OutputDir.
	KeyFileName string
	// PublicKeyFileName is the public key PEM file name written inside OutputDir.
	PublicKeyFileName string
	// SignedBy is the CA certificate PEM path used to sign the generated certificate.
	SignedBy string
	// CAKeyFile is the CA private key PEM path used to sign the generated certificate.
	CAKeyFile string
	// IsCA marks the generated certificate as a certificate authority.
	IsCA bool
	// EncryptSecret encrypts generated PEM files when set. It must be at least 32 bytes.
	EncryptSecret string
	// SignedBySecret decrypts an encrypted SignedBy certificate when set.
	SignedBySecret string
	// CAKeySecret decrypts an encrypted CAKeyFile private key when set.
	CAKeySecret string
}

// UpdateEncryptionSecretOptions configures re-encryption of existing encrypted PEM files.
type UpdateEncryptionSecretOptions struct {
	// CertificatePath is the encrypted certificate PEM path to update.
	CertificatePath string
	// PrivateKeyPath is the encrypted private key PEM path to update.
	PrivateKeyPath string
	// PublicKeyPath is the encrypted public key PEM path to update.
	PublicKeyPath string
	// EncryptSecretOld is the current secret used to decrypt the PEM files.
	EncryptSecretOld string
	// EncryptSecretNew is the new secret used to re-encrypt the PEM files.
	EncryptSecretNew string
}

// Result describes the generated PEM artifacts and the effective generation parameters.
type Result struct {
	// Algorithm is the normalized algorithm used for generation.
	Algorithm string
	// OutputDir is the normalized output directory used for the generated files.
	OutputDir string
	// CertificatePath is the path to the generated certificate PEM file.
	CertificatePath string
	// PrivateKeyPath is the path to the generated private key PEM file.
	PrivateKeyPath string
	// PublicKeyPath is the path to the generated public key PEM file.
	PublicKeyPath string
	// Encrypted reports whether the generated PEM files were encrypted.
	Encrypted bool
}

// UpdateEncryptionSecretResult describes the PEM files updated with a new encryption secret.
type UpdateEncryptionSecretResult struct {
	// CertificatePath is the re-encrypted certificate PEM path.
	CertificatePath string
	// PrivateKeyPath is the re-encrypted private key PEM path.
	PrivateKeyPath string
	// PublicKeyPath is the re-encrypted public key PEM path.
	PublicKeyPath string
}

type pemFileUpdate struct {
	path    string
	content []byte
	mode    os.FileMode
}

// Generator coordinates filesystem writes and cryptographic generation helpers.
type Generator struct {
	// mkdirAllFn creates output directories before writing generated files.
	mkdirAllFn func(string, os.FileMode) error
	// writeFilesFn atomically writes a complete PEM file batch.
	writeFilesFn func([]pemFileUpdate) error
	// nowFn provides the certificate validity start time.
	nowFn func() time.Time
	// randReader provides entropy for key and certificate generation.
	randReader io.Reader
}

// NewGenerator creates the default certificate generator.
func NewGenerator() *Generator {
	return &Generator{
		mkdirAllFn:   os.MkdirAll,
		writeFilesFn: writePEMFilesAtomically,
		nowFn:        time.Now,
		randReader:   rand.Reader,
	}
}

// GenerateCertificates generates PEM certificate assets using the default generator.
func GenerateCertificates(options Options) (Result, error) {
	return NewGenerator().Generate(options)
}

// UpdateEncryptionSecret re-encrypts existing encrypted PEM files using a new
// secret and upgrades legacy envelopes to the current format.
func UpdateEncryptionSecret(options UpdateEncryptionSecretOptions) (UpdateEncryptionSecretResult, error) {
	return NewGenerator().UpdateEncryptionSecret(options)
}

// Generate creates a certificate together with matching private and public keys.
func (generator *Generator) Generate(options Options) (Result, error) {
	resolvedOptions, err := normalizeOptions(options)
	if err != nil {
		return Result{}, err
	}

	if err := generator.mkdirAllFn(resolvedOptions.OutputDir, 0o755); err != nil {
		return Result{}, fmt.Errorf("create output directory: %w", err)
	}

	randomSource, err := generator.randomSource(resolvedOptions.Salt)
	if err != nil {
		return Result{}, fmt.Errorf("build random source: %w", err)
	}

	privateKey, publicKey, err := buildKeyPair(randomSource, resolvedOptions)
	if err != nil {
		return Result{}, err
	}

	certificatePEM, err := generator.buildCertificate(randomSource, resolvedOptions, publicKey, privateKey)
	if err != nil {
		return Result{}, err
	}

	privateKeyPEM, err := encodePrivateKeyPEM(privateKey)
	if err != nil {
		return Result{}, err
	}

	publicKeyPEM, err := encodePublicKeyPEM(publicKey)
	if err != nil {
		return Result{}, err
	}

	encrypted := resolvedOptions.EncryptSecret != ""
	if encrypted {
		certificatePEM, err = encryptPEM(certificatePEM, resolvedOptions.EncryptSecret, encryptedKindCertificate, randomSource)
		if err != nil {
			return Result{}, fmt.Errorf("encrypt certificate file: %w", err)
		}
		privateKeyPEM, err = encryptPEM(privateKeyPEM, resolvedOptions.EncryptSecret, encryptedKindPrivateKey, randomSource)
		if err != nil {
			return Result{}, fmt.Errorf("encrypt private key file: %w", err)
		}
		publicKeyPEM, err = encryptPEM(publicKeyPEM, resolvedOptions.EncryptSecret, encryptedKindPublicKey, randomSource)
		if err != nil {
			return Result{}, fmt.Errorf("encrypt public key file: %w", err)
		}
	}

	result := Result{
		Algorithm:       resolvedOptions.Algorithm,
		OutputDir:       resolvedOptions.OutputDir,
		CertificatePath: filepath.Join(resolvedOptions.OutputDir, resolvedOptions.CertFileName),
		PrivateKeyPath:  filepath.Join(resolvedOptions.OutputDir, resolvedOptions.KeyFileName),
		PublicKeyPath:   filepath.Join(resolvedOptions.OutputDir, resolvedOptions.PublicKeyFileName),
		Encrypted:       encrypted,
	}

	updates := []pemFileUpdate{
		{path: result.CertificatePath, content: certificatePEM, mode: 0o644},
		{path: result.PrivateKeyPath, content: privateKeyPEM, mode: 0o600},
		{path: result.PublicKeyPath, content: publicKeyPEM, mode: 0o644},
	}
	if err := generator.writeFilesFn(updates); err != nil {
		return Result{}, fmt.Errorf("write generated PEM files: %w", err)
	}

	return result, nil
}

// UpdateEncryptionSecret atomically updates existing encrypted certificate,
// private key, and public key files using the current envelope format.
func (generator *Generator) UpdateEncryptionSecret(options UpdateEncryptionSecretOptions) (UpdateEncryptionSecretResult, error) {
	resolvedOptions, err := normalizeUpdateEncryptionSecretOptions(options)
	if err != nil {
		return UpdateEncryptionSecretResult{}, err
	}

	randomSource, err := generator.randomSource("")
	if err != nil {
		return UpdateEncryptionSecretResult{}, fmt.Errorf("build random source: %w", err)
	}

	updates := make([]pemFileUpdate, 0, 3)
	certificateUpdate, err := generator.prepareReencryptedPEMFile(resolvedOptions.CertificatePath, encryptedKindCertificate, resolvedOptions.EncryptSecretOld, resolvedOptions.EncryptSecretNew, randomSource, 0o644)
	if err != nil {
		return UpdateEncryptionSecretResult{}, fmt.Errorf("update certificate encryption secret: %w", err)
	}
	updates = append(updates, certificateUpdate)

	privateKeyUpdate, err := generator.prepareReencryptedPEMFile(resolvedOptions.PrivateKeyPath, encryptedKindPrivateKey, resolvedOptions.EncryptSecretOld, resolvedOptions.EncryptSecretNew, randomSource, 0o600)
	if err != nil {
		return UpdateEncryptionSecretResult{}, fmt.Errorf("update private key encryption secret: %w", err)
	}
	updates = append(updates, privateKeyUpdate)

	publicKeyUpdate, err := generator.prepareReencryptedPEMFile(resolvedOptions.PublicKeyPath, encryptedKindPublicKey, resolvedOptions.EncryptSecretOld, resolvedOptions.EncryptSecretNew, randomSource, 0o644)
	if err != nil {
		return UpdateEncryptionSecretResult{}, fmt.Errorf("update public key encryption secret: %w", err)
	}
	updates = append(updates, publicKeyUpdate)

	if err := generator.writeFilesFn(updates); err != nil {
		return UpdateEncryptionSecretResult{}, fmt.Errorf("write re-encrypted PEM files: %w", err)
	}

	return UpdateEncryptionSecretResult{
		CertificatePath: resolvedOptions.CertificatePath,
		PrivateKeyPath:  resolvedOptions.PrivateKeyPath,
		PublicKeyPath:   resolvedOptions.PublicKeyPath,
	}, nil
}

func (generator *Generator) prepareReencryptedPEMFile(path string, kind string, oldSecret string, newSecret string, randomSource io.Reader, mode os.FileMode) (pemFileUpdate, error) {
	content, err := os.ReadFile(path) // #nosec G304 -- user-provided PEM/key/cert path is the intended CLI input
	if err != nil {
		return pemFileUpdate{}, err
	}
	if err := requireEncryptedPEM(content, kind); err != nil {
		return pemFileUpdate{}, err
	}

	plainContent, err := DecryptPEM(content, oldSecret)
	if err != nil {
		return pemFileUpdate{}, err
	}
	defer clear(plainContent)

	encryptedContent, err := encryptPEM(plainContent, newSecret, kind, randomSource)
	if err != nil {
		return pemFileUpdate{}, err
	}
	return pemFileUpdate{path: path, content: encryptedContent, mode: mode}, nil
}

func defaultOptions() *Options {
	return &Options{
		Algorithm:         algorithmRSA,
		OutputDir:         ".",
		CommonName:        "localhost",
		DNSNames:          []string{"localhost"},
		Organization:      "PointerByte",
		ValidForDays:      365,
		RSAKeySize:        2048,
		ECCCurve:          curveP256,
		CertFileName:      "cert.pem",
		KeyFileName:       "key.pem",
		PublicKeyFileName: "public.pem",
	}
}

func normalizeOptions(options Options) (Options, error) {
	defaults := defaultOptions()

	options.Algorithm = strings.ToLower(strings.TrimSpace(coalesce(options.Algorithm, defaults.Algorithm)))
	options.OutputDir = strings.TrimSpace(coalesce(options.OutputDir, defaults.OutputDir))
	options.CommonName = strings.TrimSpace(coalesce(options.CommonName, defaults.CommonName))
	options.Organization = strings.TrimSpace(coalesce(options.Organization, defaults.Organization))
	options.ECCCurve = strings.ToLower(strings.TrimSpace(coalesce(options.ECCCurve, defaults.ECCCurve)))
	options.CertFileName = strings.TrimSpace(coalesce(options.CertFileName, defaults.CertFileName))
	options.KeyFileName = strings.TrimSpace(coalesce(options.KeyFileName, defaults.KeyFileName))
	options.PublicKeyFileName = strings.TrimSpace(coalesce(options.PublicKeyFileName, defaults.PublicKeyFileName))
	options.SignedBy = strings.TrimSpace(options.SignedBy)
	options.CAKeyFile = strings.TrimSpace(options.CAKeyFile)
	options.Salt = strings.TrimSpace(options.Salt)

	if options.ValidForDays <= 0 {
		options.ValidForDays = defaults.ValidForDays
	}
	if options.RSAKeySize == 0 {
		options.RSAKeySize = defaults.RSAKeySize
	}
	if len(options.DNSNames) == 0 {
		options.DNSNames = append([]string(nil), defaults.DNSNames...)
	}

	if options.OutputDir == "" {
		return Options{}, fmt.Errorf("output directory is required")
	}
	if options.CommonName == "" {
		return Options{}, fmt.Errorf("common name is required")
	}
	if options.ValidForDays <= 0 {
		return Options{}, fmt.Errorf("days must be greater than zero")
	}
	if options.CertFileName == "" || options.KeyFileName == "" || options.PublicKeyFileName == "" {
		return Options{}, fmt.Errorf("certificate, key, and public key file names are required")
	}
	outputPaths := []string{
		filepath.Clean(filepath.Join(options.OutputDir, options.CertFileName)),
		filepath.Clean(filepath.Join(options.OutputDir, options.KeyFileName)),
		filepath.Clean(filepath.Join(options.OutputDir, options.PublicKeyFileName)),
	}
	if outputPaths[0] == outputPaths[1] || outputPaths[0] == outputPaths[2] || outputPaths[1] == outputPaths[2] {
		return Options{}, fmt.Errorf("certificate, key, and public key paths must be different")
	}
	if (options.SignedBy == "") != (options.CAKeyFile == "") {
		return Options{}, fmt.Errorf("signed-by and ca-key must be provided together")
	}
	if options.EncryptSecret != "" {
		if err := validateEncryptionSecret(options.EncryptSecret); err != nil {
			return Options{}, err
		}
	}
	if options.SignedBySecret != "" && options.SignedBy == "" {
		return Options{}, fmt.Errorf("signed-by-secret requires signed-by")
	}
	if options.CAKeySecret != "" && options.CAKeyFile == "" {
		return Options{}, fmt.Errorf("ca-key-secret requires ca-key")
	}
	if options.SignedBySecret != "" {
		if err := validateEncryptionSecret(options.SignedBySecret); err != nil {
			return Options{}, fmt.Errorf("signed-by-secret: %w", err)
		}
	}
	if options.CAKeySecret != "" {
		if err := validateEncryptionSecret(options.CAKeySecret); err != nil {
			return Options{}, fmt.Errorf("ca-key-secret: %w", err)
		}
	}

	switch options.Algorithm {
	case algorithmRSA:
		if options.RSAKeySize < 2048 {
			return Options{}, fmt.Errorf("rsa-bits must be at least 2048")
		}
	case algorithmECC:
		if _, err := resolveCurve(options.ECCCurve); err != nil {
			return Options{}, err
		}
	case algorithmEd25519:
	default:
		return Options{}, fmt.Errorf("unsupported algorithm %q", options.Algorithm)
	}

	return options, nil
}

func normalizeUpdateEncryptionSecretOptions(options UpdateEncryptionSecretOptions) (UpdateEncryptionSecretOptions, error) {
	options.CertificatePath = strings.TrimSpace(options.CertificatePath)
	options.PrivateKeyPath = strings.TrimSpace(options.PrivateKeyPath)
	options.PublicKeyPath = strings.TrimSpace(options.PublicKeyPath)

	if options.CertificatePath == "" {
		return UpdateEncryptionSecretOptions{}, fmt.Errorf("certificate path is required")
	}
	if options.PrivateKeyPath == "" {
		return UpdateEncryptionSecretOptions{}, fmt.Errorf("private key path is required")
	}
	if options.PublicKeyPath == "" {
		return UpdateEncryptionSecretOptions{}, fmt.Errorf("public key path is required")
	}
	if strings.TrimSpace(options.EncryptSecretOld) == "" {
		return UpdateEncryptionSecretOptions{}, fmt.Errorf("old encryption secret is required")
	}
	if strings.TrimSpace(options.EncryptSecretNew) == "" {
		return UpdateEncryptionSecretOptions{}, fmt.Errorf("new encryption secret is required")
	}
	if options.EncryptSecretOld == options.EncryptSecretNew {
		return UpdateEncryptionSecretOptions{}, fmt.Errorf("new encryption secret must be different from old encryption secret")
	}
	if err := validateEncryptionSecret(options.EncryptSecretOld); err != nil {
		return UpdateEncryptionSecretOptions{}, fmt.Errorf("old encryption secret: %w", err)
	}
	if err := validateEncryptionSecret(options.EncryptSecretNew); err != nil {
		return UpdateEncryptionSecretOptions{}, fmt.Errorf("new encryption secret: %w", err)
	}
	return options, nil
}

func coalesce(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func (generator *Generator) randomSource(salt string) (io.Reader, error) {
	if salt == "" {
		return generator.randReader, nil
	}

	seed := make([]byte, 32)
	if _, err := io.ReadFull(generator.randReader, seed); err != nil {
		return nil, err
	}
	return &saltedReader{
		seed:    seed,
		salt:    []byte(salt),
		counter: 0,
	}, nil
}

func buildKeyPair(randomSource io.Reader, options Options) (any, any, error) {
	switch options.Algorithm {
	case algorithmRSA:
		privateKey, err := rsa.GenerateKey(randomSource, options.RSAKeySize)
		if err != nil {
			return nil, nil, fmt.Errorf("generate rsa key: %w", err)
		}
		return privateKey, &privateKey.PublicKey, nil
	case algorithmECC:
		curve, err := resolveCurve(options.ECCCurve)
		if err != nil {
			return nil, nil, err
		}
		privateKey, err := ecdsa.GenerateKey(curve, randomSource)
		if err != nil {
			return nil, nil, fmt.Errorf("generate ecc key: %w", err)
		}
		return privateKey, &privateKey.PublicKey, nil
	case algorithmEd25519:
		publicKey, privateKey, err := ed25519.GenerateKey(randomSource)
		if err != nil {
			return nil, nil, fmt.Errorf("generate ed25519 key: %w", err)
		}
		return privateKey, publicKey, nil
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm %q", options.Algorithm)
	}
}

func resolveCurve(name string) (elliptic.Curve, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case curveP256:
		return elliptic.P256(), nil
	case curveP384:
		return elliptic.P384(), nil
	case curveP521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ecc curve %q", name)
	}
}

func (generator *Generator) buildCertificate(randomSource io.Reader, options Options, publicKey any, privateKey any) ([]byte, error) {
	serialNumber, err := rand.Int(randomSource, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	notBefore := generator.nowFn().UTC()
	notAfter := notBefore.Add(time.Duration(options.ValidForDays) * 24 * time.Hour)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   options.CommonName,
			Organization: []string{options.Organization},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              sanitizeStrings(options.DNSNames),
		IPAddresses:           parseIPAddresses(options.IPAddresses),
		IsCA:                  options.IsCA,
	}

	if options.Algorithm == algorithmRSA {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	if options.IsCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	parent := template
	signingKey := privateKey
	if options.SignedBy != "" {
		caCert, caKey, err := loadSigningCA(options.SignedBy, options.CAKeyFile, options.SignedBySecret, options.CAKeySecret)
		if err != nil {
			return nil, err
		}
		parent = caCert
		signingKey = caKey
	}

	der, err := x509.CreateCertificate(randomSource, template, parent, publicKey, signingKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func loadSigningCA(certPath string, keyPath string, certSecret string, keySecret string) (*x509.Certificate, any, error) {
	certificate, err := readCertificatePEMFile(certPath, certSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("read signed-by certificate: %w", err)
	}
	if !certificate.IsCA {
		return nil, nil, fmt.Errorf("signed-by certificate is not a CA")
	}

	privateKey, err := readPrivateKeyPEMFile(keyPath, keySecret)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca-key: %w", err)
	}
	return certificate, privateKey, nil
}

func readCertificatePEMFile(path string, secret string) (*x509.Certificate, error) {
	content, err := os.ReadFile(path) // #nosec G304 -- user-provided PEM/key/cert path is the intended CLI input
	if err != nil {
		return nil, err
	}
	content, err = DecryptPEM(content, secret)
	if err != nil {
		return nil, err
	}
	defer clear(content)

	block, _ := pem.Decode(content)
	if block == nil {
		return nil, fmt.Errorf("decode certificate PEM: no PEM data found")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return certificate, nil
}

func readPrivateKeyPEMFile(path string, secret string) (any, error) {
	content, err := os.ReadFile(path) // #nosec G304 -- user-provided PEM/key/cert path is the intended CLI input
	if err != nil {
		return nil, err
	}
	content, err = DecryptPEM(content, secret)
	if err != nil {
		return nil, err
	}
	defer clear(content)

	block, _ := pem.Decode(content)
	if block == nil {
		return nil, fmt.Errorf("decode private key PEM: no PEM data found")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		return privateKey, nil
	}
	if privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return privateKey, nil
	}
	if privateKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return privateKey, nil
	}
	return nil, fmt.Errorf("parse private key: %w", err)
}

// ReadPEMFile reads a PEM file and decrypts it when it contains a GoForge
// encrypted PEM envelope.
func ReadPEMFile(path string, secret string) ([]byte, error) {
	content, err := os.ReadFile(path) // #nosec G304 -- user-provided PEM/key/cert path is the intended CLI input
	if err != nil {
		return nil, err
	}
	return DecryptPEM(content, secret)
}

// ReadCertificateFile reads a plain or encrypted certificate PEM file.
func ReadCertificateFile(path string, secret string) (*x509.Certificate, error) {
	return readCertificatePEMFile(path, secret)
}

// ReadPrivateKeyFile reads a plain or encrypted private key PEM file.
func ReadPrivateKeyFile(path string, secret string) (any, error) {
	return readPrivateKeyPEMFile(path, secret)
}

// ReadPublicKeyFile reads a plain or encrypted public key PEM file.
func ReadPublicKeyFile(path string, secret string) (any, error) {
	content, err := ReadPEMFile(path, secret)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(content)
	if block == nil {
		return nil, fmt.Errorf("decode public key PEM: no PEM data found")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return publicKey, nil
}

// DecryptPEM returns plain PEM content. It reads the current and legacy
// GoForge encrypted envelope versions. Unencrypted PEM content is returned as-is.
func DecryptPEM(content []byte, secret string) ([]byte, error) {
	block, _ := pem.Decode(content)
	if block == nil || block.Type != encryptedPEMBlockType {
		return content, nil
	}
	if err := validateEncryptionSecret(secret); err != nil {
		return nil, err
	}

	var payload encryptedPEMPayload
	if err := json.Unmarshal(block.Bytes, &payload); err != nil {
		return nil, fmt.Errorf("decode encrypted PEM payload: %w", err)
	}
	if payload.Algorithm != encryptedPEMAlgorithm {
		return nil, fmt.Errorf("unsupported encrypted PEM algorithm %q", payload.Algorithm)
	}

	var (
		aead cipher.AEAD
		aad  []byte
		err  error
	)
	switch payload.Version {
	case legacyEncryptedPEMVersion:
		aead, err = newLegacyAESGCM(secret)
		aad = []byte(block.Headers["Kind"])
	case encryptedPEMVersion:
		if err := validateEncryptedPEMKDF(payload); err != nil {
			return nil, err
		}
		kdfSalt, decodeErr := base64.StdEncoding.DecodeString(payload.KDFSalt)
		if decodeErr != nil {
			return nil, fmt.Errorf("decode encrypted PEM KDF salt: %w", decodeErr)
		}
		if len(kdfSalt) != encryptedPEMSaltBytes {
			return nil, fmt.Errorf("invalid encrypted PEM KDF salt size")
		}
		aead, err = newArgon2idAESGCM(secret, kdfSalt)
		aad = encryptedPEMAAD(block.Headers["Kind"], payload)
	default:
		return nil, fmt.Errorf("unsupported encrypted PEM version %d", payload.Version)
	}
	if err != nil {
		return nil, err
	}

	nonce, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted PEM nonce: %w", err)
	}
	cipherText, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted PEM ciphertext: %w", err)
	}

	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid encrypted PEM nonce size")
	}

	plainText, err := aead.Open(nil, nonce, cipherText, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt encrypted PEM: %w", err)
	}
	return plainText, nil
}

func requireEncryptedPEM(content []byte, kind string) error {
	block, _ := pem.Decode(content)
	if block == nil {
		return fmt.Errorf("decode encrypted PEM: no PEM data found")
	}
	if block.Type != encryptedPEMBlockType {
		return fmt.Errorf("PEM file is not encrypted")
	}
	if block.Headers["Kind"] != kind {
		return fmt.Errorf("encrypted PEM kind = %q, want %q", block.Headers["Kind"], kind)
	}
	return nil
}

func encryptPEM(content []byte, secret string, kind string, randomSource io.Reader) ([]byte, error) {
	if err := validateEncryptionSecret(secret); err != nil {
		return nil, err
	}

	kdfSalt := make([]byte, encryptedPEMSaltBytes)
	if _, err := io.ReadFull(randomSource, kdfSalt); err != nil {
		return nil, fmt.Errorf("generate encrypted PEM KDF salt: %w", err)
	}
	aead, err := newArgon2idAESGCM(secret, kdfSalt)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(randomSource, nonce); err != nil {
		return nil, fmt.Errorf("generate encrypted PEM nonce: %w", err)
	}

	payload := encryptedPEMPayload{
		Version:    encryptedPEMVersion,
		Algorithm:  encryptedPEMAlgorithm,
		KDF:        encryptedPEMKDF,
		KDFSalt:    base64.StdEncoding.EncodeToString(kdfSalt),
		KDFTime:    encryptedPEMKDFTime,
		KDFMemory:  encryptedPEMKDFMemory,
		KDFThreads: encryptedPEMKDFThreads,
		KDFKeySize: encryptedPEMKDFKeyBytes,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
	}
	cipherText := aead.Seal(nil, nonce, content, encryptedPEMAAD(kind, payload))
	payload.Ciphertext = base64.StdEncoding.EncodeToString(cipherText)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode encrypted PEM payload: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:    encryptedPEMBlockType,
		Headers: map[string]string{"Kind": kind},
		Bytes:   payloadBytes,
	}), nil
}

func validateEncryptionSecret(secret string) error {
	if len([]byte(secret)) < minimumEncryptionSecretBytes {
		return fmt.Errorf("encryption secret must be at least 256 bits")
	}
	return nil
}

func newLegacyAESGCM(secret string) (cipher.AEAD, error) {
	password := []byte(secret)
	defer clear(password)
	key := sha256.Sum256(password)
	defer clear(key[:])
	return newAESGCMWithKey(key[:])
}

func newArgon2idAESGCM(secret string, salt []byte) (cipher.AEAD, error) {
	password := []byte(secret)
	defer clear(password)
	key := argon2.IDKey(
		password,
		salt,
		encryptedPEMKDFTime,
		encryptedPEMKDFMemory,
		encryptedPEMKDFThreads,
		encryptedPEMKDFKeyBytes,
	)
	defer clear(key)
	return newAESGCMWithKey(key)
}

func newAESGCMWithKey(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES-256 cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	return aead, nil
}

func validateEncryptedPEMKDF(payload encryptedPEMPayload) error {
	if payload.KDF != encryptedPEMKDF {
		return fmt.Errorf("unsupported encrypted PEM KDF %q", payload.KDF)
	}
	if payload.KDFTime != encryptedPEMKDFTime ||
		payload.KDFMemory != encryptedPEMKDFMemory ||
		payload.KDFThreads != encryptedPEMKDFThreads ||
		payload.KDFKeySize != encryptedPEMKDFKeyBytes {
		return fmt.Errorf("unsupported encrypted PEM KDF parameters")
	}
	return nil
}

func encryptedPEMAAD(kind string, payload encryptedPEMPayload) []byte {
	return []byte(fmt.Sprintf(
		"%s\x00%s\x00%d\x00%s\x00%s\x00%d\x00%d\x00%d\x00%d",
		encryptedPEMBlockType,
		kind,
		payload.Version,
		payload.Algorithm,
		payload.KDF,
		payload.KDFTime,
		payload.KDFMemory,
		payload.KDFThreads,
		payload.KDFKeySize,
	))
}

func sanitizeStrings(values []string) []string {
	var sanitized []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			sanitized = append(sanitized, value)
		}
	}
	return sanitized
}

func parseIPAddresses(values []string) []net.IP {
	var ips []net.IP
	for _, value := range values {
		if ip := net.ParseIP(strings.TrimSpace(value)); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

func encodePrivateKeyPEM(privateKey any) ([]byte, error) {
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}), nil
}

func encodePublicKeyPEM(publicKey any) ([]byte, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER}), nil
}

type saltedReader struct {
	seed    []byte
	salt    []byte
	counter uint64
	buffer  []byte
}

func (reader *saltedReader) Read(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		if len(reader.buffer) == 0 {
			reader.buffer = reader.nextBlock()
		}

		copied := copy(p[total:], reader.buffer)
		total += copied
		reader.buffer = reader.buffer[copied:]
	}
	return total, nil
}

func (reader *saltedReader) nextBlock() []byte {
	hash := sha256.New()
	hash.Write(reader.seed)
	hash.Write(reader.salt)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], reader.counter)
	hash.Write(counterBytes[:])
	reader.counter++
	return hash.Sum(nil)
}
