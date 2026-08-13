// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

const (
	algorithmRSA     = "rsa"
	algorithmECC     = "ecc"
	algorithmEd25519 = "ed25519"
	curveP256        = "p256"
	curveP384        = "p384"
	curveP521        = "p521"
)

type generateCommand struct {
	app                  *App
	options              *Options
	encryptSecretSource  secretSourceFlags
	signedBySecretSource secretSourceFlags
	caKeySecretSource    secretSourceFlags
}

type readCommand struct {
	app        *App
	file       string
	secret     string
	source     secretSourceFlags
	outputFile string
}

type reencryptCommand struct {
	app             *App
	options         *UpdateEncryptionSecretOptions
	oldSecretSource secretSourceFlags
	newSecretSource secretSourceFlags
}

// newGenerateCommand creates the certificate generation command.
func newGenerateCommand(app *App) Command {
	return &generateCommand{
		app:     app,
		options: defaultOptions(),
	}
}

// Cobra creates the executable Cobra command that resolves options and generates PEM files.
func (command *generateCommand) Cobra() *cobra.Command {
	cobraCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a certificate and key files",
		RunE: func(cmd *cobra.Command, args []string) error {
			options := *command.options
			var err error
			options.EncryptSecret, err = resolveSecretSource("encryption secret", options.EncryptSecret, command.encryptSecretSource)
			if err != nil {
				return err
			}
			options.SignedBySecret, err = resolveSecretSource("signed-by secret", options.SignedBySecret, command.signedBySecretSource)
			if err != nil {
				return err
			}
			options.CAKeySecret, err = resolveSecretSource("CA key secret", options.CAKeySecret, command.caKeySecretSource)
			if err != nil {
				return err
			}

			result, err := command.app.generator.Generate(options)
			if err != nil {
				return err
			}

			_, err = fmt.Fprintf(
				command.app.streams.Out,
				"Certificate generated in %s using %s\nCert: %s\nKey: %s\nPublic key: %s\nEncrypted: %t\n",
				result.OutputDir,
				strings.ToUpper(result.Algorithm),
				result.CertificatePath,
				result.PrivateKeyPath,
				result.PublicKeyPath,
				result.Encrypted,
			)
			return err
		},
	}

	cobraCmd.Flags().StringVarP(&command.options.Algorithm, "algorithm", "a", command.options.Algorithm, "Certificate algorithm: rsa, ecc, or ed25519")
	cobraCmd.Flags().StringVarP(&command.options.OutputDir, "dir", "d", command.options.OutputDir, "Output directory for the generated PEM files")
	cobraCmd.Flags().StringVarP(&command.options.CommonName, "common-name", "n", command.options.CommonName, "Common Name for the self-signed certificate")
	cobraCmd.Flags().StringSliceVar(&command.options.DNSNames, "dns", command.options.DNSNames, "DNS Subject Alternative Names")
	cobraCmd.Flags().StringVar(&command.options.Organization, "organization", command.options.Organization, "Organization value for the certificate subject")
	cobraCmd.Flags().IntVar(&command.options.ValidForDays, "days", command.options.ValidForDays, "Certificate validity in days")
	cobraCmd.Flags().IntVar(&command.options.RSAKeySize, "rsa-bits", command.options.RSAKeySize, "RSA key size in bits")
	cobraCmd.Flags().StringVar(&command.options.ECCCurve, "ecc-curve", command.options.ECCCurve, "ECC curve: p256, p384, or p521")
	cobraCmd.Flags().StringVar(&command.options.Salt, "salt", command.options.Salt, "Optional extra entropy salt used during key and certificate generation")
	cobraCmd.Flags().StringVar(&command.options.CertFileName, "cert-file", command.options.CertFileName, "Certificate file name")
	cobraCmd.Flags().StringVar(&command.options.KeyFileName, "key-file", command.options.KeyFileName, "Private key file name")
	cobraCmd.Flags().StringVar(&command.options.PublicKeyFileName, "public-key-file", command.options.PublicKeyFileName, "Public key file name")
	cobraCmd.Flags().StringVar(&command.options.SignedBy, "signed-by", command.options.SignedBy, "CA certificate PEM file used to sign the generated certificate")
	cobraCmd.Flags().StringVar(&command.options.CAKeyFile, "ca-key", command.options.CAKeyFile, "CA private key PEM file used to sign the generated certificate")
	cobraCmd.Flags().BoolVar(&command.options.IsCA, "ca", command.options.IsCA, "Mark the generated certificate as a certificate authority")
	cobraCmd.Flags().StringVar(&command.options.EncryptSecret, "encrypt-secret", command.options.EncryptSecret, "Secret used to encrypt generated PEM files; must be at least 256 bits")
	cobraCmd.Flags().StringVar(&command.options.SignedBySecret, "signed-by-secret", command.options.SignedBySecret, "Secret used to read an encrypted signed-by certificate")
	cobraCmd.Flags().StringVar(&command.options.CAKeySecret, "ca-key-secret", command.options.CAKeySecret, "Secret used to read an encrypted CA private key")
	addSecretSourceFlags(cobraCmd, &command.encryptSecretSource, "encrypt-secret", "generated PEM encryption secret")
	addSecretSourceFlags(cobraCmd, &command.signedBySecretSource, "signed-by-secret", "signed-by certificate secret")
	addSecretSourceFlags(cobraCmd, &command.caKeySecretSource, "ca-key-secret", "CA private key secret")
	deprecateLiteralSecretFlag(cobraCmd, "encrypt-secret")
	deprecateLiteralSecretFlag(cobraCmd, "signed-by-secret")
	deprecateLiteralSecretFlag(cobraCmd, "ca-key-secret")
	return cobraCmd
}

// newReadCommand creates the encrypted PEM read command.
func newReadCommand(app *App) Command {
	return &readCommand{
		app: app,
	}
}

// Cobra creates the executable Cobra command that reads plain or encrypted PEM files.
func (command *readCommand) Cobra() *cobra.Command {
	cobraCmd := &cobra.Command{
		Use:   "read",
		Short: "Read a plain or encrypted PEM file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(command.file) == "" {
				return fmt.Errorf("file is required")
			}

			secret, err := resolveSecretSource("decryption secret", command.secret, command.source)
			if err != nil {
				return err
			}
			content, err := ReadPEMFile(command.file, secret)
			if err != nil {
				return err
			}
			defer clear(content)
			if strings.TrimSpace(command.outputFile) != "" {
				return command.app.generator.writeFilesFn([]pemFileUpdate{{
					path:    command.outputFile,
					content: content,
					mode:    0o600,
				}})
			}
			_, err = command.app.streams.Out.Write(content)
			return err
		},
	}

	cobraCmd.Flags().StringVarP(&command.file, "file", "f", command.file, "Plain or encrypted PEM file to read")
	cobraCmd.Flags().StringVarP(&command.secret, "secret", "s", command.secret, "Secret used to decrypt encrypted PEM files")
	cobraCmd.Flags().StringVarP(&command.outputFile, "out", "o", command.outputFile, "Optional output file for the decrypted PEM")
	addSecretSourceFlags(cobraCmd, &command.source, "secret", "decryption secret")
	deprecateLiteralSecretFlag(cobraCmd, "secret")
	return cobraCmd
}

// newReencryptCommand creates the encrypted PEM secret update command.
func newReencryptCommand(app *App) Command {
	defaults := defaultOptions()
	return &reencryptCommand{
		app: app,
		options: &UpdateEncryptionSecretOptions{
			CertificatePath: defaults.CertFileName,
			PrivateKeyPath:  defaults.KeyFileName,
			PublicKeyPath:   defaults.PublicKeyFileName,
		},
	}
}

// Cobra creates the executable Cobra command that updates encrypted PEM secrets.
func (command *reencryptCommand) Cobra() *cobra.Command {
	cobraCmd := &cobra.Command{
		Use:   "reencrypt",
		Short: "Update the encryption secret for existing encrypted PEM files",
		RunE: func(cmd *cobra.Command, args []string) error {
			options := *command.options
			var err error
			options.EncryptSecretOld, err = resolveSecretSource("old encryption secret", options.EncryptSecretOld, command.oldSecretSource)
			if err != nil {
				return err
			}
			options.EncryptSecretNew, err = resolveSecretSource("new encryption secret", options.EncryptSecretNew, command.newSecretSource)
			if err != nil {
				return err
			}

			result, err := command.app.generator.UpdateEncryptionSecret(options)
			if err != nil {
				return err
			}

			_, err = fmt.Fprintf(
				command.app.streams.Out,
				"Encryption secret updated\nCert: %s\nKey: %s\nPublic key: %s\n",
				result.CertificatePath,
				result.PrivateKeyPath,
				result.PublicKeyPath,
			)
			return err
		},
	}

	cobraCmd.Flags().StringVar(&command.options.CertificatePath, "cert-file", command.options.CertificatePath, "Encrypted certificate PEM file path")
	cobraCmd.Flags().StringVar(&command.options.PrivateKeyPath, "key-file", command.options.PrivateKeyPath, "Encrypted private key PEM file path")
	cobraCmd.Flags().StringVar(&command.options.PublicKeyPath, "public-key-file", command.options.PublicKeyPath, "Encrypted public key PEM file path")
	cobraCmd.Flags().StringVar(&command.options.EncryptSecretOld, "encrypt-secret-old", command.options.EncryptSecretOld, "Current secret used to decrypt encrypted PEM files")
	cobraCmd.Flags().StringVar(&command.options.EncryptSecretNew, "encrypt-secret-new", command.options.EncryptSecretNew, "New secret used to re-encrypt encrypted PEM files")
	addSecretSourceFlags(cobraCmd, &command.oldSecretSource, "encrypt-secret-old", "current encryption secret")
	addSecretSourceFlags(cobraCmd, &command.newSecretSource, "encrypt-secret-new", "new encryption secret")
	deprecateLiteralSecretFlag(cobraCmd, "encrypt-secret-old")
	deprecateLiteralSecretFlag(cobraCmd, "encrypt-secret-new")
	return cobraCmd
}

func addSecretSourceFlags(command *cobra.Command, source *secretSourceFlags, baseName string, description string) {
	command.Flags().StringVar(
		&source.environment,
		baseName+"-env",
		source.environment,
		"Environment variable containing the "+description,
	)
	command.Flags().StringVar(
		&source.file,
		baseName+"-file",
		source.file,
		"Regular file containing the "+description,
	)
}

func deprecateLiteralSecretFlag(command *cobra.Command, name string) {
	flag := command.Flags().Lookup(name)
	if flag != nil {
		flag.Deprecated = "use --" + name + "-env or --" + name + "-file to keep the secret out of process arguments"
	}
}
