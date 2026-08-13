// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewAppAndExecute(t *testing.T) {
	app := NewApp()
	if app == nil {
		t.Fatal("expected app")
	}
	if app.streams.In == nil || app.streams.Out == nil || app.streams.Err == nil {
		t.Fatal("expected streams to be initialized")
	}
	if app.generator == nil {
		t.Fatal("expected generator to be initialized")
	}

	root := app.rootCommand()
	if root.Use != "go-openssl" {
		t.Fatalf("expected root use go-openssl, got %q", root.Use)
	}
}

func TestExecuteRunsRootCommandHelp(t *testing.T) {
	app := &App{
		streams: IOStreams{
			In:  strings.NewReader(""),
			Out: &bytes.Buffer{},
			Err: &bytes.Buffer{},
		},
		generator: NewGenerator(),
	}

	root := app.rootCommand()
	root.SetArgs([]string{"help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("expected help execution without error, got %v", err)
	}
}

func TestAppExecute(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() {
		os.Args = originalArgs
	})

	app := &App{
		streams: IOStreams{
			In:  strings.NewReader(""),
			Out: &bytes.Buffer{},
			Err: &bytes.Buffer{},
		},
		generator: NewGenerator(),
	}

	os.Args = []string{"go-openssl", "help"}
	if err := app.Execute(); err != nil {
		t.Fatalf("expected app.Execute without error, got %v", err)
	}
}

func TestGenerateCommandCobra(t *testing.T) {
	app := &App{
		streams:   IOStreams{In: strings.NewReader(""), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}},
		generator: NewGenerator(),
	}

	generateCmd := newGenerateCommand(app).Cobra()
	if generateCmd.Use != "generate" {
		t.Fatalf("expected use generate, got %q", generateCmd.Use)
	}
	if generateCmd.Flag("algorithm") == nil || generateCmd.Flag("dir") == nil || generateCmd.Flag("salt") == nil ||
		generateCmd.Flag("signed-by") == nil || generateCmd.Flag("ca-key") == nil ||
		generateCmd.Flag("encrypt-secret") == nil || generateCmd.Flag("ca-key-secret") == nil {
		t.Fatal("expected certificate flags to be registered")
	}

	readCmd := newReadCommand(app).Cobra()
	if readCmd.Use != "read" {
		t.Fatalf("expected use read, got %q", readCmd.Use)
	}
	if readCmd.Flag("file") == nil || readCmd.Flag("secret") == nil || readCmd.Flag("out") == nil {
		t.Fatal("expected read flags to be registered")
	}

	reencryptCmd := newReencryptCommand(app).Cobra()
	if reencryptCmd.Use != "reencrypt" {
		t.Fatalf("expected use reencrypt, got %q", reencryptCmd.Use)
	}
	if reencryptCmd.Flag("cert-file") == nil || reencryptCmd.Flag("key-file") == nil ||
		reencryptCmd.Flag("public-key-file") == nil || reencryptCmd.Flag("encrypt-secret-old") == nil ||
		reencryptCmd.Flag("encrypt-secret-new") == nil {
		t.Fatal("expected reencrypt flags to be registered")
	}
}

func TestGenerateCommandRunE(t *testing.T) {
	output := &bytes.Buffer{}
	app := &App{
		streams: IOStreams{
			In:  strings.NewReader(""),
			Out: output,
			Err: &bytes.Buffer{},
		},
		generator: NewGenerator(),
	}

	cmd := app.rootCommand()
	dir := filepath.Join(t.TempDir(), "certs")
	cmd.SetArgs([]string{
		"generate",
		"--algorithm", algorithmECC,
		"--ecc-curve", curveP256,
		"--common-name", "localhost",
		"--dir", dir,
		"--salt", "pepper",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command execution without error, got %v", err)
	}
	if !strings.Contains(output.String(), "Certificate generated in") {
		t.Fatalf("expected success output, got %q", output.String())
	}
}

func TestReadCommandRunE(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	result, err := GenerateCertificates(Options{
		OutputDir:     dir,
		CommonName:    "localhost",
		EncryptSecret: testEncryptionSecret,
	})
	if err != nil {
		t.Fatalf("GenerateCertificates returned error: %v", err)
	}

	output := &bytes.Buffer{}
	app := &App{
		streams: IOStreams{
			In:  strings.NewReader(""),
			Out: output,
			Err: &bytes.Buffer{},
		},
		generator: NewGenerator(),
	}

	cmd := app.rootCommand()
	cmd.SetArgs([]string{
		"read",
		"--file", result.CertificatePath,
		"--secret", testEncryptionSecret,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected read command execution without error, got %v", err)
	}
	if !strings.Contains(output.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("expected decrypted certificate output, got %q", output.String())
	}
}

func TestReencryptCommandRunE(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	result, err := GenerateCertificates(Options{
		OutputDir:     dir,
		CommonName:    "localhost",
		EncryptSecret: testEncryptionSecret,
	})
	if err != nil {
		t.Fatalf("GenerateCertificates returned error: %v", err)
	}

	output := &bytes.Buffer{}
	app := &App{
		streams: IOStreams{
			In:  strings.NewReader(""),
			Out: output,
			Err: &bytes.Buffer{},
		},
		generator: NewGenerator(),
	}

	cmd := app.rootCommand()
	cmd.SetArgs([]string{
		"reencrypt",
		"--cert-file", result.CertificatePath,
		"--key-file", result.PrivateKeyPath,
		"--public-key-file", result.PublicKeyPath,
		"--encrypt-secret-old", testEncryptionSecret,
		"--encrypt-secret-new", testEncryptionSecretNew,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected reencrypt command execution without error, got %v", err)
	}
	if !strings.Contains(output.String(), "Encryption secret updated") {
		t.Fatalf("expected success output, got %q", output.String())
	}
	if _, err := ReadCertificateFile(result.CertificatePath, testEncryptionSecretNew); err != nil {
		t.Fatalf("expected certificate to be readable with new secret, got %v", err)
	}
	if _, err := ReadCertificateFile(result.CertificatePath, testEncryptionSecret); err == nil {
		t.Fatal("expected old secret to fail after reencrypt command")
	}
}
