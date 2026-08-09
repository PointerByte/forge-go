// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestEncryptedPEMVersion2IsDeterministicForFixedRandomness(t *testing.T) {
	plainText := []byte("deterministic PEM fixture")
	randomness := make([]byte, encryptedPEMSaltBytes+12)
	for index := range randomness {
		randomness[index] = byte(index + 1)
	}

	first, err := encryptPEM(
		plainText,
		testEncryptionSecret,
		encryptedKindPrivateKey,
		bytes.NewReader(randomness),
	)
	if err != nil {
		t.Fatalf("encryptPEM() error = %v", err)
	}
	second, err := encryptPEM(
		plainText,
		testEncryptionSecret,
		encryptedKindPrivateKey,
		bytes.NewReader(randomness),
	)
	if err != nil {
		t.Fatalf("encryptPEM() second error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("fixed randomness did not produce a deterministic envelope")
	}

	block, _ := pem.Decode(first)
	if block == nil {
		t.Fatal("encrypted result does not contain a PEM block")
	}
	var payload encryptedPEMPayload
	if err := json.Unmarshal(block.Bytes, &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Version != encryptedPEMVersion ||
		payload.Algorithm != encryptedPEMAlgorithm ||
		payload.KDF != encryptedPEMKDF ||
		payload.KDFTime != encryptedPEMKDFTime ||
		payload.KDFMemory != encryptedPEMKDFMemory ||
		payload.KDFThreads != encryptedPEMKDFThreads ||
		payload.KDFKeySize != encryptedPEMKDFKeyBytes {
		t.Fatalf("unexpected encrypted payload metadata: %#v", payload)
	}
	if payload.KDFSalt != base64.StdEncoding.EncodeToString(randomness[:encryptedPEMSaltBytes]) {
		t.Fatalf("KDF salt = %q, want deterministic fixture", payload.KDFSalt)
	}
	if payload.Nonce != base64.StdEncoding.EncodeToString(randomness[encryptedPEMSaltBytes:]) {
		t.Fatalf("nonce = %q, want deterministic fixture", payload.Nonce)
	}

	decrypted, err := DecryptPEM(first, testEncryptionSecret)
	if err != nil {
		t.Fatalf("DecryptPEM() error = %v", err)
	}
	if !bytes.Equal(decrypted, plainText) {
		t.Fatalf("DecryptPEM() = %q, want %q", decrypted, plainText)
	}

	block.Headers["Kind"] = encryptedKindCertificate
	if _, err := DecryptPEM(pem.EncodeToMemory(block), testEncryptionSecret); err == nil {
		t.Fatal("tampered PEM kind was not authenticated")
	}
}

func TestEncryptedPEMVersion2RejectsUntrustedKDFMetadata(t *testing.T) {
	randomness := make([]byte, encryptedPEMSaltBytes+12)
	encrypted, err := encryptPEM(
		[]byte("fixture"),
		testEncryptionSecret,
		encryptedKindCertificate,
		bytes.NewReader(randomness),
	)
	if err != nil {
		t.Fatalf("encryptPEM() error = %v", err)
	}
	block, _ := pem.Decode(encrypted)
	var payload encryptedPEMPayload
	if err := json.Unmarshal(block.Bytes, &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	payload.KDFMemory++
	if _, err := DecryptPEM(encryptedPayloadPEM(t, encryptedKindCertificate, payload), testEncryptionSecret); err == nil ||
		!strings.Contains(err.Error(), "unsupported encrypted PEM KDF parameters") {
		t.Fatalf("unexpected KDF parameter error: %v", err)
	}

	payload.KDFMemory = encryptedPEMKDFMemory
	payload.KDF = "UNSUPPORTED"
	if _, err := DecryptPEM(encryptedPayloadPEM(t, encryptedKindCertificate, payload), testEncryptionSecret); err == nil ||
		!strings.Contains(err.Error(), "unsupported encrypted PEM KDF") {
		t.Fatalf("unexpected KDF name error: %v", err)
	}

	payload.KDF = encryptedPEMKDF
	payload.KDFMemory = encryptedPEMKDFMemory
	payload.KDFSalt = "%%%"
	if _, err := DecryptPEM(encryptedPayloadPEM(t, encryptedKindCertificate, payload), testEncryptionSecret); err == nil ||
		!strings.Contains(err.Error(), "decode encrypted PEM KDF salt") {
		t.Fatalf("unexpected KDF salt error: %v", err)
	}
}

func TestEncryptPEMRejectsInvalidSecretAndEntropy(t *testing.T) {
	if _, err := encryptPEM(
		[]byte("fixture"),
		"short",
		encryptedKindCertificate,
		bytes.NewReader(nil),
	); err == nil || !strings.Contains(err.Error(), "at least 256 bits") {
		t.Fatalf("short secret error = %v", err)
	}
	if _, err := encryptPEM(
		[]byte("fixture"),
		testEncryptionSecret,
		encryptedKindCertificate,
		bytes.NewReader(nil),
	); err == nil || !strings.Contains(err.Error(), "KDF salt") {
		t.Fatalf("missing KDF salt entropy error = %v", err)
	}
	if _, err := encryptPEM(
		[]byte("fixture"),
		testEncryptionSecret,
		encryptedKindCertificate,
		bytes.NewReader(make([]byte, encryptedPEMSaltBytes)),
	); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("missing nonce entropy error = %v", err)
	}
	if _, err := newAESGCMWithKey([]byte("short")); err == nil {
		t.Fatal("newAESGCMWithKey() unexpectedly accepted a short key")
	}
}

func TestDecryptPEMSupportsLegacyVersion1(t *testing.T) {
	plainText := []byte("legacy PEM fixture")
	legacy := legacyEncryptedPEMForTest(
		t,
		plainText,
		testEncryptionSecret,
		encryptedKindCertificate,
	)

	decrypted, err := DecryptPEM(legacy, testEncryptionSecret)
	if err != nil {
		t.Fatalf("DecryptPEM(version 1) error = %v", err)
	}
	if !bytes.Equal(decrypted, plainText) {
		t.Fatalf("DecryptPEM(version 1) = %q, want %q", decrypted, plainText)
	}
}

func TestUpdateEncryptionSecretUpgradesLegacyVersion1Batch(t *testing.T) {
	directory := t.TempDir()
	fixtures := []struct {
		name string
		kind string
		mode os.FileMode
	}{
		{name: "cert.pem", kind: encryptedKindCertificate, mode: 0o644},
		{name: "key.pem", kind: encryptedKindPrivateKey, mode: 0o600},
		{name: "public.pem", kind: encryptedKindPublicKey, mode: 0o644},
	}
	paths := make([]string, 0, len(fixtures))
	for _, fixture := range fixtures {
		path := filepath.Join(directory, fixture.name)
		content := legacyEncryptedPEMForTest(
			t,
			[]byte(fixture.kind+" content"),
			testEncryptionSecret,
			fixture.kind,
		)
		if err := os.WriteFile(path, content, fixture.mode); err != nil {
			t.Fatalf("os.WriteFile(%q) error = %v", path, err)
		}
		paths = append(paths, path)
	}

	_, err := UpdateEncryptionSecret(UpdateEncryptionSecretOptions{
		CertificatePath:  paths[0],
		PrivateKeyPath:   paths[1],
		PublicKeyPath:    paths[2],
		EncryptSecretOld: testEncryptionSecret,
		EncryptSecretNew: testEncryptionSecretNew,
	})
	if err != nil {
		t.Fatalf("UpdateEncryptionSecret() error = %v", err)
	}

	for index, fixture := range fixtures {
		content, err := os.ReadFile(paths[index])
		if err != nil {
			t.Fatalf("os.ReadFile(%q) error = %v", paths[index], err)
		}
		block, _ := pem.Decode(content)
		var payload encryptedPEMPayload
		if err := json.Unmarshal(block.Bytes, &payload); err != nil {
			t.Fatalf("json.Unmarshal(%q) error = %v", paths[index], err)
		}
		if payload.Version != encryptedPEMVersion {
			t.Fatalf("%s envelope version = %d, want %d", fixture.kind, payload.Version, encryptedPEMVersion)
		}
		decrypted, err := DecryptPEM(content, testEncryptionSecretNew)
		if err != nil {
			t.Fatalf("DecryptPEM(%s) error = %v", fixture.kind, err)
		}
		if string(decrypted) != fixture.kind+" content" {
			t.Fatalf("DecryptPEM(%s) = %q", fixture.kind, decrypted)
		}
	}
}

func TestUpdateEncryptionSecretWrongCurrentSecretLeavesBatchUnchanged(t *testing.T) {
	directory := t.TempDir()
	fixtures := []struct {
		name string
		kind string
	}{
		{name: "cert.pem", kind: encryptedKindCertificate},
		{name: "key.pem", kind: encryptedKindPrivateKey},
		{name: "public.pem", kind: encryptedKindPublicKey},
	}
	paths := make([]string, 0, len(fixtures))
	before := make([][]byte, 0, len(fixtures))
	for _, fixture := range fixtures {
		path := filepath.Join(directory, fixture.name)
		content := legacyEncryptedPEMForTest(
			t,
			[]byte(fixture.kind+" content"),
			testEncryptionSecret,
			fixture.kind,
		)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("os.WriteFile(%q) error = %v", path, err)
		}
		paths = append(paths, path)
		before = append(before, append([]byte(nil), content...))
	}

	_, err := UpdateEncryptionSecret(UpdateEncryptionSecretOptions{
		CertificatePath:  paths[0],
		PrivateKeyPath:   paths[1],
		PublicKeyPath:    paths[2],
		EncryptSecretOld: strings.Repeat("x", minimumEncryptionSecretBytes),
		EncryptSecretNew: testEncryptionSecretNew,
	})
	if err == nil {
		t.Fatal("UpdateEncryptionSecret() unexpectedly accepted the wrong current secret")
	}
	for index, path := range paths {
		after, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("os.ReadFile(%q) error = %v", path, readErr)
		}
		if !bytes.Equal(after, before[index]) {
			t.Fatalf("%s changed after failed secret validation", path)
		}
	}
}

func TestWritePEMFilesAtomicallyReplacesContentAndModes(t *testing.T) {
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "cert.pem")
	privateKeyPath := filepath.Join(directory, "key.pem")
	if err := os.WriteFile(certificatePath, []byte("old certificate"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	if err := os.WriteFile(privateKeyPath, []byte("old key"), 0o644); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	err := writePEMFilesAtomically([]pemFileUpdate{
		{path: certificatePath, content: []byte("new certificate"), mode: 0o644},
		{path: privateKeyPath, content: []byte("new key"), mode: 0o600},
	})
	if err != nil {
		t.Fatalf("writePEMFilesAtomically() error = %v", err)
	}
	assertFileContentAndMode(t, certificatePath, "new certificate", 0o644)
	assertFileContentAndMode(t, privateKeyPath, "new key", 0o600)
	assertNoAtomicTemporaryFiles(t, directory)
}

func TestWritePEMFilesAtomicallyLeavesTargetsOnStagingFailure(t *testing.T) {
	directory := t.TempDir()
	existingPath := filepath.Join(directory, "existing.pem")
	if err := os.WriteFile(existingPath, []byte("original"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	err := writePEMFilesAtomically([]pemFileUpdate{
		{path: existingPath, content: []byte("replacement"), mode: 0o600},
		{path: filepath.Join(directory, "missing", "new.pem"), content: []byte("new"), mode: 0o600},
	})
	if err == nil {
		t.Fatal("writePEMFilesAtomically() unexpectedly succeeded")
	}
	assertFileContentAndMode(t, existingPath, "original", 0o600)
	assertNoAtomicTemporaryFiles(t, directory)
}

func TestWritePEMFilesAtomicallyRollsBackReportedSyncFailure(t *testing.T) {
	directory := t.TempDir()
	existingPath := filepath.Join(directory, "existing.pem")
	newPath := filepath.Join(directory, "new.pem")
	if err := os.WriteFile(existingPath, []byte("original"), 0o644); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	err := writePEMFilesAtomicallyWithSync(
		[]pemFileUpdate{
			{path: existingPath, content: []byte("replacement"), mode: 0o600},
			{path: newPath, content: []byte("new"), mode: 0o600},
		},
		func([]stagedPEMFile) error {
			return errors.New("injected directory sync failure")
		},
	)
	if err == nil || !strings.Contains(err.Error(), "injected directory sync failure") {
		t.Fatalf("write error = %v, want injected sync failure", err)
	}
	assertFileContentAndMode(t, existingPath, "original", 0o644)
	if _, err := os.Stat(newPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new target remained after rollback: %v", err)
	}
	assertNoAtomicTemporaryFiles(t, directory)
}

func TestWritePEMFilesAtomicallyRejectsUnsafeAndDuplicateTargets(t *testing.T) {
	directory := t.TempDir()
	regularPath := filepath.Join(directory, "regular.pem")
	linkPath := filepath.Join(directory, "link.pem")
	if err := os.WriteFile(regularPath, []byte("original"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	if err := os.Symlink(regularPath, linkPath); err != nil {
		t.Fatalf("os.Symlink() error = %v", err)
	}

	if err := writePEMFilesAtomically([]pemFileUpdate{{
		path: linkPath, content: []byte("replacement"), mode: 0o600,
	}}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("unsafe target error = %v", err)
	}
	assertFileContentAndMode(t, regularPath, "original", 0o600)

	if err := writePEMFilesAtomically([]pemFileUpdate{
		{path: regularPath, content: []byte("one"), mode: 0o600},
		{path: regularPath, content: []byte("two"), mode: 0o600},
	}); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate target error = %v", err)
	}
	assertFileContentAndMode(t, regularPath, "original", 0o600)
	assertNoAtomicTemporaryFiles(t, directory)
}

func TestWritePEMFilesAtomicallyRejectsInvalidTargetPaths(t *testing.T) {
	if err := writePEMFilesAtomically([]pemFileUpdate{{
		path: "", content: []byte("content"), mode: 0o600,
	}}); err == nil || !strings.Contains(err.Error(), "path is required") {
		t.Fatalf("empty target error = %v", err)
	}

	directory := t.TempDir()
	parentFile := filepath.Join(directory, "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("content"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(parent) error = %v", err)
	}
	if err := writePEMFilesAtomically([]pemFileUpdate{{
		path: filepath.Join(parentFile, "output.pem"), content: []byte("content"), mode: 0o600,
	}}); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("non-directory parent error = %v", err)
	}
}

func TestValidateStagedTargetsUnchangedDetectsContentAndExistenceRaces(t *testing.T) {
	directory := t.TempDir()
	existingPath := filepath.Join(directory, "existing.pem")
	if err := os.WriteFile(existingPath, []byte("original"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(existing) error = %v", err)
	}
	info, err := os.Lstat(existingPath)
	if err != nil {
		t.Fatalf("os.Lstat(existing) error = %v", err)
	}
	originalContent, originalInfo, err := snapshotExistingFile(existingPath, info)
	if err != nil {
		t.Fatalf("snapshotExistingFile() error = %v", err)
	}
	defer clear(originalContent)
	stagedExisting := []stagedPEMFile{{
		update:          pemFileUpdate{path: existingPath},
		originalContent: originalContent,
		originalMode:    originalInfo.Mode().Perm(),
		originalInfo:    originalInfo,
		existed:         true,
	}}
	if err := os.WriteFile(existingPath, []byte("modified"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(modified) error = %v", err)
	}
	if err := validateStagedTargetsUnchanged(stagedExisting); err == nil ||
		!strings.Contains(err.Error(), "changed before commit") {
		t.Fatalf("content race error = %v", err)
	}

	appearedPath := filepath.Join(directory, "appeared.pem")
	stagedMissing := []stagedPEMFile{{
		update: pemFileUpdate{path: appearedPath},
	}}
	if err := os.WriteFile(appearedPath, []byte("appeared"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(appeared) error = %v", err)
	}
	if err := validateStagedTargetsUnchanged(stagedMissing); err == nil ||
		!strings.Contains(err.Error(), "appeared before commit") {
		t.Fatalf("existence race error = %v", err)
	}
}

func TestSnapshotAndStageRejectChangedOrFailingInputs(t *testing.T) {
	directory := t.TempDir()
	expectedPath := filepath.Join(directory, "expected.pem")
	otherPath := filepath.Join(directory, "other.pem")
	if err := os.WriteFile(expectedPath, []byte("expected"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(expected) error = %v", err)
	}
	if err := os.WriteFile(otherPath, []byte("other"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(other) error = %v", err)
	}
	expectedInfo, err := os.Lstat(expectedPath)
	if err != nil {
		t.Fatalf("os.Lstat(expected) error = %v", err)
	}
	if content, _, err := snapshotExistingFile(otherPath, expectedInfo); err == nil ||
		!strings.Contains(err.Error(), "changed while it was opened") {
		clear(content)
		t.Fatalf("changed snapshot error = %v", err)
	}

	stagedPath, err := stagePEMReader(
		filepath.Join(directory, "failed.pem"),
		".tmp-",
		failingReader{},
		0o600,
	)
	if err == nil || !strings.Contains(err.Error(), "injected read failure") {
		t.Fatalf("stage reader error = %v", err)
	}
	if stagedPath != "" {
		t.Fatalf("failed stage returned temporary path %q", stagedPath)
	}
	assertNoAtomicTemporaryFiles(t, directory)
}

func TestResolveSecretSourceFromEnvironmentAndFile(t *testing.T) {
	t.Setenv("GOFORGE_TEST_SECRET", testEncryptionSecret)
	fromEnvironment, err := resolveSecretSource(
		"test secret",
		"",
		secretSourceFlags{environment: "GOFORGE_TEST_SECRET"},
	)
	if err != nil {
		t.Fatalf("resolveSecretSource(environment) error = %v", err)
	}
	if fromEnvironment != testEncryptionSecret {
		t.Fatal("environment secret was not returned unchanged")
	}

	secretPath := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretPath, []byte(testEncryptionSecret+"\r\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(secret) error = %v", err)
	}
	fromFile, err := resolveSecretSource(
		"test secret",
		"",
		secretSourceFlags{file: secretPath},
	)
	if err != nil {
		t.Fatalf("resolveSecretSource(file) error = %v", err)
	}
	if fromFile != testEncryptionSecret {
		t.Fatalf("file secret = %q, want trailing line ending removed", fromFile)
	}

	if _, err := resolveSecretSource(
		"test secret",
		testEncryptionSecret,
		secretSourceFlags{environment: "GOFORGE_TEST_SECRET"},
	); err == nil || !strings.Contains(err.Error(), "multiple secret sources") {
		t.Fatalf("ambiguous source error = %v", err)
	}
}

func TestResolveSecretSourceRejectsMissingAndEmptySources(t *testing.T) {
	if literal, err := resolveSecretSource("test secret", testEncryptionSecret, secretSourceFlags{}); err != nil ||
		literal != testEncryptionSecret {
		t.Fatalf("literal source = %q, error = %v", literal, err)
	}
	if _, err := resolveSecretSource(
		"test secret",
		"",
		secretSourceFlags{environment: "GOFORGE_MISSING_SECRET"},
	); err == nil || !strings.Contains(err.Error(), "is not set") {
		t.Fatalf("missing environment error = %v", err)
	}

	t.Setenv("GOFORGE_EMPTY_SECRET", "")
	if _, err := resolveSecretSource(
		"test secret",
		"",
		secretSourceFlags{environment: "GOFORGE_EMPTY_SECRET"},
	); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("empty environment error = %v", err)
	}
	if _, err := resolveSecretSource(
		"test secret",
		"",
		secretSourceFlags{file: filepath.Join(t.TempDir(), "missing")},
	); err == nil || !strings.Contains(err.Error(), "read test secret file") {
		t.Fatalf("missing file error = %v", err)
	}
}

func TestReadSecretFileRejectsUnsafeOrUnboundedSources(t *testing.T) {
	directory := t.TempDir()
	secretPath := filepath.Join(directory, "secret")
	if err := os.WriteFile(secretPath, []byte(testEncryptionSecret), 0o600); err != nil {
		t.Fatalf("os.WriteFile(secret) error = %v", err)
	}
	linkPath := filepath.Join(directory, "secret-link")
	if err := os.Symlink(secretPath, linkPath); err != nil {
		t.Fatalf("os.Symlink() error = %v", err)
	}
	if _, err := readSecretFile(linkPath); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlink secret error = %v", err)
	}

	largePath := filepath.Join(directory, "large-secret")
	if err := os.WriteFile(largePath, bytes.Repeat([]byte{'x'}, maximumSecretFileBytes+1), 0o600); err != nil {
		t.Fatalf("os.WriteFile(large secret) error = %v", err)
	}
	if _, err := readSecretFile(largePath); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("large secret error = %v", err)
	}

	emptyPath := filepath.Join(directory, "empty-secret")
	if err := os.WriteFile(emptyPath, []byte("\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(empty secret) error = %v", err)
	}
	if _, err := readSecretFile(emptyPath); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty secret file error = %v", err)
	}
}

func TestTrimOneLineEnding(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "none", content: "secret", want: "secret"},
		{name: "lf", content: "secret\n", want: "secret"},
		{name: "crlf", content: "secret\r\n", want: "secret"},
		{name: "only one", content: "secret\n\n", want: "secret\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := string(trimOneLineEnding([]byte(test.content))); got != test.want {
				t.Fatalf("trimOneLineEnding(%q) = %q, want %q", test.content, got, test.want)
			}
		})
	}
}

func TestCommandsExposeSafeSecretSourcesAndDeprecateLiterals(t *testing.T) {
	app := &App{
		streams: IOStreams{
			In:  strings.NewReader(""),
			Out: &bytes.Buffer{},
			Err: &bytes.Buffer{},
		},
		generator: NewGenerator(),
	}

	assertSecretFlags(t, newGenerateCommand(app).Cobra(), []string{
		"encrypt-secret",
		"signed-by-secret",
		"ca-key-secret",
	})
	assertSecretFlags(t, newReadCommand(app).Cobra(), []string{"secret"})
	assertSecretFlags(t, newReencryptCommand(app).Cobra(), []string{
		"encrypt-secret-old",
		"encrypt-secret-new",
	})
}

func TestGenerateCommandUsesEnvironmentSecretWithoutDisclosingIt(t *testing.T) {
	t.Setenv("GOFORGE_GENERATE_SECRET", testEncryptionSecret)
	output := &bytes.Buffer{}
	errorOutput := &bytes.Buffer{}
	app := &App{
		streams: IOStreams{
			In:  strings.NewReader(""),
			Out: output,
			Err: errorOutput,
		},
		generator: NewGenerator(),
	}
	directory := t.TempDir()
	command := app.rootCommand()
	command.SetArgs([]string{
		"generate",
		"--algorithm", algorithmEd25519,
		"--dir", directory,
		"--encrypt-secret-env", "GOFORGE_GENERATE_SECRET",
	})
	if err := command.Execute(); err != nil {
		t.Fatalf("generate command error = %v", err)
	}
	if strings.Contains(output.String(), testEncryptionSecret) ||
		strings.Contains(errorOutput.String(), testEncryptionSecret) {
		t.Fatal("command output disclosed the environment secret")
	}

	content, err := os.ReadFile(filepath.Join(directory, "key.pem"))
	if err != nil {
		t.Fatalf("os.ReadFile(key.pem) error = %v", err)
	}
	block, _ := pem.Decode(content)
	var payload encryptedPEMPayload
	if err := json.Unmarshal(block.Bytes, &payload); err != nil {
		t.Fatalf("json.Unmarshal(key payload) error = %v", err)
	}
	if payload.Version != encryptedPEMVersion {
		t.Fatalf("generated envelope version = %d, want %d", payload.Version, encryptedPEMVersion)
	}
}

func TestReadCommandUsesSecretFileAndWritesOwnerOnly(t *testing.T) {
	directory := t.TempDir()
	plainText := []byte("decrypted PEM fixture\n")
	encrypted, err := encryptPEM(
		plainText,
		testEncryptionSecret,
		encryptedKindPrivateKey,
		bytes.NewReader(make([]byte, encryptedPEMSaltBytes+12)),
	)
	if err != nil {
		t.Fatalf("encryptPEM() error = %v", err)
	}
	inputPath := filepath.Join(directory, "encrypted.pem")
	secretPath := filepath.Join(directory, "secret")
	outputPath := filepath.Join(directory, "decrypted.pem")
	if err := os.WriteFile(inputPath, encrypted, 0o600); err != nil {
		t.Fatalf("os.WriteFile(input) error = %v", err)
	}
	if err := os.WriteFile(secretPath, []byte(testEncryptionSecret+"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(secret) error = %v", err)
	}

	app := &App{
		streams: IOStreams{
			In:  strings.NewReader(""),
			Out: &bytes.Buffer{},
			Err: &bytes.Buffer{},
		},
		generator: NewGenerator(),
	}
	command := app.rootCommand()
	command.SetArgs([]string{
		"read",
		"--file", inputPath,
		"--secret-file", secretPath,
		"--out", outputPath,
	})
	if err := command.Execute(); err != nil {
		t.Fatalf("read command error = %v", err)
	}
	assertFileContentAndMode(t, outputPath, string(plainText), 0o600)
}

func legacyEncryptedPEMForTest(t *testing.T, plainText []byte, secret string, kind string) []byte {
	t.Helper()

	aead, err := newLegacyAESGCM(secret)
	if err != nil {
		t.Fatalf("newLegacyAESGCM() error = %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	for index := range nonce {
		nonce[index] = byte(index + 1)
	}
	cipherText := aead.Seal(nil, nonce, plainText, []byte(kind))
	payload, err := json.Marshal(encryptedPEMPayload{
		Version:    legacyEncryptedPEMVersion,
		Algorithm:  encryptedPEMAlgorithm,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(cipherText),
	})
	if err != nil {
		t.Fatalf("json.Marshal(legacy payload) error = %v", err)
	}
	return encryptedTestPEM(t, kind, payload)
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("injected read failure")
}

func assertFileContentAndMode(t *testing.T, path string, wantContent string, wantMode os.FileMode) {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) error = %v", path, err)
	}
	if string(content) != wantContent {
		t.Fatalf("%s content = %q, want %q", path, content, wantContent)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat(%q) error = %v", path, err)
	}
	if info.Mode().Perm() != wantMode {
		t.Fatalf("%s mode = %04o, want %04o", path, info.Mode().Perm(), wantMode)
	}
}

func assertNoAtomicTemporaryFiles(t *testing.T, directory string) {
	t.Helper()

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("os.ReadDir(%q) error = %v", directory, err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") || strings.Contains(entry.Name(), ".backup-") {
			t.Fatalf("atomic temporary artifact remains: %s", entry.Name())
		}
	}
}

func assertSecretFlags(t *testing.T, command *cobra.Command, literals []string) {
	t.Helper()

	for _, literal := range literals {
		flag := command.Flags().Lookup(literal)
		if flag == nil {
			t.Fatalf("literal flag --%s is not registered", literal)
		}
		if flag.Deprecated == "" {
			t.Fatalf("literal flag --%s is not deprecated", literal)
		}
		for _, suffix := range []string{"-env", "-file"} {
			if command.Flags().Lookup(literal+suffix) == nil {
				t.Fatalf("safe source flag --%s%s is not registered", literal, suffix)
			}
		}
	}
}
