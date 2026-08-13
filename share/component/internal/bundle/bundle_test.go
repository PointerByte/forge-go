package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateWritesStrictDeterministicBundle(t *testing.T) {
	artifacts := t.TempDir()
	portableRoot := t.TempDir()
	writeFixture(t, filepath.Join(artifacts, "goforge.component.wasm"), "component")
	writeFixture(t, filepath.Join(artifacts, "goforge.component.wit"), "pointerbyte:goforge/operations@0.1.0\nwasi:cli/environment@0.2.12")
	writeFixture(t, filepath.Join(artifacts, "host", "goforge.js"), "export const instantiate = () => {};")
	writeFixture(t, filepath.Join(artifacts, "host", "goforge.core.wasm"), "core")

	vectors, err := os.ReadFile("../../../portable/testdata/vectors/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(portableRoot, "testdata", "vectors"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(portableRoot, "testdata", "vectors", "v1.json"), vectors, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Generate(artifacts, portableRoot, ComponentizeGoToolchain()); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(artifacts, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Generate(artifacts, portableRoot, ComponentizeGoToolchain()); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(artifacts, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("bundle generation is not deterministic")
	}

	encoded, err := os.ReadFile(filepath.Join(artifacts, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{"abi", "capabilities", "componentVersion", "coreModules", "glue", "operations", "schema", "source", "witPackage"}
	if len(value) != len(wantKeys) {
		t.Fatalf("manifest has unexpected fields: %s", encoded)
	}
	for _, key := range wantKeys {
		if _, found := value[key]; !found {
			t.Fatalf("manifest is missing %q", key)
		}
	}
	if !strings.Contains(string(encoded), `"schema": "goforge.bundle-manifest.v1"`) ||
		!strings.Contains(string(encoded), `"witPackage": "pointerbyte:goforge@0.1.0"`) {
		t.Fatalf("manifest identity mismatch: %s", encoded)
	}
}

func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveRootRejectsMissingAndNonDirectoryRoots(t *testing.T) {
	if _, err := resolveRoot(""); err == nil {
		t.Fatal("an empty root must be rejected")
	}
	if _, err := resolveRoot(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a missing root must be rejected")
	}
	file := filepath.Join(t.TempDir(), "regular")
	writeFixture(t, file, "not a directory")
	if _, err := resolveRoot(file); err == nil {
		t.Fatal("a regular file must not be accepted as a bundle root")
	}
	root := t.TempDir()
	resolved, err := resolveRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(resolved) {
		t.Fatalf("resolveRoot must return an absolute path, got %q", resolved)
	}
}

func TestContainedRejectsEveryEscapeFromTheBundleRoot(t *testing.T) {
	root := t.TempDir()
	for _, escape := range []string{
		"..",
		filepath.Join("..", "outside"),
		filepath.Join("host", "..", "..", "outside"),
		filepath.Join(filepath.Dir(root), "sibling"),
		"/etc/passwd",
	} {
		if _, err := contained(root, escape); err == nil {
			t.Fatalf("path %q must not be accepted inside %q", escape, root)
		}
	}

	for _, inside := range []string{
		"manifest.json",
		filepath.Join("host", "goforge.js"),
		filepath.Join("vectors", "v1.json"),
		filepath.Join(root, "manifest.json"),
	} {
		if _, err := contained(root, inside); err != nil {
			t.Fatalf("path %q must be accepted inside %q: %v", inside, root, err)
		}
	}
}

func TestContainedReadersAndWritersRefuseToLeaveTheRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	writeFixture(t, outside, "must not be read")

	if _, err := readContained(root, outside); err == nil {
		t.Fatal("readContained must refuse a path outside the root")
	}
	if err := writeFile(root, outside, []byte("must not be written")); err == nil {
		t.Fatal("writeFile must refuse a path outside the root")
	}
	if _, err := os.ReadFile(outside); err != nil {
		t.Fatal(err)
	}
	if contents, err := os.ReadFile(outside); err != nil || string(contents) != "must not be read" {
		t.Fatal("the refused write must not have modified the file outside the root")
	}

	// The same helpers still work for legitimate in-root paths.
	if err := writeFile(root, filepath.Join(root, "nested", "ok.json"), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	contents, err := readContained(root, filepath.Join(root, "nested", "ok.json"))
	if err != nil || string(contents) != "{}" {
		t.Fatalf("in-root round trip failed: %v %q", err, contents)
	}
}

// stageBundle lays out the minimum inputs Generate requires, with the WIT
// declaring the WASI version the given toolchain expects.
func stageBundle(t *testing.T, wasi string) (string, string) {
	t.Helper()
	artifacts := t.TempDir()
	portableRoot := t.TempDir()
	writeFixture(t, filepath.Join(artifacts, "goforge.component.wasm"), "component")
	writeFixture(t, filepath.Join(artifacts, "goforge.component.wit"),
		"pointerbyte:goforge/operations@0.1.0\nwasi:cli/environment@"+wasi)
	writeFixture(t, filepath.Join(artifacts, "host", "goforge.js"), "export const instantiate = () => {};")
	writeFixture(t, filepath.Join(artifacts, "host", "goforge.core.wasm"), "core")

	vectors, err := os.ReadFile("../../../portable/testdata/vectors/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(portableRoot, "testdata", "vectors"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(portableRoot, "testdata", "vectors", "v1.json"), vectors, 0o644,
	); err != nil {
		t.Fatal(err)
	}
	return artifacts, portableRoot
}

func TestGenerateRejectsAWASIVersionTheArtifactDoesNotResolve(t *testing.T) {
	// A TinyGo build links WASI 0.2.0. Recording it as the componentize-go
	// toolchain would publish provenance that disagrees with the artifact.
	artifacts, portableRoot := stageBundle(t, "0.2.0")
	err := Generate(artifacts, portableRoot, ComponentizeGoToolchain())
	if err == nil || !strings.Contains(err.Error(), "declared WASI version 0.2.12") {
		t.Fatalf("a WASI mismatch must be rejected, got %v", err)
	}

	// The same tree passes once the declared toolchain matches reality.
	if err := Generate(artifacts, portableRoot, TinyGoToolchain()); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateRejectsAnArtifactMissingTheExportedInterface(t *testing.T) {
	artifacts, portableRoot := stageBundle(t, "0.2.0")
	writeFixture(t, filepath.Join(artifacts, "goforge.component.wit"),
		"pointerbyte:goforge/other@0.1.0\nwasi:cli/environment@0.2.0")
	err := Generate(artifacts, portableRoot, TinyGoToolchain())
	if err == nil || !strings.Contains(err.Error(), "does not export") {
		t.Fatalf("a missing operations export must be rejected, got %v", err)
	}
}

func TestGenerateRequiresDeclaredToolchainEvidence(t *testing.T) {
	artifacts, portableRoot := stageBundle(t, "0.2.0")
	for name, chain := range map[string]Toolchain{
		"no WASI version":       {ComponentCompiler: "tinygo 0.41.1"},
		"no component compiler": {WASI: "0.2.0"},
		"empty":                 {},
	} {
		if err := Generate(artifacts, portableRoot, chain); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}

func TestGenerateWritesProvenanceBoundToTheRealDigests(t *testing.T) {
	artifacts, portableRoot := stageBundle(t, "0.2.0")
	if err := Generate(artifacts, portableRoot, TinyGoToolchain()); err != nil {
		t.Fatal(err)
	}

	encoded, err := os.ReadFile(filepath.Join(artifacts, "provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	var statement struct {
		Type    string `json:"_type"`
		Subject []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		Predicate struct {
			RunDetails struct {
				Builder struct {
					Production bool `json:"production"`
				} `json:"builder"`
			} `json:"runDetails"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(encoded, &statement); err != nil {
		t.Fatal(err)
	}
	if statement.Type != "https://in-toto.io/Statement/v1" || len(statement.Subject) != 2 {
		t.Fatalf("unexpected provenance shape: %s", encoded)
	}
	if !statement.Predicate.RunDetails.Builder.Production {
		t.Fatal("the TinyGo toolchain must be recorded as the production build")
	}

	// The recorded digest must be the artifact's real digest, not a placeholder.
	actual, err := describe(artifacts, filepath.Join(artifacts, "goforge.component.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range statement.Subject {
		if subject.Name != "goforge.component.wasm" {
			continue
		}
		if subject.Digest["sha256"] != actual.SHA256 {
			t.Fatalf("provenance digest %s does not match the artifact %s",
				subject.Digest["sha256"], actual.SHA256)
		}
		return
	}
	t.Fatal("provenance does not describe the component")
}

func TestGenerateLabelsANonProductionToolchainAsSuch(t *testing.T) {
	artifacts, portableRoot := stageBundle(t, "0.2.12")
	if err := Generate(artifacts, portableRoot, ComponentizeGoToolchain()); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(artifacts, "toolchain.json"))
	if err != nil {
		t.Fatal(err)
	}
	var chain Toolchain
	if err := json.Unmarshal(encoded, &chain); err != nil {
		t.Fatal(err)
	}
	if chain.Production {
		t.Fatal("componentize-go is rejected for production by ADR 0012 and must not claim otherwise")
	}
	if chain.ComponentCompiler != "componentize-go 0.4.0" || chain.WASI != "0.2.12" {
		t.Fatalf("toolchain evidence does not describe the build: %s", encoded)
	}
}

func TestGenerateWritesALicenseInventoryCoveringTheShippedArtifacts(t *testing.T) {
	artifacts, portableRoot := stageBundle(t, "0.2.0")
	if err := Generate(artifacts, portableRoot, TinyGoToolchain()); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(artifacts, "LICENSES.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"Apache License 2.0", "Go standard library", "tinygo 0.41.1", "jco 1.26.1",
	} {
		if !strings.Contains(string(contents), required) {
			t.Fatalf("license inventory does not mention %q", required)
		}
	}
}

func TestGenerateIsDeterministicIncludingProvenanceAndLicenses(t *testing.T) {
	artifacts, portableRoot := stageBundle(t, "0.2.0")
	if err := Generate(artifacts, portableRoot, TinyGoToolchain()); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(artifacts, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Generate(artifacts, portableRoot, TinyGoToolchain()); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(artifacts, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("provenance or licenses introduced non-determinism into the bundle")
	}
	for _, name := range []string{"provenance.json", "LICENSES.txt", "toolchain.json"} {
		if !strings.Contains(string(first), name) {
			t.Fatalf("%s is not covered by SHA256SUMS", name)
		}
	}
}
