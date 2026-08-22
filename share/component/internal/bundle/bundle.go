// Package bundle creates deterministic release metadata for the production
// GoForge component and its jco host artifacts.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/PointerByte/forge-go/share/portable"
)

const (
	bundleSchema    = "goforge.bundle-manifest.v1"
	toolchainSchema = "goforge.toolchain-evidence.v1"
	vectorPath      = "vectors/v1.json"
)

type descriptor struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type operationContract struct {
	Capability        string `json:"capability"`
	RetrySafe         bool   `json:"retrySafe"`
	SecuritySensitive bool   `json:"securitySensitive"`
}

type manifest struct {
	Schema           string                       `json:"schema"`
	ABI              string                       `json:"abi"`
	ComponentVersion string                       `json:"componentVersion"`
	WITPackage       string                       `json:"witPackage"`
	Source           descriptor                   `json:"source"`
	Glue             descriptor                   `json:"glue"`
	CoreModules      map[string]descriptor        `json:"coreModules"`
	Capabilities     []string                     `json:"capabilities"`
	Operations       map[string]operationContract `json:"operations"`
}

type contractEvidence struct {
	Schema     string     `json:"schema"`
	ABI        string     `json:"abi"`
	WITPackage string     `json:"witPackage"`
	Manifest   descriptor `json:"manifest"`
	Vectors    descriptor `json:"vectors"`
}

// Toolchain identifies the exact tools that produced a bundle. It is both the
// input that tells Generate what to verify and the evidence written into
// toolchain.json, so the recorded provenance can never drift from what was
// actually checked.
type Toolchain struct {
	Schema string `json:"schema"`
	// LanguageDirective is the Go compatibility floor the modules declare.
	LanguageDirective string `json:"languageDirective"`
	// ComponentCompiler is the tool that produced the component, e.g.
	// "tinygo 0.41.1" or "componentize-go 0.4.0".
	ComponentCompiler string `json:"componentCompiler"`
	// Compiler is the Go toolchain backing ComponentCompiler.
	Compiler string `json:"compiler"`
	// Bindings is the WIT binding generator and version.
	Bindings string `json:"bindings"`
	// GeneratedRuntime is the Component Model runtime module the guest links.
	GeneratedRuntime string `json:"generatedRuntime"`
	// WASI is the exact patch version the built component must resolve. The
	// extracted WIT is checked against this value rather than a hard-coded one,
	// because TinyGo links 0.2.0 where componentize-go links 0.2.12.
	WASI string `json:"wasi"`
	// Production marks the toolchain selected by ADR 0012 for release builds.
	// A non-production bundle is still generated, so regression builds keep
	// working, but it is labelled as such and must never be published.
	Production bool `json:"production"`

	WasmTools string `json:"wasmTools"`
	Jco       string `json:"jco"`
	Deno      string `json:"deno"`
}

// TinyGoToolchain is the production selection accepted by ADR 0012.
//
// The WASI baseline is deliberately 0.2.0, not 0.2.12: TinyGo's wasip2 target
// links the 0.2.0 interfaces, and recording anything else would misstate what
// the shipped artifact actually imports.
func TinyGoToolchain() Toolchain {
	return Toolchain{
		Schema:            toolchainSchema,
		LanguageDirective: "go1.25.0",
		ComponentCompiler: "tinygo 0.41.1",
		Compiler:          "go1.26.2 (bundled in tinygo/tinygo:0.41.1)",
		Bindings:          "wit-bindgen-go v0.7.0",
		GeneratedRuntime:  "go.bytecodealliance.org/cm@v0.3.0",
		WASI:              "0.2.0",
		Production:        true,
		WasmTools:         "1.255.0",
		Jco:               "1.26.1",
		Deno:              "2.9.4",
	}
}

// ComponentizeGoToolchain is retained for research and regression builds only.
// ADR 0012 rejects it for production: it intermittently traps during Go garbage
// collection under sustained dispatch load on both Deno/jco and wasmtime.
func ComponentizeGoToolchain() Toolchain {
	return Toolchain{
		Schema:            toolchainSchema,
		LanguageDirective: "go1.25.0",
		ComponentCompiler: "componentize-go 0.4.0",
		Compiler:          "go1.25.12",
		Bindings:          "wit-bindgen 0.58.0",
		GeneratedRuntime:  "go.bytecodealliance.org/pkg@0.2.2",
		WASI:              "0.2.12",
		Production:        false,
		WasmTools:         "1.255.0",
		Jco:               "1.26.1",
		Deno:              "2.9.4",
	}
}

// Generate validates the built/transpiled surface and writes deterministic
// release metadata into artifactRoot. portableRoot is used only to copy the
// canonical shared vector set into the standalone release bundle.
//
// Both roots are resolved once and every subsequent path is required to stay
// inside them, so a caller-supplied root can never make this tool read or write
// outside the tree it was pointed at.
func Generate(artifactRoot, portableRoot string, chain Toolchain) error {
	if chain.WASI == "" || chain.ComponentCompiler == "" {
		return errors.New("toolchain evidence must declare a component compiler and a WASI version")
	}
	artifactRoot, err := resolveRoot(artifactRoot)
	if err != nil {
		return err
	}
	portableRoot, err = resolveRoot(portableRoot)
	if err != nil {
		return err
	}

	componentPath := filepath.Join(artifactRoot, "goforge.component.wasm")
	witPath := filepath.Join(artifactRoot, "goforge.component.wit")
	gluePath := filepath.Join(artifactRoot, "host", "goforge.js")
	for _, required := range []string{componentPath, witPath, gluePath} {
		if info, err := os.Stat(required); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("required release artifact is missing or empty: %s", required)
		}
	}

	wit, err := readContained(artifactRoot, witPath)
	if err != nil {
		return err
	}
	// The WASI version is checked against the declared toolchain rather than a
	// constant: the production TinyGo build links 0.2.0 and the retained
	// componentize-go regression build links 0.2.12, and silently accepting
	// either would let the recorded provenance disagree with the artifact.
	if !strings.Contains(string(wit), "pointerbyte:goforge/operations@0.1.0") {
		return errors.New("extracted WIT does not export pointerbyte:goforge/operations@0.1.0")
	}
	if !strings.Contains(string(wit), "wasi:cli/environment@"+chain.WASI) {
		return fmt.Errorf(
			"extracted WIT does not resolve the declared WASI version %s", chain.WASI)
	}

	dispatcher := portable.DefaultDispatcher()
	contractManifest := dispatcher.Manifest()
	manifestJSON := dispatcher.ManifestJSON()
	if len(manifestJSON) == 0 {
		return errors.New("portable manifest encoding failed")
	}
	manifestPath := filepath.Join(artifactRoot, "goforge.abi.manifest.json")
	if err := writeFile(artifactRoot, manifestPath, manifestJSON); err != nil {
		return err
	}

	sharedVectors := filepath.Join(portableRoot, "testdata", "vectors", "v1.json")
	vectors, err := readContained(portableRoot, sharedVectors)
	if err != nil {
		return err
	}
	var vectorHeader struct {
		Schema string            `json:"schema"`
		ABI    string            `json:"abi"`
		Values []json.RawMessage `json:"vectors"`
	}
	if err := json.Unmarshal(vectors, &vectorHeader); err != nil {
		return err
	}
	if vectorHeader.Schema != "goforge.test-vectors.v1" || vectorHeader.ABI != portable.ABIVersion || len(vectorHeader.Values) != len(contractManifest.Operations) {
		return errors.New("shared vectors do not cover the portable manifest")
	}
	if err := writeFile(artifactRoot, filepath.Join(artifactRoot, vectorPath), vectors); err != nil {
		return err
	}

	coreFiles, err := filepath.Glob(filepath.Join(artifactRoot, "host", "*.wasm"))
	if err != nil {
		return err
	}
	if len(coreFiles) == 0 {
		return errors.New("jco did not emit any core WebAssembly modules")
	}
	sort.Strings(coreFiles)
	cores := make(map[string]descriptor, len(coreFiles))
	for _, path := range coreFiles {
		name := filepath.Base(path)
		cores[name], err = describe(artifactRoot, path)
		if err != nil {
			return err
		}
	}

	capabilities := make([]string, 0, len(contractManifest.Capabilities))
	for _, capability := range contractManifest.Capabilities {
		capabilities = append(capabilities, capability.Name)
	}
	operations := make(map[string]operationContract, len(contractManifest.Operations))
	for _, operation := range contractManifest.Operations {
		operations[string(operation.Name)] = operationContract{
			Capability:        operation.Capability,
			RetrySafe:         true,
			SecuritySensitive: strings.HasPrefix(operation.Capability, "crypto."),
		}
	}

	sourceDescriptor, err := describe(artifactRoot, componentPath)
	if err != nil {
		return err
	}
	glueDescriptor, err := describe(artifactRoot, gluePath)
	if err != nil {
		return err
	}
	release := manifest{
		Schema:           bundleSchema,
		ABI:              portable.ABIVersion,
		ComponentVersion: portable.PackageVersion,
		WITPackage:       portable.PackageName + "@" + portable.PackageVersion,
		Source:           sourceDescriptor,
		Glue:             glueDescriptor,
		CoreModules:      cores,
		Capabilities:     capabilities,
		Operations:       operations,
	}
	if err := writeJSON(artifactRoot, filepath.Join(artifactRoot, "manifest.json"), release); err != nil {
		return err
	}

	manifestDescriptor, err := describe(artifactRoot, manifestPath)
	if err != nil {
		return err
	}
	vectorDescriptor, err := describe(artifactRoot, filepath.Join(artifactRoot, vectorPath))
	if err != nil {
		return err
	}
	if err := writeJSON(artifactRoot, filepath.Join(artifactRoot, "contract.json"), contractEvidence{
		Schema:     "goforge.contract-bundle.v1",
		ABI:        portable.ABIVersion,
		WITPackage: portable.PackageName + "@" + portable.PackageVersion,
		Manifest:   manifestDescriptor,
		Vectors:    vectorDescriptor,
	}); err != nil {
		return err
	}
	if err := writeJSON(artifactRoot, filepath.Join(artifactRoot, "toolchain.json"), chain); err != nil {
		return err
	}
	if err := writeLicenses(artifactRoot, chain); err != nil {
		return err
	}
	if err := writeProvenance(artifactRoot, chain, sourceDescriptor, glueDescriptor); err != nil {
		return err
	}

	releaseManifest, err := describe(artifactRoot, filepath.Join(artifactRoot, "manifest.json"))
	if err != nil {
		return err
	}
	if err := writeFile(
		artifactRoot,
		filepath.Join(artifactRoot, "manifest.sha256"),
		[]byte(releaseManifest.SHA256+"  manifest.json\n"),
	); err != nil {
		return err
	}
	return writeChecksums(artifactRoot)
}

// writeLicenses records every license that applies to the shipped bundle.
//
// The guest links no third-party Go modules — `go list -deps` over the portable
// core resolves only the standard library — so the set is small and stated
// exactly rather than generated from a dependency scan that would report
// nothing.
func writeLicenses(root string, chain Toolchain) error {
	var text strings.Builder
	text.WriteString("GoForge component release bundle — license inventory\n")
	text.WriteString("====================================================\n\n")
	text.WriteString("Component and portable core\n")
	text.WriteString("  GoForge — Apache License 2.0. Full text: LICENSE at the repository root.\n")
	text.WriteString("  The guest links no third-party Go modules; `go list -deps` over the\n")
	text.WriteString("  portable core resolves only the Go standard library.\n\n")
	text.WriteString("Go standard library, linked into the guest\n")
	text.WriteString("  The Go Authors — BSD 3-Clause. https://go.dev/LICENSE\n\n")
	text.WriteString("Build-time tools, not linked into the artifact\n")
	fmt.Fprintf(&text, "  %s — Apache-2.0 WITH LLVM-exception (TinyGo) or Apache-2.0\n",
		chain.ComponentCompiler)
	fmt.Fprintf(&text, "  %s — Apache-2.0 WITH LLVM-exception\n", chain.Bindings)
	fmt.Fprintf(&text, "  wasm-tools %s — Apache-2.0 WITH LLVM-exception\n", chain.WasmTools)
	fmt.Fprintf(&text, "  jco %s — Apache-2.0 WITH LLVM-exception\n", chain.Jco)
	text.WriteString("\nGenerated host glue, shipped in this bundle\n")
	fmt.Fprintf(&text, "  Produced by jco %s from the component above; Apache-2.0 WITH\n", chain.Jco)
	text.WriteString("  LLVM-exception, inherited from the generator.\n")
	fmt.Fprintf(&text, "\nRuntime module linked into the guest\n  %s — Apache-2.0 WITH LLVM-exception\n",
		chain.GeneratedRuntime)
	return writeFile(root, filepath.Join(root, "LICENSES.txt"), []byte(text.String()))
}

// provenance is a deliberately timestamp-free in-toto statement. A build time
// would change on every run and break the reproducible-digest guarantee that
// ADR 0012 makes a release constraint.
type provenance struct {
	Type          string              `json:"_type"`
	Subject       []provenanceSubject `json:"subject"`
	PredicateType string              `json:"predicateType"`
	Predicate     provenancePredicate `json:"predicate"`
}

type provenanceSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type provenancePredicate struct {
	BuildDefinition provenanceBuildDefinition `json:"buildDefinition"`
	RunDetails      provenanceRunDetails      `json:"runDetails"`
}

type provenanceBuildDefinition struct {
	BuildType            string            `json:"buildType"`
	ExternalParameters   map[string]string `json:"externalParameters"`
	ResolvedDependencies []provenanceDep   `json:"resolvedDependencies"`
}

type provenanceDep struct {
	URI  string `json:"uri"`
	Name string `json:"name"`
}

type provenanceRunDetails struct {
	Builder provenanceBuilder `json:"builder"`
}

type provenanceBuilder struct {
	ID         string `json:"id"`
	Production bool   `json:"production"`
}

// writeProvenance records what produced the bundle, bound to the exact digests
// of the artifacts it describes.
func writeProvenance(root string, chain Toolchain, source, glue descriptor) error {
	dependencies := []provenanceDep{
		{Name: "component-compiler", URI: chain.ComponentCompiler},
		{Name: "go-toolchain", URI: chain.Compiler},
		{Name: "wit-bindings", URI: chain.Bindings},
		{Name: "component-runtime", URI: chain.GeneratedRuntime},
		{Name: "wasi", URI: "wasi:cli/imports@" + chain.WASI},
		{Name: "wasm-tools", URI: "wasm-tools " + chain.WasmTools},
		{Name: "jco", URI: "jco " + chain.Jco},
	}
	return writeJSON(root, filepath.Join(root, "provenance.json"), provenance{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []provenanceSubject{
			{Name: "goforge.component.wasm", Digest: map[string]string{"sha256": source.SHA256}},
			{Name: "host/goforge.js", Digest: map[string]string{"sha256": glue.SHA256}},
		},
		PredicateType: "https://slsa.dev/provenance/v1",
		Predicate: provenancePredicate{
			BuildDefinition: provenanceBuildDefinition{
				BuildType: "https://pointerbyte.dev/goforge/component-build/v1",
				ExternalParameters: map[string]string{
					"world":             "goforge",
					"witPackage":        portable.PackageName + "@" + portable.PackageVersion,
					"abi":               portable.ABIVersion,
					"languageDirective": chain.LanguageDirective,
				},
				ResolvedDependencies: dependencies,
			},
			RunDetails: provenanceRunDetails{
				Builder: provenanceBuilder{
					ID:         "https://pointerbyte.dev/goforge/share/component/scripts/build.sh",
					Production: chain.Production,
				},
			},
		},
	})
}

// resolveRoot turns a caller-supplied directory into a clean absolute path and
// proves it is an existing directory before anything is read from or written
// beneath it.
func resolveRoot(root string) (string, error) {
	if root == "" {
		return "", errors.New("bundle root must not be empty")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	info, err := os.Stat(absolute)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("bundle root is not a directory: %s", absolute)
	}
	return absolute, nil
}

// contained rejects any path that escapes root, so a traversal segment or an
// absolute path smuggled through a caller-supplied name cannot reach outside
// the bundle tree.
func contained(root, path string) (string, error) {
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		cleaned = filepath.Clean(filepath.Join(root, cleaned))
	}
	relative, err := filepath.Rel(root, cleaned)
	if err != nil {
		return "", err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes the bundle root: %s", path)
	}
	return cleaned, nil
}

// readContained reads a file only after proving it lives inside root.
func readContained(root, path string) ([]byte, error) {
	safe, err := contained(root, path)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(safe) // #nosec G304 -- safe is proven to be inside root by contained.
}

func describe(root, path string) (descriptor, error) {
	encoded, err := readContained(root, path)
	if err != nil {
		return descriptor{}, err
	}
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return descriptor{}, err
	}
	return descriptor{Path: filepath.ToSlash(relative), SHA256: digest(encoded)}, nil
}

func writeJSON(root, path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(root, path, append(encoded, '\n'))
}

// writeFile writes one bundle artifact. The 0o755/0o644 modes are deliberate:
// a release bundle is distributed and must stay readable by the consumers that
// verify and load it. Nothing secret is ever written here — the bundle contains
// only public component bytes, manifests and checksums.
func writeFile(root, path string, encoded []byte) error {
	safe, err := contained(root, path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(safe), 0o755); err != nil { // #nosec G301 -- public release tree.
		return err
	}
	return os.WriteFile(safe, encoded, 0o644) // #nosec G306 -- public release artifact.
}

func writeChecksums(root string) error {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type().IsRegular() && filepath.Base(path) != "SHA256SUMS" {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(paths)
	var output strings.Builder
	for _, path := range paths {
		descriptor, err := describe(root, path)
		if err != nil {
			return err
		}
		fmt.Fprintf(&output, "%s  %s\n", descriptor.SHA256, descriptor.Path)
	}
	return writeFile(root, filepath.Join(root, "SHA256SUMS"), []byte(output.String()))
}

func digest(encoded []byte) string {
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
