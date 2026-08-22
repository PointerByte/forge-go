// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	configYAML = "yaml"
	configJSON = "json"
)

var (
	modulePathPattern  = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	serviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	goVersionPattern   = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?$`)
)

type scaffoldOptions struct {
	modulePath   string
	appName      string
	configFormat string
	goVersion    string
	outputDir    string
}

// scaffolder coordinates filesystem writes and `go` commands for a generated service.
type scaffolder struct {
	streams     IOStreams
	runner      goRunner
	absFn       func(string) (string, error)
	statFn      func(string) (fs.FileInfo, error)
	mkdirAllFn  func(string, os.FileMode) error
	writeFileFn func(string, []byte, os.FileMode) error
}

// newScaffolder builds a scaffolder with the default filesystem helpers.
func newScaffolder(streams IOStreams, runner goRunner) *scaffolder {
	return &scaffolder{
		streams:     streams,
		runner:      runner,
		absFn:       filepath.Abs,
		statFn:      os.Stat,
		mkdirAllFn:  os.MkdirAll,
		writeFileFn: os.WriteFile,
	}
}

// resolveScaffoldOptions merges CLI flags and interactive prompts into a validated configuration.
func resolveScaffoldOptions(streams IOStreams, options *scaffoldOptions, defaultGoVersion string) (scaffoldOptions, error) {
	reader := bufio.NewReader(streams.In)

	modulePath, err := promptRequired(reader, streams.Out, "Package/module name", options.modulePath)
	if err != nil {
		return scaffoldOptions{}, err
	}
	if !isValidModulePath(modulePath) {
		return scaffoldOptions{}, fmt.Errorf("package/module name contains invalid characters")
	}

	appName, err := promptRequired(reader, streams.Out, "app.name", options.appName)
	if err != nil {
		return scaffoldOptions{}, err
	}
	if !isValidServiceName(appName) {
		return scaffoldOptions{}, fmt.Errorf("app.name contains invalid characters")
	}

	configFormat, err := promptConfigFormat(reader, streams.Out, options.configFormat)
	if err != nil {
		return scaffoldOptions{}, err
	}

	goVersion, err := promptGoVersion(reader, streams.Out, options.goVersion, defaultGoVersion)
	if err != nil {
		return scaffoldOptions{}, err
	}

	outputDir := strings.TrimSpace(options.outputDir)
	if outputDir == "" {
		outputDir = appName
	}

	return scaffoldOptions{
		modulePath:   modulePath,
		appName:      appName,
		configFormat: configFormat,
		goVersion:    goVersion,
		outputDir:    outputDir,
	}, nil
}

// promptRequired reads a mandatory value unless one was already provided through flags.
func promptRequired(reader *bufio.Reader, output io.Writer, label string, fallback string) (string, error) {
	fallback = strings.TrimSpace(fallback)
	if fallback != "" {
		return fallback, nil
	}

	if _, err := fmt.Fprintf(output, "%s: ", label); err != nil {
		return "", err
	}

	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	return value, nil
}

const (
	defaultGoForgeVersion       = "v1.0.3"
	defaultGoForgeLoggerVersion = "v1.0.3"
)

// promptConfigFormat resolves the config format, defaulting to YAML when the user leaves it blank.
func promptConfigFormat(reader *bufio.Reader, output io.Writer, fallback string) (string, error) {
	fallback = strings.ToLower(strings.TrimSpace(fallback))
	if fallback != "" {
		if !isValidConfigFormat(fallback) {
			return "", fmt.Errorf("invalid config format %q", fallback)
		}
		return fallback, nil
	}

	if _, err := fmt.Fprint(output, "Config format [yaml/json] (default: yaml): "); err != nil {
		return "", err
	}

	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}

	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return configYAML, nil
	}
	if !isValidConfigFormat(value) {
		return "", fmt.Errorf("invalid config format %q", value)
	}
	return value, nil
}

// promptGoVersion resolves the Go module version, defaulting to the installed toolchain.
func promptGoVersion(reader *bufio.Reader, output io.Writer, fallback string, defaultVersion string) (string, error) {
	fallback = normalizeGoVersion(fallback)
	if fallback != "" {
		if !isValidGoVersion(fallback) {
			return "", fmt.Errorf("invalid Go version %q", fallback)
		}
		return fallback, nil
	}

	defaultVersion = normalizeGoVersion(defaultVersion)
	if !isValidGoVersion(defaultVersion) {
		return "", fmt.Errorf("invalid default Go version %q", defaultVersion)
	}

	if _, err := fmt.Fprintf(output, "Go version (default: %s): ", defaultVersion); err != nil {
		return "", err
	}

	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}

	value = normalizeGoVersion(value)
	if value == "" {
		return defaultVersion, nil
	}
	if !isValidGoVersion(value) {
		return "", fmt.Errorf("invalid Go version %q", value)
	}
	return value, nil
}

// isValidConfigFormat reports whether the requested config format is supported.
func isValidConfigFormat(value string) bool {
	return value == configYAML || value == configJSON
}

// isValidGoVersion reports whether the value can be used in a go.mod go directive.
func isValidGoVersion(value string) bool {
	return goVersionPattern.MatchString(value)
}

// normalizeGoVersion trims spaces and accepts the go command's "go1.x.y" version shape.
func normalizeGoVersion(value string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), "go")
}

// isValidModulePath validates the module/package path accepted by the scaffold.
func isValidModulePath(value string) bool {
	return modulePathPattern.MatchString(value) && !strings.Contains(value, " ")
}

// isValidServiceName validates the app.name value used for generated services.
func isValidServiceName(value string) bool {
	return serviceNamePattern.MatchString(value) && !strings.Contains(value, " ")
}

// createService materializes the scaffolded project, initializes the module, and installs dependencies.
func (scaffolder *scaffolder) createService(serviceType string, options scaffoldOptions) error {
	outputDir, err := scaffolder.absFn(options.outputDir)
	if err != nil {
		return fmt.Errorf("resolve output directory: %w", err)
	}

	if _, err := scaffolder.statFn(outputDir); err == nil {
		return fmt.Errorf("output directory already exists: %s", outputDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output directory: %w", err)
	}

	if err := scaffolder.mkdirAllFn(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	files, err := buildProjectFiles(serviceType, options)
	if err != nil {
		return err
	}

	for name, content := range files {
		target := filepath.Join(outputDir, name)
		if err := scaffolder.mkdirAllFn(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("create parent directory for %s: %w", name, err)
		}
		if err := scaffolder.writeFileFn(target, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}

	if err := scaffolder.runner(outputDir, "mod", "init", options.modulePath); err != nil {
		return fmt.Errorf("initialize go module: %w", err)
	}

	if options.goVersion != "" {
		if err := scaffolder.runner(outputDir, "mod", "edit", "-go="+options.goVersion); err != nil {
			return fmt.Errorf("set Go version: %w", err)
		}
	}

	if err := scaffolder.runner(outputDir, "get", "github.com/PointerByte/forge-go@"+defaultGoForgeVersion, "github.com/PointerByte/forge-go/logger@"+defaultGoForgeLoggerVersion); err != nil {
		return fmt.Errorf("pin dependencies: %w", err)
	}

	if err := scaffolder.runner(outputDir, "mod", "tidy"); err != nil {
		return fmt.Errorf("install dependencies: %w", err)
	}

	if _, err := fmt.Fprintf(scaffolder.streams.Out, "Service created in %s\n", outputDir); err != nil {
		return err
	}
	return nil
}
