// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package utilities

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/spf13/viper"
)

// resetUtilitiesTestState restores package hooks and global Viper state so
// each test can exercise LoadEnv and the override helpers in isolation.
func resetUtilitiesTestState(t *testing.T) {
	t.Helper()

	originalReadInConfig := readInConfig

	t.Cleanup(func() {
		readInConfig = originalReadInConfig
		viper.Reset()
	})

	viper.Reset()
	readInConfig = viper.ReadInConfig
}

// writeApplicationJSON stores a JSON config file with the shape expected by
// LoadEnv when application.json is used as the fallback format.
func writeApplicationJSON(t *testing.T, dir string, data map[string]any) {
	t.Helper()

	payload, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "application.json"), payload, 0o600); err != nil {
		t.Fatalf("os.WriteFile(application.json) error = %v", err)
	}
}

// writeApplicationYAML stores a YAML config file so tests can verify that
// application.yml takes precedence over application.json when both exist.
func writeApplicationYAML(t *testing.T, dir string, content string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, "application.yml"), []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile(application.yml) error = %v", err)
	}
}

func writeEnvFile(t *testing.T, dir string, name string, content string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%s) error = %v", name, err)
	}
}

// TestExportMappedEnvOverridesNestedValues verifies that environment variables
// override deeply nested configuration values using the generated path-based
// env names.
func TestExportMappedEnvOverridesNestedValues(t *testing.T) {
	resetUtilitiesTestState(t)

	viper.Set("app.name", "from-config")
	viper.Set("server.port", ":8080")
	viper.Set("jwt.enable", false)
	viper.Set("server.modeTest", false)
	viper.Set("server.gin.rate.limit", 1000)
	viper.Set("traces.SkipPaths", []string{"/health"})

	t.Setenv("APP_NAME", "from-env")
	t.Setenv("SERVER_PORT", ":9090")
	t.Setenv("JWT_ENABLE", "true")
	t.Setenv("SERVER_MODETEST", "true")
	t.Setenv("SERVER_GIN_RATE_LIMIT", "2500")
	t.Setenv("TRACES_SKIPPATHS", "/health,/refresh")

	exportMappedEnv()

	if got := viper.GetString("app.name"); got != "from-env" {
		t.Fatalf("app.name = %q, want %q", got, "from-env")
	}
	if got := viper.GetString("server.port"); got != ":9090" {
		t.Fatalf("server.port = %q, want %q", got, ":9090")
	}
	if got := viper.GetBool("jwt.enable"); !got {
		t.Fatalf("jwt.enable = %v, want true", got)
	}
	if got := viper.GetBool("server.modeTest"); !got {
		t.Fatalf("server.modeTest = %v, want true", got)
	}
	if got := viper.GetInt("server.gin.rate.limit"); got != 2500 {
		t.Fatalf("server.gin.rate.limit = %d, want 2500", got)
	}

	wantSkipPaths := []string{"/health", "/refresh"}
	if got := viper.GetStringSlice("traces.SkipPaths"); !reflect.DeepEqual(got, wantSkipPaths) {
		t.Fatalf("traces.SkipPaths = %v, want %v", got, wantSkipPaths)
	}
}

// TestExportMappedEnvAdaptsToNewApplicationKeys covers keys that are only
// discovered dynamically from the current Viper settings tree.
func TestExportMappedEnvAdaptsToNewApplicationKeys(t *testing.T) {
	resetUtilitiesTestState(t)

	viper.Set("aws.parametersStore.enable", false)
	viper.Set("server.gin.UseH2C", true)
	viper.Set("server.groups", []string{"/api/v1"})

	t.Setenv("AWS_PARAMETERSSTORE_ENABLE", "true")
	t.Setenv("SERVER_GIN_USEH2C", "false")
	t.Setenv("SERVER_GROUPS", `["/api/v2","/internal"]`)

	exportMappedEnv()

	if got := viper.GetBool("aws.parametersStore.enable"); !got {
		t.Fatalf("aws.parametersStore.enable = %v, want true", got)
	}
	if got := viper.GetBool("server.gin.UseH2C"); got {
		t.Fatalf("server.gin.UseH2C = %v, want false", got)
	}

	wantGroups := []string{"/api/v2", "/internal"}
	if got := viper.GetStringSlice("server.groups"); !reflect.DeepEqual(got, wantGroups) {
		t.Fatalf("server.groups = %v, want %v", got, wantGroups)
	}
}

// TestApplyEnvOverridesHandlesMapAnyAnyAndInvalidKey documents the mixed map
// case used by Viper internals and ensures non-string keys are ignored safely.
func TestApplyEnvOverridesHandlesMapAnyAnyAndInvalidKey(t *testing.T) {
	resetUtilitiesTestState(t)

	t.Setenv("JWT_ENABLE", "true")

	input := map[any]any{
		"jwt": map[any]any{
			"enable": false,
		},
		1: "ignored",
	}

	applyEnvOverrides(input, nil)

	if !viper.GetBool("jwt.enable") {
		t.Fatal("expected jwt.enable to be true")
	}
}

// TestEnvNameFromPath keeps the env-name mapping explicit for future changes.
func TestEnvNameFromPath(t *testing.T) {
	got := envNameFromPath([]string{" aws ", "parametersStore", "", "enable"})
	if got != "AWS_PARAMETERSSTORE_ENABLE" {
		t.Fatalf("envNameFromPath() = %q, want %q", got, "AWS_PARAMETERSSTORE_ENABLE")
	}
}

// TestParseEnvValueAndHelpers exercises the type conversion helpers used by
// environment variable overrides, including slices and fallback behavior.
func TestParseEnvValueAndHelpers(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		template any
		want     any
	}{
		{name: "bool", raw: "true", template: false, want: true},
		{name: "invalid bool falls back string", raw: "wat", template: false, want: "wat"},
		{name: "int", raw: "12", template: 1, want: 12},
		{name: "int64", raw: "15", template: int64(1), want: int64(15)},
		{name: "uint64", raw: "17", template: uint64(1), want: uint64(17)},
		{name: "float64", raw: "1.5", template: 0.0, want: 1.5},
		{name: "string slice csv", raw: "a,b", template: []string{}, want: []string{"a", "b"}},
		{name: "string slice json", raw: `["a","b"]`, template: []string{}, want: []string{"a", "b"}},
		{name: "any slice strings", raw: `["a","b"]`, template: []any{"x"}, want: []string{"a", "b"}},
		{name: "any slice mixed json", raw: `[1,"b"]`, template: []any{1}, want: []any{float64(1), "b"}},
		{name: "any slice csv", raw: "a,b", template: []any{1}, want: []any{"a", "b"}},
		{name: "default string", raw: "hello", template: struct{}{}, want: "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseEnvValue(tt.raw, tt.template)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseEnvValue() = %#v, want %#v", got, tt.want)
			}
		})
	}

	if got := parseStringSlice(" [bad json "); !reflect.DeepEqual(got, []string{"[bad json"}) {
		t.Fatalf("parseStringSlice() fallback = %#v", got)
	}
	if got := splitCommaSeparated(" a, , b ,, "); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("splitCommaSeparated() = %#v, want %#v", got, []string{"a", "b"})
	}
	if got := splitCommaSeparated(""); len(got) != 0 {
		t.Fatalf("splitCommaSeparated(\"\") = %#v, want empty slice", got)
	}
	if !allStringValues(nil) {
		t.Fatal("allStringValues(nil) = false, want true")
	}
	if allStringValues([]any{"ok", 1}) {
		t.Fatal("allStringValues(mixed) = true, want false")
	}
}

// TestLoadEnvReadConfigError keeps the top-level failure path covered so
// callers can rely on LoadEnv surfacing config read problems unchanged.
func TestLoadEnvReadConfigError(t *testing.T) {
	resetUtilitiesTestState(t)

	wantErr := errors.New("read error")
	readInConfig = func() error { return wantErr }

	err := LoadEnv(t.TempDir())
	if !errors.Is(err, wantErr) {
		t.Fatalf("LoadEnv() error = %v, want %v", err, wantErr)
	}
}

// TestLoadEnvLoadsJSONAndEnvOverrides covers the common fallback path where
// application.json is loaded and then overridden by environment variables.
func TestLoadEnvLoadsJSONAndEnvOverrides(t *testing.T) {
	resetUtilitiesTestState(t)

	dir := t.TempDir()
	writeApplicationJSON(t, dir, map[string]any{
		"app": map[string]any{
			"name": "from-file",
		},
		"server": map[string]any{
			"port":   ":8080",
			"groups": []string{"/api/v1"},
		},
		"traces": map[string]any{
			"SkipPaths": []string{"/health"},
		},
	})

	t.Setenv("APP_NAME", "from-env")
	t.Setenv("SERVER_GROUPS", "/v2,/v3")

	if err := LoadEnv(dir); err != nil {
		t.Fatalf("LoadEnv() error = %v", err)
	}

	if got := viper.GetString("app.name"); got != "from-env" {
		t.Fatalf("app.name = %q, want %q", got, "from-env")
	}
	if got := viper.GetString("server.port"); got != ":8080" {
		t.Fatalf("server.port = %q, want %q", got, ":8080")
	}
	if got := viper.GetStringSlice("server.groups"); !reflect.DeepEqual(got, []string{"/v2", "/v3"}) {
		t.Fatalf("server.groups = %#v, want %#v", got, []string{"/v2", "/v3"})
	}
}

// TestLoadEnvLoadsConfiguredEnvFiles verifies that .env files are loaded only
// when the application configuration declares them in env.files.
func TestLoadEnvLoadsConfiguredEnvFiles(t *testing.T) {
	resetUtilitiesTestState(t)

	dir := t.TempDir()
	writeApplicationJSON(t, dir, map[string]any{
		"app": map[string]any{
			"name": "from-file",
		},
		"env": map[string]any{
			"files": []string{".env", ".env.production"},
		},
		"server": map[string]any{
			"port": ":8080",
		},
	})
	writeEnvFile(t, dir, ".env", "APP_NAME=from-env\n")
	writeEnvFile(t, dir, ".env.local", "APP_NAME=from-local\nSERVER_PORT=:9090\n")
	writeEnvFile(t, dir, ".env.production", "APP_NAME=from-production\nSERVER_PORT=:6060\n")
	t.Setenv("APP_NAME", "from-process")
	t.Setenv("SERVER_PORT", ":7070")

	if err := LoadEnv(dir); err != nil {
		t.Fatalf("LoadEnv() error = %v", err)
	}

	if got := viper.GetString("app.name"); got != "from-production" {
		t.Fatalf("app.name = %q, want %q", got, "from-production")
	}
	if got := viper.GetString("server.port"); got != ":6060" {
		t.Fatalf("server.port = %q, want %q", got, ":6060")
	}
}

// TestLoadEnvLoadsFromResourcesDirectory documents the project convention that
// application configuration lives under resources/.
func TestLoadEnvLoadsFromResourcesDirectory(t *testing.T) {
	resetUtilitiesTestState(t)

	dir := t.TempDir()
	resourcesDir := filepath.Join(dir, "resources")
	if err := os.Mkdir(resourcesDir, 0o700); err != nil {
		t.Fatalf("os.Mkdir(resources) error = %v", err)
	}
	writeApplicationJSON(t, resourcesDir, map[string]any{
		"app": map[string]any{
			"name": "from-resources",
		},
	})

	if err := LoadEnv(dir); err != nil {
		t.Fatalf("LoadEnv() error = %v", err)
	}

	if got := viper.GetString("app.name"); got != "from-resources" {
		t.Fatalf("app.name = %q, want %q", got, "from-resources")
	}
}

// TestLoadEnvFindsParentResourcesDirectory keeps examples runnable when they
// are started from cmd/example instead of the repository root.
func TestLoadEnvFindsParentResourcesDirectory(t *testing.T) {
	resetUtilitiesTestState(t)

	dir := t.TempDir()
	resourcesDir := filepath.Join(dir, "resources")
	nestedDir := filepath.Join(dir, "cmd", "example")
	if err := os.Mkdir(resourcesDir, 0o700); err != nil {
		t.Fatalf("os.Mkdir(resources) error = %v", err)
	}
	if err := os.MkdirAll(nestedDir, 0o700); err != nil {
		t.Fatalf("os.MkdirAll(cmd/example) error = %v", err)
	}
	writeApplicationJSON(t, resourcesDir, map[string]any{
		"app": map[string]any{
			"name": "from-parent-resources",
		},
	})

	if err := LoadEnv(nestedDir); err != nil {
		t.Fatalf("LoadEnv() error = %v", err)
	}

	if got := viper.GetString("app.name"); got != "from-parent-resources" {
		t.Fatalf("app.name = %q, want %q", got, "from-parent-resources")
	}
}

// TestLoadEnvPrefersYAMLOverJSON documents the file-selection rule: if
// application.yml exists, it wins over application.json.
func TestLoadEnvPrefersYAMLOverJSON(t *testing.T) {
	resetUtilitiesTestState(t)

	dir := t.TempDir()
	writeApplicationJSON(t, dir, map[string]any{
		"app": map[string]any{
			"name": "from-json",
		},
	})
	writeApplicationYAML(t, dir, "app:\n  name: from-yaml\n")

	if err := LoadEnv(dir); err != nil {
		t.Fatalf("LoadEnv() error = %v", err)
	}

	if got := viper.GetString("app.name"); got != "from-yaml" {
		t.Fatalf("app.name = %q, want %q", got, "from-yaml")
	}
}
