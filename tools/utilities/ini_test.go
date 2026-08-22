// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package utilities

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// writeINIFile stores an INI overlay next to the application file so tests can
// exercise the default.ini and <app.name>.ini resolution rules.
func writeINIFile(t *testing.T, dir string, name string, content string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%s) error = %v", name, err)
	}
}

// TestParseINIBuildsKeyPaths verifies that section headers and dotted keys
// produce the same Viper key paths, including the root section.
func TestParseINIBuildsKeyPaths(t *testing.T) {
	resetUtilitiesTestState(t)

	settings, err := parseINI(strings.Join([]string{
		"; leading comment",
		"# another comment",
		"standalone = root",
		"",
		"[app]",
		"name = dragon-cmk",
		"",
		"[server.gin]",
		"port = :8080",
		"",
		"[server]",
		"grpc.port = :50051",
		"",
		"[]",
		"back.to.root = yes",
	}, "\n"))
	if err != nil {
		t.Fatalf("parseINI() error = %v", err)
	}

	if err := viper.MergeConfigMap(settings); err != nil {
		t.Fatalf("viper.MergeConfigMap() error = %v", err)
	}

	cases := map[string]string{
		"standalone":       "root",
		"app.name":         "dragon-cmk",
		"server.gin.port":  ":8080",
		"server.grpc.port": ":50051",
		"back.to.root":     "yes",
	}
	for key, want := range cases {
		if got := viper.GetString(key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

// TestParseINIInfersValueTypes covers the typing rules applied to keys that no
// application file declares first.
func TestParseINIInfersValueTypes(t *testing.T) {
	resetUtilitiesTestState(t)

	settings, err := parseINI(strings.Join([]string{
		"[server]",
		"port = :8080",
		"enabled = true",
		"disabled = FALSE",
		"limit = 1000",
		"ratio = 0.75",
		"version = 0.0.1",
		`name = "  spaced  "`,
		"quotedNumber = '42'",
		"commented = release ; trailing comment",
		"hashInValue = abc#123",
		"groups = [/api/v1, /api/v2]",
		"single = [/health]",
		"empty = []",
	}, "\n"))
	if err != nil {
		t.Fatalf("parseINI() error = %v", err)
	}

	server, ok := settings["server"].(map[string]any)
	if !ok {
		t.Fatalf("settings[server] = %#v, want map", settings["server"])
	}

	want := map[string]any{
		"port":         ":8080",
		"enabled":      true,
		"disabled":     false,
		"limit":        1000,
		"ratio":        0.75,
		"version":      "0.0.1",
		"name":         "  spaced  ",
		"quotedNumber": "42",
		"commented":    "release",
		"hashInValue":  "abc#123",
		"groups":       []any{"/api/v1", "/api/v2"},
		"single":       []any{"/health"},
		"empty":        []any{},
	}
	for key, wantValue := range want {
		if got := server[key]; !reflect.DeepEqual(got, wantValue) {
			t.Fatalf("server.%s = %#v (%T), want %#v (%T)", key, got, got, wantValue, wantValue)
		}
	}
}

// TestParseINIRepeatedKeysBuildList verifies the repeated-key list idiom.
func TestParseINIRepeatedKeysBuildList(t *testing.T) {
	resetUtilitiesTestState(t)

	settings, err := parseINI(strings.Join([]string{
		"[traces]",
		"SkipPaths = /health",
		"SkipPaths = /metrics",
		"SkipPaths = /ready",
	}, "\n"))
	if err != nil {
		t.Fatalf("parseINI() error = %v", err)
	}

	if err := viper.MergeConfigMap(settings); err != nil {
		t.Fatalf("viper.MergeConfigMap() error = %v", err)
	}

	want := []string{"/health", "/metrics", "/ready"}
	if got := viper.GetStringSlice("traces.SkipPaths"); !reflect.DeepEqual(got, want) {
		t.Fatalf("traces.SkipPaths = %#v, want %#v", got, want)
	}
}

// TestParseINIKeepsDeclaredTypes verifies that an overlay never changes the type
// of a key the application file already declares.
func TestParseINIKeepsDeclaredTypes(t *testing.T) {
	resetUtilitiesTestState(t)

	// Seed the config layer the way ReadInConfig does: viper.Set writes the
	// override layer, which would outrank the merged overlay on read-back.
	baseline := map[string]any{
		"server": map[string]any{
			"gin": map[string]any{
				"groups": []string{"/api/v1"},
				"rate":   map[string]any{"limit": 1000},
			},
		},
		"jwt": map[string]any{"enable": false},
		"app": map[string]any{"version": "0.0.1"},
	}
	if err := viper.MergeConfigMap(baseline); err != nil {
		t.Fatalf("viper.MergeConfigMap(baseline) error = %v", err)
	}

	settings, err := parseINI(strings.Join([]string{
		"[server.gin]",
		"groups = /v2, /v3",
		"rate.limit = 2500",
		"",
		"[jwt]",
		"enable = true",
		"",
		"[app]",
		"version = 1.0",
	}, "\n"))
	if err != nil {
		t.Fatalf("parseINI() error = %v", err)
	}
	if err := viper.MergeConfigMap(settings); err != nil {
		t.Fatalf("viper.MergeConfigMap() error = %v", err)
	}

	if got := viper.GetStringSlice("server.gin.groups"); !reflect.DeepEqual(got, []string{"/v2", "/v3"}) {
		t.Fatalf("server.gin.groups = %#v, want %#v", got, []string{"/v2", "/v3"})
	}
	if got := viper.GetInt("server.gin.rate.limit"); got != 2500 {
		t.Fatalf("server.gin.rate.limit = %d, want 2500", got)
	}
	if got := viper.GetBool("jwt.enable"); !got {
		t.Fatalf("jwt.enable = %v, want true", got)
	}
	// A string key stays a string even when the value looks like a number.
	if got := viper.GetString("app.version"); got != "1.0" {
		t.Fatalf("app.version = %q, want %q", got, "1.0")
	}
}

// TestParseINIRejectsMalformedContent verifies that a broken overlay fails loudly
// instead of being silently skipped.
func TestParseINIRejectsMalformedContent(t *testing.T) {
	resetUtilitiesTestState(t)

	cases := map[string]string{
		"missing separator":    "[app]\nname",
		"unterminated section": "[app\nname = x",
		"trailing garbage":     "[app] oops\nname = x",
		"missing key name":     "[app]\n. = x",
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseINI(content); err == nil {
				t.Fatalf("parseINI(%q) error = nil, want error", content)
			}
		})
	}
}

// TestINIFileNameRejectsUnusableNames verifies that app.name cannot select a
// file outside the configuration directory.
func TestINIFileNameRejectsUnusableNames(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"blank":            "   ",
		"current dir":      ".",
		"parent dir":       "..",
		"absolute path":    "/etc/passwd",
		"relative escape":  "../../secrets",
		"windows separMod": `..\secrets`,
		"default overlay":  "default",
	}
	for name, appName := range cases {
		t.Run(name, func(t *testing.T) {
			if got := iniFileName(appName); got != "" {
				t.Fatalf("iniFileName(%q) = %q, want empty", appName, got)
			}
		})
	}

	if got := iniFileName(" dragon-cmk "); got != "dragon-cmk.ini" {
		t.Fatalf("iniFileName() = %q, want %q", got, "dragon-cmk.ini")
	}
}

// TestLoadEnvMergesINIOverApplicationFile verifies the documented precedence:
// application file, then default.ini, then <app.name>.ini.
func TestLoadEnvMergesINIOverApplicationFile(t *testing.T) {
	resetUtilitiesTestState(t)

	dir := t.TempDir()
	writeApplicationYAML(t, dir, strings.Join([]string{
		"app:",
		"  name: dragon-cmk",
		"  version: 0.0.1",
		"server:",
		"  gin:",
		"    port: \":8080\"",
		"    groups:",
		"      - /api/v1",
	}, "\n"))
	writeINIFile(t, dir, "default.ini", strings.Join([]string{
		"[app]",
		"version = 0.0.2",
		"",
		"[server.gin]",
		"port = :9090",
		"groups = /api/v1, /api/v2",
	}, "\n"))
	writeINIFile(t, dir, "dragon-cmk.ini", strings.Join([]string{
		"[server.gin]",
		"port = :7070",
	}, "\n"))

	if err := LoadEnv(dir); err != nil {
		t.Fatalf("LoadEnv() error = %v", err)
	}

	if got := viper.GetString("app.name"); got != "dragon-cmk" {
		t.Fatalf("app.name = %q, want %q", got, "dragon-cmk")
	}
	// default.ini overrides the application file.
	if got := viper.GetString("app.version"); got != "0.0.2" {
		t.Fatalf("app.version = %q, want %q", got, "0.0.2")
	}
	// <app.name>.ini overrides default.ini.
	if got := viper.GetString("server.gin.port"); got != ":7070" {
		t.Fatalf("server.gin.port = %q, want %q", got, ":7070")
	}
	want := []string{"/api/v1", "/api/v2"}
	if got := viper.GetStringSlice("server.gin.groups"); !reflect.DeepEqual(got, want) {
		t.Fatalf("server.gin.groups = %#v, want %#v", got, want)
	}
}

// TestLoadEnvUsesAppNameFromINI verifies that an application name declared in
// default.ini still selects its own overlay.
func TestLoadEnvUsesAppNameFromINI(t *testing.T) {
	resetUtilitiesTestState(t)

	dir := t.TempDir()
	writeApplicationJSON(t, dir, map[string]any{
		"server": map[string]any{"port": ":8080"},
	})
	writeINIFile(t, dir, "default.ini", "[app]\nname = dragon-cmk\n")
	writeINIFile(t, dir, "dragon-cmk.ini", "[server]\nport = :7070\n")

	if err := LoadEnv(dir); err != nil {
		t.Fatalf("LoadEnv() error = %v", err)
	}

	if got := viper.GetString("server.port"); got != ":7070" {
		t.Fatalf("server.port = %q, want %q", got, ":7070")
	}
}

// TestLoadEnvSelectsINIFromAppNameEnv verifies that APP_NAME selects the overlay
// the same way it overrides every other configuration value.
func TestLoadEnvSelectsINIFromAppNameEnv(t *testing.T) {
	resetUtilitiesTestState(t)

	dir := t.TempDir()
	writeApplicationJSON(t, dir, map[string]any{
		"app":    map[string]any{"name": "dragon-cmk"},
		"server": map[string]any{"port": ":8080"},
	})
	writeINIFile(t, dir, "dragon-cmk.ini", "[server]\nport = :7070\n")
	writeINIFile(t, dir, "wyvern-cmk.ini", "[server]\nport = :6060\n")
	t.Setenv("APP_NAME", "wyvern-cmk")

	if err := LoadEnv(dir); err != nil {
		t.Fatalf("LoadEnv() error = %v", err)
	}

	if got := viper.GetString("server.port"); got != ":6060" {
		t.Fatalf("server.port = %q, want %q", got, ":6060")
	}
}

// TestLoadEnvWithoutApplicationFile verifies that a project configured through
// INI files alone loads, including through the resources/ lookup.
func TestLoadEnvWithoutApplicationFile(t *testing.T) {
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
	writeINIFile(t, resourcesDir, "default.ini", strings.Join([]string{
		"[app]",
		"name = dragon-cmk",
		"",
		"[server.gin]",
		"port = :8080",
		"rate.limit = 1000",
	}, "\n"))

	if err := LoadEnv(nestedDir); err != nil {
		t.Fatalf("LoadEnv() error = %v", err)
	}

	if got := viper.GetString("app.name"); got != "dragon-cmk" {
		t.Fatalf("app.name = %q, want %q", got, "dragon-cmk")
	}
	if got := viper.GetInt("server.gin.rate.limit"); got != 1000 {
		t.Fatalf("server.gin.rate.limit = %d, want 1000", got)
	}
}

// TestLoadEnvReportsMalformedINI verifies that a broken overlay stops startup
// instead of leaving the application half-configured.
func TestLoadEnvReportsMalformedINI(t *testing.T) {
	resetUtilitiesTestState(t)

	dir := t.TempDir()
	writeApplicationJSON(t, dir, map[string]any{"app": map[string]any{"name": "dragon-cmk"}})
	writeINIFile(t, dir, "default.ini", "[server\nport = :8080\n")

	err := LoadEnv(dir)
	if err == nil {
		t.Fatal("LoadEnv() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "default.ini") {
		t.Fatalf("LoadEnv() error = %v, want it to name default.ini", err)
	}
}

// TestLoadEnvEnvFilesOverrideINI verifies that .env files and process
// environment variables still win over the INI overlays.
func TestLoadEnvEnvFilesOverrideINI(t *testing.T) {
	resetUtilitiesTestState(t)

	dir := t.TempDir()
	writeApplicationJSON(t, dir, map[string]any{
		"app": map[string]any{"name": "dragon-cmk"},
		"env": map[string]any{"files": []string{".env"}},
		"server": map[string]any{
			"port":     ":8080",
			"modeTest": false,
		},
	})
	writeINIFile(t, dir, "default.ini", "[server]\nport = :9090\nmodeTest = true\n")
	writeEnvFile(t, dir, ".env", "SERVER_PORT=:6060\n")
	// godotenv.Overload writes to the process environment; t.Setenv registers the
	// cleanup that keeps the change from leaking into later tests.
	t.Setenv("SERVER_PORT", ":5050")

	if err := LoadEnv(dir); err != nil {
		t.Fatalf("LoadEnv() error = %v", err)
	}

	if got := viper.GetString("server.port"); got != ":6060" {
		t.Fatalf("server.port = %q, want %q", got, ":6060")
	}
	// A key the .env does not mention keeps the INI value.
	if got := viper.GetBool("server.modeTest"); !got {
		t.Fatalf("server.modeTest = %v, want true", got)
	}
}

// TestLoadEnvIgnoresMissingINIFiles verifies that the overlays stay optional.
func TestLoadEnvIgnoresMissingINIFiles(t *testing.T) {
	resetUtilitiesTestState(t)

	dir := t.TempDir()
	writeApplicationJSON(t, dir, map[string]any{
		"app": map[string]any{"name": "dragon-cmk"},
	})

	if err := LoadEnv(dir); err != nil {
		t.Fatalf("LoadEnv() error = %v", err)
	}
	if got := viper.GetString("app.name"); got != "dragon-cmk" {
		t.Fatalf("app.name = %q, want %q", got, "dragon-cmk")
	}
}

// TestMergeINIFileReportsReadErrors verifies that an unreadable overlay is
// reported rather than treated as absent.
func TestMergeINIFileReportsReadErrors(t *testing.T) {
	resetUtilitiesTestState(t)

	dir := t.TempDir()
	if err := mergeINIFile(dir); err == nil {
		t.Fatal("mergeINIFile(directory) error = nil, want error")
	}
}

// TestMergeINIFileIgnoresEmptyOverlay verifies that a comment-only file is a
// no-op rather than an error.
func TestMergeINIFileIgnoresEmptyOverlay(t *testing.T) {
	resetUtilitiesTestState(t)

	dir := t.TempDir()
	writeINIFile(t, dir, "default.ini", "; nothing configured yet\n")

	if err := mergeINIFile(filepath.Join(dir, "default.ini")); err != nil {
		t.Fatalf("mergeINIFile() error = %v", err)
	}
	if len(viper.AllSettings()) != 0 {
		t.Fatalf("viper.AllSettings() = %#v, want empty", viper.AllSettings())
	}
}

// TestHasINIConfigDetectsAppNameEnvOverlay verifies that a directory holding
// only <APP_NAME>.ini is discoverable, because that name is known up front.
func TestHasINIConfigDetectsAppNameEnvOverlay(t *testing.T) {
	resetUtilitiesTestState(t)

	dir := t.TempDir()
	writeINIFile(t, dir, "dragon-cmk.ini", "[app]\nname = dragon-cmk\n")

	if hasINIConfig(dir) {
		t.Fatal("hasINIConfig() = true without APP_NAME, want false")
	}

	t.Setenv("APP_NAME", "dragon-cmk")
	if !hasINIConfig(dir) {
		t.Fatal("hasINIConfig() = false with APP_NAME, want true")
	}
}

// TestParseINIRepeatedKeysMergeLists verifies that repeating a key whose value
// is already a list appends to it instead of nesting a list inside a list.
func TestParseINIRepeatedKeysMergeLists(t *testing.T) {
	resetUtilitiesTestState(t)

	baseline := map[string]any{
		"traces": map[string]any{"SkipPaths": []string{"/health"}},
	}
	if err := viper.MergeConfigMap(baseline); err != nil {
		t.Fatalf("viper.MergeConfigMap(baseline) error = %v", err)
	}

	settings, err := parseINI(strings.Join([]string{
		"[server.gin]",
		"groups = [/api/v1, /api/v2]",
		"groups = /api/v3",
		"",
		"[traces]",
		"SkipPaths = /metrics",
		"SkipPaths = /ready",
	}, "\n"))
	if err != nil {
		t.Fatalf("parseINI() error = %v", err)
	}
	if err := viper.MergeConfigMap(settings); err != nil {
		t.Fatalf("viper.MergeConfigMap() error = %v", err)
	}

	wantGroups := []string{"/api/v1", "/api/v2", "/api/v3"}
	if got := viper.GetStringSlice("server.gin.groups"); !reflect.DeepEqual(got, wantGroups) {
		t.Fatalf("server.gin.groups = %#v, want %#v", got, wantGroups)
	}

	// The declared []string type is preserved while the repeats accumulate.
	wantSkipPaths := []string{"/metrics", "/ready"}
	if got := viper.GetStringSlice("traces.SkipPaths"); !reflect.DeepEqual(got, wantSkipPaths) {
		t.Fatalf("traces.SkipPaths = %#v, want %#v", got, wantSkipPaths)
	}
}

// TestLoadEnvReadsEnvFilesDeclaredInINI verifies that an INI-only project can
// declare env.files, in both the list and comma-separated forms.
func TestLoadEnvReadsEnvFilesDeclaredInINI(t *testing.T) {
	cases := map[string]string{
		"list form":  "[env]\nfiles = [.env, .env.local]\n",
		"comma form": "[env]\nfiles = .env, .env.local\n",
	}

	for name, envSection := range cases {
		t.Run(name, func(t *testing.T) {
			resetUtilitiesTestState(t)

			dir := t.TempDir()
			writeINIFile(t, dir, "default.ini", envSection+"\n[app]\nname = dragon-cmk\n")
			writeEnvFile(t, dir, ".env", "APP_NAME=from-env\n")
			writeEnvFile(t, dir, ".env.local", "APP_NAME=from-local\n")
			t.Setenv("APP_NAME", "from-process")

			if err := LoadEnv(dir); err != nil {
				t.Fatalf("LoadEnv() error = %v", err)
			}
			if got := viper.GetString("app.name"); got != "from-local" {
				t.Fatalf("app.name = %q, want %q", got, "from-local")
			}
		})
	}
}
