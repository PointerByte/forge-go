// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package utilities

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

const (
	// defaultININame is the project-independent INI overlay. It is the only
	// INI file that can be discovered before app.name is known, which is why
	// LoadEnv also accepts it when no application.yml is present.
	defaultININame = "default.ini"
	iniExtension   = ".ini"
	appNameKey     = "app.name"
	appNameEnv     = "APP_NAME"
)

// loadINIFiles merges the INI overlays living in configDir. default.ini is
// merged first and <app.name>.ini second, so a project-specific file always
// wins over the shared defaults. Both files are optional; a missing one is not
// an error, but a malformed one is.
func loadINIFiles(configDir string) error {
	if err := mergeINIFile(filepath.Join(configDir, defaultININame)); err != nil {
		return err
	}

	// app.name may itself come from default.ini, so it is resolved after that
	// file has been merged.
	name := applicationININame()
	if name == "" {
		return nil
	}
	return mergeINIFile(filepath.Join(configDir, name))
}

// mergeINIFile merges a single INI file into the current Viper settings.
func mergeINIFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	settings, err := parseINI(string(content))
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(settings) == 0 {
		return nil
	}
	return viper.MergeConfigMap(settings)
}

// hasINIConfig reports whether dir holds an INI file that can be found before
// any configuration is loaded: default.ini, or the file named by the APP_NAME
// environment variable. <app.name>.ini alone cannot make a directory
// discoverable, because the name is only known once a file has been read.
func hasINIConfig(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, defaultININame)); err == nil {
		return true
	}

	name := iniFileName(os.Getenv(appNameEnv))
	if name == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

// applicationININame returns the INI file named after the application. The
// APP_NAME environment variable wins over the loaded app.name so a deployment
// can select its overlay the same way it overrides every other key.
func applicationININame() string {
	if name := iniFileName(os.Getenv(appNameEnv)); name != "" {
		return name
	}
	return iniFileName(viper.GetString(appNameKey))
}

// iniFileName turns an application name into its INI file name. Names that
// contain a path separator are rejected: app.name is configuration data, and it
// must not be able to select a file outside the configuration directory.
func iniFileName(appName string) string {
	appName = strings.TrimSpace(appName)
	if appName == "" || appName == "." || appName == ".." {
		return ""
	}
	if strings.ContainsAny(appName, `/\`) {
		return ""
	}

	name := appName + iniExtension
	if strings.EqualFold(name, defaultININame) {
		// Already merged as the shared overlay.
		return ""
	}
	return name
}

// parseINI converts INI content into the nested map Viper merges.
//
// Section headers and dotted keys build the same key path, so [server.gin] with
// port and [server] with gin.port both produce server.gin.port. Values are
// typed against the configuration already loaded when the key exists there, and
// inferred otherwise. Quoting a value keeps it a string, [a, b] declares a
// list, and repeating a key appends to one. Comments start with ; or # at the
// beginning of a line, or after whitespace on an unquoted value.
func parseINI(content string) (map[string]any, error) {
	settings := make(map[string]any)
	var section []string

	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, ";") || strings.HasPrefix(text, "#") {
			continue
		}

		if strings.HasPrefix(text, "[") {
			name, err := parseINISection(text)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line, err)
			}
			section = name
			continue
		}

		key, raw, found := strings.Cut(text, "=")
		if !found {
			return nil, fmt.Errorf("line %d: expected [section] or key = value, got %q", line, text)
		}

		leaf := splitINIKey(key)
		if len(leaf) == 0 {
			return nil, fmt.Errorf("line %d: missing key name in %q", line, text)
		}

		path := append(append(make([]string, 0, len(section)+len(leaf)), section...), leaf...)
		setINIValue(settings, path, parseINIValue(raw, path))
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return settings, nil
}

// parseINISection reads a [section] header into a key path. An empty [] header
// returns to the root section.
func parseINISection(text string) ([]string, error) {
	end := strings.Index(text, "]")
	if end < 0 {
		return nil, fmt.Errorf("unterminated section header %q", text)
	}

	if rest := strings.TrimSpace(text[end+1:]); rest != "" &&
		!strings.HasPrefix(rest, ";") && !strings.HasPrefix(rest, "#") {
		return nil, fmt.Errorf("unexpected %q after section header", rest)
	}
	return splitINIKey(text[1:end]), nil
}

// splitINIKey turns a dotted key or section name into a Viper key path.
func splitINIKey(raw string) []string {
	parts := make([]string, 0, 4)
	for _, part := range strings.Split(raw, ".") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		parts = append(parts, part)
	}
	return parts
}

// setINIValue stores value at path, creating the intermediate maps. Repeating a
// key inside one file appends to a list instead of replacing the first value.
func setINIValue(settings map[string]any, path []string, value any) {
	node := settings
	for _, part := range path[:len(path)-1] {
		child, ok := node[part].(map[string]any)
		if !ok {
			child = make(map[string]any)
			node[part] = child
		}
		node = child
	}

	leaf := path[len(path)-1]
	existing, repeated := node[leaf]
	if !repeated {
		node[leaf] = value
		return
	}
	node[leaf] = append(iniValueList(existing), iniValueList(value)...)
}

// iniValueList normalizes a value into the slice form repeated keys build.
func iniValueList(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	case []string:
		items := make([]any, 0, len(typed))
		for _, item := range typed {
			items = append(items, item)
		}
		return items
	default:
		return []any{value}
	}
}

// parseINIValue converts one raw INI value into the type Viper should hold.
// A key that the application file already declares reuses the environment
// override conversion, so an INI overlay never changes the type of an existing
// setting; new keys fall back to inference.
func parseINIValue(raw string, path []string) any {
	value, quoted := trimINIValue(raw)
	if quoted {
		return value
	}
	if items, ok := parseINIList(value); ok {
		return items
	}
	if template := viper.Get(strings.Join(path, ".")); template != nil {
		return parseEnvValue(value, template)
	}
	return inferINIScalar(value)
}

// trimINIValue removes surrounding whitespace, one matching pair of quotes and
// any trailing comment. The bool reports whether the value was quoted, which
// keeps it a string regardless of its contents.
func trimINIValue(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", false
	}

	if quote := value[0]; quote == '"' || quote == '\'' {
		if end := strings.IndexByte(value[1:], quote); end >= 0 {
			return value[1 : end+1], true
		}
	}
	return strings.TrimSpace(stripINIComment(value)), false
}

// stripINIComment removes a trailing ; or # comment. The marker must follow
// whitespace, so values that embed one, such as a password or a colour, survive.
func stripINIComment(value string) string {
	for index := 1; index < len(value); index++ {
		if value[index] != ';' && value[index] != '#' {
			continue
		}
		if previous := value[index-1]; previous == ' ' || previous == '\t' {
			return value[:index]
		}
	}
	return value
}

// parseINIList reads the [a, b, c] form that declares a list explicitly. It is
// needed because a single-element list is otherwise indistinguishable from a
// scalar when no application file declares the key first.
func parseINIList(value string) ([]any, bool) {
	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		return nil, false
	}

	var decoded []any
	if err := json.Unmarshal([]byte(value), &decoded); err == nil {
		return decoded, true
	}

	items := make([]any, 0)
	for _, item := range splitCommaSeparated(value[1 : len(value)-1]) {
		if trimmed, quoted := trimINIValue(item); quoted {
			items = append(items, trimmed)
		} else {
			items = append(items, inferINIScalar(trimmed))
		}
	}
	return items, true
}

// inferINIScalar types a value that no application file declares first. Only
// true and false become booleans: 1 and 0 stay numbers, because ports, limits
// and sizes are far more common in this configuration than flags written as
// digits.
func inferINIScalar(value string) any {
	switch strings.ToLower(value) {
	case "true":
		return true
	case "false":
		return false
	}

	if parsed, err := strconv.Atoi(value); err == nil {
		return parsed
	}
	if parsed, err := strconv.ParseFloat(value, 64); err == nil {
		return parsed
	}
	return value
}
