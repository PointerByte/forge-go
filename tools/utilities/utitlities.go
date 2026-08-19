package utilities

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

var readInConfig = viper.ReadInConfig

const resourcesDirName = "resources"

type configFileCandidate struct {
	name       string
	configType string
}

var configFileCandidates = []configFileCandidate{
	{name: "application.yml", configType: "yml"},
	{name: "application.yaml", configType: "yaml"},
	{name: "application.json", configType: "json"},
}

// LoadEnv resolves the GoForge runtime configuration directory and loads it
// into Viper. If prefixPath is empty, the current working directory is used. If
// prefixPath contains application.yml, application.yaml, application.json, or
// default.ini directly, that directory is used; otherwise LoadEnv walks upward
// looking for the nearest resources/ directory with one of those files. When no
// matching resources/ directory is found, it falls back to prefixPath/resources
// so the returned read error points at the expected location.
//
// Configuration is loaded in this order, each step overriding the previous one:
// application.yml, application.yaml, or application.json; default.ini;
// <app.name>.ini; the environment files declared in env.files; and finally
// process environment variable overrides derived from the existing Viper key
// paths, for example app.name -> APP_NAME. Missing .env and .ini files are
// ignored, but a malformed .ini and a failure to read the selected application
// file are returned. The application file becomes optional only when the
// directory is configured through INI files alone.
func LoadEnv(prefixPath string) error {
	if prefixPath == "" {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		prefixPath = dir
	}

	configDir := resolveConfigDir(prefixPath)

	// A project configured through INI files alone has no application file to
	// read, and reporting one as missing would be wrong. Every other case keeps
	// the original behavior, including the error that names application.json.
	configFile, configType, found := resolveConfigFile(configDir)
	if found || !hasINIConfig(configDir) {
		viper.SetConfigFile(configFile)
		viper.SetConfigType(configType)
		if err := readInConfig(); err != nil {
			return err
		}
	}

	if err := loadINIFiles(configDir); err != nil {
		return err
	}

	loadEnvFiles(configDir)

	// Enable reading from environment variables.
	viper.AutomaticEnv()

	// Apply mapped environment variable overrides.
	exportMappedEnv()
	return nil
}

func loadEnvFiles(configDir string) {
	for _, envFile := range resolveEnvFiles(configDir) {
		_ = godotenv.Overload(envFile)
		viper.SetConfigFile(envFile)
		viper.SetConfigType("env")
		_ = viper.MergeInConfig()
	}
}

func resolveEnvFiles(configDir string) []string {
	envFiles := make([]string, 0)
	for _, envFile := range envFileNames() {
		envFile = strings.TrimSpace(envFile)
		if envFile == "" {
			continue
		}
		if !filepath.IsAbs(envFile) {
			envFile = filepath.Join(configDir, envFile)
		}
		envFiles = append(envFiles, envFile)
	}
	return envFiles
}

// envFileNames returns the env.files entries. A list is read as-is; a single
// comma-separated string is split, which is the form an INI file produces for a
// key no application file declared first.
func envFileNames() []string {
	if raw, ok := viper.Get("env.files").(string); ok {
		return splitCommaSeparated(raw)
	}
	return viper.GetStringSlice("env.files")
}

func resolveConfigDir(prefixPath string) string {
	if strings.TrimSpace(prefixPath) == "" {
		prefixPath = "."
	}

	if hasConfigFiles(prefixPath) {
		return prefixPath
	}

	if configDir := findResourcesConfigDir(prefixPath); configDir != "" {
		return configDir
	}

	return filepath.Join(prefixPath, resourcesDirName)
}

func findResourcesConfigDir(prefixPath string) string {
	dir, err := filepath.Abs(prefixPath)
	if err != nil {
		dir = filepath.Clean(prefixPath)
	}

	for {
		configDir := filepath.Join(dir, resourcesDirName)
		if hasConfigFiles(configDir) {
			return configDir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// hasConfigFiles reports whether dir is a usable configuration directory,
// which an INI-only project satisfies without an application file.
func hasConfigFiles(dir string) bool {
	return hasApplicationConfig(dir) || hasINIConfig(dir)
}

func hasApplicationConfig(dir string) bool {
	for _, candidate := range configFileCandidates {
		if _, err := os.Stat(filepath.Join(dir, candidate.name)); err == nil {
			return true
		}
	}
	return false
}

// resolveConfigFile returns the application file to read and whether one
// actually exists. The fallback keeps the read error pointing at
// application.json when the directory holds no configuration at all.
func resolveConfigFile(dir string) (string, string, bool) {
	for _, candidate := range configFileCandidates {
		configFile := filepath.Join(dir, candidate.name)
		if _, err := os.Stat(configFile); err == nil {
			return configFile, candidate.configType, true
		}
	}
	return filepath.Join(dir, "application.json"), "json", false
}

func exportMappedEnv() {
	applyEnvOverrides(viper.AllSettings(), nil)
}

func applyEnvOverrides(node any, path []string) {
	switch value := node.(type) {
	case map[string]any:
		for key, nested := range value {
			applyEnvOverrides(nested, append(path, key))
		}
	case map[any]any:
		for rawKey, nested := range value {
			key, ok := rawKey.(string)
			if !ok {
				continue
			}
			applyEnvOverrides(nested, append(path, key))
		}
	default:
		if len(path) == 0 {
			return
		}
		envName := envNameFromPath(path)
		rawValue, ok := os.LookupEnv(envName)
		if !ok {
			return
		}
		viper.Set(strings.Join(path, "."), parseEnvValue(rawValue, value))
	}
}

func envNameFromPath(path []string) string {
	parts := make([]string, 0, len(path))
	for _, part := range path {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		parts = append(parts, strings.ToUpper(part))
	}
	return strings.Join(parts, "_")
}

func parseEnvValue(raw string, template any) any {
	raw = strings.TrimSpace(raw)
	switch template := template.(type) {
	case bool:
		if parsed, err := strconv.ParseBool(raw); err == nil {
			return parsed
		}
	case int:
		if parsed, err := strconv.Atoi(raw); err == nil {
			return parsed
		}
	case int8, int16, int32, int64:
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return parsed
		}
	case uint, uint8, uint16, uint32, uint64:
		if parsed, err := strconv.ParseUint(raw, 10, 64); err == nil {
			return parsed
		}
	case float32, float64:
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
			return parsed
		}
	case []string:
		return parseStringSlice(raw)
	case []any:
		return parseSliceValue(raw, template)
	}
	return raw
}

func parseStringSlice(raw string) []string {
	if strings.HasPrefix(raw, "[") {
		var items []string
		if err := json.Unmarshal([]byte(raw), &items); err == nil {
			return items
		}
	}
	return splitCommaSeparated(raw)
}

func parseSliceValue(raw string, template []any) any {
	if strings.HasPrefix(raw, "[") {
		if allStringValues(template) {
			var items []string
			if err := json.Unmarshal([]byte(raw), &items); err == nil {
				return items
			}
		}

		var items []any
		if err := json.Unmarshal([]byte(raw), &items); err == nil {
			return items
		}
	}

	values := splitCommaSeparated(raw)
	if allStringValues(template) {
		return values
	}

	items := make([]any, 0, len(values))
	for _, value := range values {
		items = append(items, value)
	}
	return items
}

func allStringValues(values []any) bool {
	if len(values) == 0 {
		return true
	}

	for _, value := range values {
		if _, ok := value.(string); !ok {
			return false
		}
	}
	return true
}

func splitCommaSeparated(raw string) []string {
	if raw == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}
