// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package sanitizer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"strings"

	"github.com/PointerByte/forge-go/logger/formatter"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
)

const (
	// RedactedValue is the value emitted when a configured sensitive key is found.
	RedactedValue = "[REDACTED]"
	maxDepth      = 32
)

type redactPattern struct {
	re          *regexp.Regexp
	replacement string
}

// Sanitizer redacts values whose keys match logger.sensibleKeys.
type Sanitizer struct {
	keys     map[string]struct{}
	patterns []redactPattern
}

// New creates a Sanitizer from a slice of sensitive key names.
func New(keys []string) Sanitizer {
	s := Sanitizer{keys: map[string]struct{}{}}
	for _, key := range keys {
		key = normalizeKey(key)
		if key == "" {
			continue
		}
		s.keys[key] = struct{}{}
		s.patterns = append(s.patterns, patternsForKey(key)...)
	}
	return s
}

// FromViper builds a Sanitizer from the cached logger.sensibleKeys configuration.
func FromViper() Sanitizer {
	keys, _ := viperdata.GetViperData(string(viperdata.LoggerSensibleKeysAtribute)).([]string)
	return New(keys)
}

// Enabled reports whether at least one sensitive key is configured.
func (s Sanitizer) Enabled() bool {
	return len(s.keys) > 0
}

// LogFormat redacts sensitive values in a full formatter log model.
func (s Sanitizer) LogFormat(log formatter.LogFormat) formatter.LogFormat {
	if !s.Enabled() {
		return log
	}

	log.Message = s.sanitizeString(log.Message)
	log.Details = s.Details(log.Details)
	for index := range log.Process {
		log.Process[index] = s.Service(log.Process[index])
	}
	if sanitized, ok := s.Value(log.Attributes).(map[string]any); ok {
		log.Attributes = sanitized
	}
	return log
}

// Details redacts sensitive values in structured request details.
func (s Sanitizer) Details(details formatter.Details) formatter.Details {
	if !s.Enabled() {
		return details
	}

	details.Client = s.sanitizeString(details.Client)
	details.Protocol = s.sanitizeString(details.Protocol)
	details.Method = s.sanitizeString(details.Method)
	details.Path = s.sanitizeString(details.Path)
	details.Headers = s.Headers(details.Headers)
	details.Request = s.Value(details.Request)
	details.Response = s.Value(details.Response)
	return details
}

// Service redacts sensitive values in a traced downstream service entry.
func (s Sanitizer) Service(service formatter.Process) formatter.Process {
	if !s.Enabled() {
		return service
	}

	service.Server = s.sanitizeString(service.Server)
	service.Protocol = s.sanitizeString(service.Protocol)
	service.Method = s.sanitizeString(service.Method)
	service.Path = s.sanitizeString(service.Path)
	if service.Headers != nil {
		headers := s.Headers(*service.Headers)
		service.Headers = &headers
	}
	service.Request = s.Value(service.Request)
	service.Response = s.Value(service.Response)
	return service
}

// Headers redacts configured header names and sanitizes JSON-looking header values.
func (s Sanitizer) Headers(headers http.Header) http.Header {
	if headers == nil || !s.Enabled() {
		return headers
	}

	out := make(http.Header, len(headers))
	for key, values := range headers {
		outValues := make([]string, len(values))
		if s.isSensitive(key) {
			for index := range values {
				outValues[index] = RedactedValue
			}
			out[key] = outValues
			continue
		}
		for index, value := range values {
			outValues[index] = s.sanitizeString(value)
		}
		out[key] = outValues
	}
	return out
}

// Value redacts sensitive keys in maps, slices, structs, JSON strings, and raw key=value strings.
func (s Sanitizer) Value(value any) any {
	if !s.Enabled() {
		return value
	}
	return s.value("", value, 0)
}

func (s Sanitizer) value(key string, value any, depth int) any {
	if key != "" && s.isSensitive(key) {
		return RedactedValue
	}
	if value == nil {
		return value
	}
	if depth > maxDepth {
		return RedactedValue
	}

	switch cast := value.(type) {
	case string:
		return s.sanitizeString(cast)
	case []byte:
		return s.sanitizeString(string(cast))
	case http.Header:
		return s.Headers(cast)
	case map[string]any:
		out := make(map[string]any, len(cast))
		for childKey, childValue := range cast {
			out[childKey] = s.value(childKey, childValue, depth+1)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(cast))
		for childKey, childValue := range cast {
			if s.isSensitive(childKey) {
				out[childKey] = RedactedValue
				continue
			}
			out[childKey] = s.sanitizeString(childValue)
		}
		return out
	case map[string][]string:
		out := make(map[string][]string, len(cast))
		for childKey, childValues := range cast {
			values := make([]string, len(childValues))
			if s.isSensitive(childKey) {
				for index := range childValues {
					values[index] = RedactedValue
				}
				out[childKey] = values
				continue
			}
			for index, childValue := range childValues {
				values[index] = s.sanitizeString(childValue)
			}
			out[childKey] = values
		}
		return out
	case []any:
		out := make([]any, len(cast))
		for index, childValue := range cast {
			out[index] = s.value("", childValue, depth+1)
		}
		return out
	case []string:
		out := make([]string, len(cast))
		for index, childValue := range cast {
			out[index] = s.sanitizeString(childValue)
		}
		return out
	}

	return s.reflectValue(value, depth)
}

func (s Sanitizer) reflectValue(value any, depth int) any {
	rv := reflect.ValueOf(value)
	if !rv.IsValid() {
		return value
	}

	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		if !rv.Elem().CanInterface() {
			return value
		}
		return s.value("", rv.Elem().Interface(), depth+1)
	case reflect.Map:
		out := make(map[string]any, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			childKey := fmt.Sprint(iter.Key().Interface())
			childValue := iter.Value()
			if !childValue.CanInterface() {
				continue
			}
			out[childKey] = s.value(childKey, childValue.Interface(), depth+1)
		}
		return out
	case reflect.Slice, reflect.Array:
		out := make([]any, rv.Len())
		for index := 0; index < rv.Len(); index++ {
			childValue := rv.Index(index)
			if !childValue.CanInterface() {
				continue
			}
			out[index] = s.value("", childValue.Interface(), depth+1)
		}
		return out
	case reflect.Struct:
		return s.structValue(value, depth)
	default:
		return value
	}
}

func (s Sanitizer) structValue(value any, depth int) any {
	data, err := json.Marshal(value)
	if err != nil {
		return RedactedValue
	}

	var decoded any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return s.sanitizeString(string(data))
	}
	return s.value("", decoded, depth+1)
}

func (s Sanitizer) sanitizeString(value string) string {
	if value == "" || !s.Enabled() {
		return value
	}

	if sanitizedJSON, ok := s.sanitizeJSONString(value); ok {
		return sanitizedJSON
	}

	out := value
	for _, pattern := range s.patterns {
		out = pattern.re.ReplaceAllString(out, pattern.replacement)
	}
	return out
}

func (s Sanitizer) sanitizeJSONString(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return "", false
	}

	var decoded any
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return "", false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return "", false
	}

	sanitized := s.value("", decoded, 0)
	data, err := json.Marshal(sanitized)
	if err != nil {
		return "", false
	}
	return string(data), true
}

func (s Sanitizer) isSensitive(key string) bool {
	key = normalizeKey(key)
	if key == "" {
		return false
	}
	if _, ok := s.keys[key]; ok {
		return true
	}
	for sensibleKey := range s.keys {
		if strings.Contains(key, sensibleKey) {
			return true
		}
	}
	return false
}

func normalizeKey(key string) string {
	return strings.ToLower(strings.TrimSpace(key))
}

func patternsForKey(key string) []redactPattern {
	quoted := regexp.QuoteMeta(key)
	return []redactPattern{
		{
			re:          regexp.MustCompile(`(?i)("` + quoted + `"\s*:\s*")([^"]*)(")`),
			replacement: `${1}` + RedactedValue + `${3}`,
		},
		{
			re:          regexp.MustCompile(`(?i)("` + quoted + `"\s*:\s*)([^,}\]\s]+)`),
			replacement: `${1}"` + RedactedValue + `"`,
		},
		{
			re:          regexp.MustCompile(`(?i)(\b` + quoted + `\b\s*[=:]\s*)([^\s,;&]+)`),
			replacement: `${1}` + RedactedValue,
		},
	}
}
