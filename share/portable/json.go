package portable

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

func strictDecode(data []byte, destination any, maxDepth int) *ABIError {
	if !utf8.Valid(data) {
		return newABIError(ErrorInvalidUTF8, "")
	}
	if err := validateJSONStructure(data, maxDepth); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return newABIError(ErrorUnknownField, "")
		}
		return newABIError(ErrorInvalidJSON, "")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return newABIError(ErrorInvalidJSON, "")
	}
	return nil
}

func strictDecodeObject(data []byte, destination any, maxDepth int) *ABIError {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return newABIError(ErrorInvalidJSON, "payload")
	}
	return strictDecode(trimmed, destination, maxDepth)
}

func requireJSONFields(data []byte, fields ...string) *ABIError {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return newABIError(ErrorInvalidJSON, "payload")
	}
	for _, field := range fields {
		value, exists := object[field]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return newABIError(ErrorInvalidRequest, "payload."+field)
		}
	}
	return nil
}

func validateJSONStructure(data []byte, maxDepth int) *ABIError {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	var scanValue func(int) *ABIError
	scanValue = func(depth int) *ABIError {
		if depth > maxDepth {
			return newABIError(ErrorInvalidJSON, "")
		}
		token, err := decoder.Token()
		if err != nil {
			return newABIError(ErrorInvalidJSON, "")
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}

		switch delimiter {
		case '{':
			fields := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return newABIError(ErrorInvalidJSON, "")
				}
				key, ok := keyToken.(string)
				if !ok {
					return newABIError(ErrorInvalidJSON, "")
				}
				if _, exists := fields[key]; exists {
					return newABIError(ErrorDuplicateField, key)
				}
				fields[key] = struct{}{}
				if err := scanValue(depth + 1); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return newABIError(ErrorInvalidJSON, "")
			}
		case '[':
			for decoder.More() {
				if err := scanValue(depth + 1); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return newABIError(ErrorInvalidJSON, "")
			}
		default:
			return newABIError(ErrorInvalidJSON, "")
		}
		return nil
	}

	if err := scanValue(1); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return newABIError(ErrorInvalidJSON, "")
	}
	return nil
}
