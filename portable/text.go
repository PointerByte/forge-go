package portable

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

type normalizePayload struct {
	Value              string `json:"value"`
	Trim               bool   `json:"trim"`
	CollapseWhitespace bool   `json:"collapse_whitespace"`
	LowercaseASCII     bool   `json:"lowercase_ascii"`
}

type normalizeResult struct {
	Value string `json:"value"`
}

func (d *Dispatcher) normalize(payload []byte) (any, *ABIError) {
	var input normalizePayload
	if err := strictDecodeObject(payload, &input, d.limits.MaxJSONDepth); err != nil {
		return nil, err
	}
	if err := requireJSONFields(payload, "value"); err != nil {
		return nil, err
	}
	if !utf8.ValidString(input.Value) {
		return nil, newABIError(ErrorInvalidUTF8, "payload.value")
	}
	if len(input.Value) > d.limits.MaxStringBytes {
		return nil, newABIError(ErrorInputTooLarge, "payload.value")
	}

	value := input.Value
	if input.Trim {
		value = strings.TrimSpace(value)
	}
	if input.CollapseWhitespace {
		value = collapseWhitespace(value)
	}
	if input.LowercaseASCII {
		value = lowercaseASCII(value)
	}
	return normalizeResult{Value: value}, nil
}

func collapseWhitespace(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	inWhitespace := false
	for _, character := range value {
		if unicode.IsSpace(character) {
			if !inWhitespace {
				builder.WriteByte(' ')
				inWhitespace = true
			}
			continue
		}
		inWhitespace = false
		builder.WriteRune(character)
	}
	return builder.String()
}

func lowercaseASCII(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for _, character := range value {
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		builder.WriteRune(character)
	}
	return builder.String()
}

type validationRules struct {
	Required         bool   `json:"required"`
	ASCII            bool   `json:"ascii"`
	ForbidControl    bool   `json:"forbid_control"`
	ForbidWhitespace bool   `json:"forbid_whitespace"`
	MinBytes         int    `json:"min_bytes"`
	MaxBytes         int    `json:"max_bytes"`
	MinRunes         int    `json:"min_runes"`
	MaxRunes         int    `json:"max_runes"`
	Prefix           string `json:"prefix"`
	Suffix           string `json:"suffix"`
}

type validatePayload struct {
	Value string          `json:"value"`
	Rules validationRules `json:"rules"`
}

type validationViolation struct {
	Code string `json:"code"`
}

type validateResult struct {
	Valid      bool                  `json:"valid"`
	Violations []validationViolation `json:"violations"`
}

func (d *Dispatcher) validate(payload []byte) (any, *ABIError) {
	var input validatePayload
	if err := strictDecodeObject(payload, &input, d.limits.MaxJSONDepth); err != nil {
		return nil, err
	}
	if err := requireJSONFields(payload, "value", "rules"); err != nil {
		return nil, err
	}
	if !utf8.ValidString(input.Value) || !utf8.ValidString(input.Rules.Prefix) || !utf8.ValidString(input.Rules.Suffix) {
		return nil, newABIError(ErrorInvalidUTF8, "payload")
	}
	if len(input.Value) > d.limits.MaxStringBytes ||
		len(input.Rules.Prefix) > d.limits.MaxStringBytes ||
		len(input.Rules.Suffix) > d.limits.MaxStringBytes {
		return nil, newABIError(ErrorInputTooLarge, "payload")
	}
	if err := validateRules(input.Rules, d.limits.MaxStringBytes); err != nil {
		return nil, err
	}

	violations := make([]validationViolation, 0, 10)
	if input.Rules.Required && input.Value == "" {
		violations = append(violations, validationViolation{Code: "required"})
	}
	if input.Rules.MinBytes > 0 && len(input.Value) < input.Rules.MinBytes {
		violations = append(violations, validationViolation{Code: "min_bytes"})
	}
	if input.Rules.MaxBytes > 0 && len(input.Value) > input.Rules.MaxBytes {
		violations = append(violations, validationViolation{Code: "max_bytes"})
	}
	runeCount := utf8.RuneCountInString(input.Value)
	if input.Rules.MinRunes > 0 && runeCount < input.Rules.MinRunes {
		violations = append(violations, validationViolation{Code: "min_runes"})
	}
	if input.Rules.MaxRunes > 0 && runeCount > input.Rules.MaxRunes {
		violations = append(violations, validationViolation{Code: "max_runes"})
	}
	if input.Rules.ASCII && !isASCII(input.Value) {
		violations = append(violations, validationViolation{Code: "ascii"})
	}
	if input.Rules.ForbidControl && containsControl(input.Value) {
		violations = append(violations, validationViolation{Code: "control"})
	}
	if input.Rules.ForbidWhitespace && containsWhitespace(input.Value) {
		violations = append(violations, validationViolation{Code: "whitespace"})
	}
	if input.Rules.Prefix != "" && !strings.HasPrefix(input.Value, input.Rules.Prefix) {
		violations = append(violations, validationViolation{Code: "prefix"})
	}
	if input.Rules.Suffix != "" && !strings.HasSuffix(input.Value, input.Rules.Suffix) {
		violations = append(violations, validationViolation{Code: "suffix"})
	}
	return validateResult{Valid: len(violations) == 0, Violations: violations}, nil
}

func validateRules(rules validationRules, maximum int) *ABIError {
	if rules.MinBytes < 0 || rules.MaxBytes < 0 || rules.MinRunes < 0 || rules.MaxRunes < 0 ||
		rules.MinBytes > maximum || rules.MaxBytes > maximum || rules.MinRunes > maximum || rules.MaxRunes > maximum ||
		(rules.MaxBytes > 0 && rules.MinBytes > rules.MaxBytes) ||
		(rules.MaxRunes > 0 && rules.MinRunes > rules.MaxRunes) {
		return newABIError(ErrorInvalidRequest, "payload.rules")
	}
	return nil
}

func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func containsControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func containsWhitespace(value string) bool {
	for _, character := range value {
		if unicode.IsSpace(character) {
			return true
		}
	}
	return false
}
