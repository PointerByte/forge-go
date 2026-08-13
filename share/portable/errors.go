package portable

// ErrorCode is a stable machine-readable ABI error identifier.
type ErrorCode string

const (
	ErrorInvalidJSON            ErrorCode = "invalid_json"
	ErrorUnknownField           ErrorCode = "unknown_field"
	ErrorDuplicateField         ErrorCode = "duplicate_field"
	ErrorRequestTooLarge        ErrorCode = "request_too_large"
	ErrorResponseTooLarge       ErrorCode = "response_too_large"
	ErrorInvalidABI             ErrorCode = "invalid_abi"
	ErrorInvalidRequest         ErrorCode = "invalid_request"
	ErrorUnknownOperation       ErrorCode = "unknown_operation"
	ErrorCapabilityUnavailable  ErrorCode = "capability_unavailable"
	ErrorExecutionStateRequired ErrorCode = "execution_state_required"
	ErrorDeadlineExceeded       ErrorCode = "deadline_exceeded"
	ErrorCancellationRequested  ErrorCode = "cancellation_requested"
	ErrorInvalidBase64          ErrorCode = "invalid_base64"
	ErrorInvalidUTF8            ErrorCode = "invalid_utf8"
	ErrorInputTooLarge          ErrorCode = "input_too_large"
	ErrorInvalidKey             ErrorCode = "invalid_key"
	ErrorInvalidNonce           ErrorCode = "invalid_nonce"
	ErrorAuthenticationFailed   ErrorCode = "authentication_failed"
	ErrorInternal               ErrorCode = "internal"
)

// ABIError is the unified portable error representation. Message is stable
// and never includes an underlying cryptographic or runtime error.
type ABIError struct {
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	Retryable bool      `json:"retryable"`
	Field     string    `json:"field,omitempty"`
}

// Error implements error.
func (e *ABIError) Error() string {
	if e == nil {
		return ""
	}
	return string(e.Code) + ": " + e.Message
}

// ErrorDefinition describes a stable catalog entry in the manifest.
type ErrorDefinition struct {
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	Retryable bool      `json:"retryable"`
}

var errorCatalog = []ErrorDefinition{
	{ErrorInvalidJSON, "JSON is malformed or not canonical ABI input", false},
	{ErrorUnknownField, "JSON contains an unknown field", false},
	{ErrorDuplicateField, "JSON contains a duplicate object field", false},
	{ErrorRequestTooLarge, "request exceeds the configured byte limit", false},
	{ErrorResponseTooLarge, "response exceeds the configured byte limit", false},
	{ErrorInvalidABI, "request ABI version is unsupported", false},
	{ErrorInvalidRequest, "request does not satisfy the ABI contract", false},
	{ErrorUnknownOperation, "operation is unsupported", false},
	{ErrorCapabilityUnavailable, "required capability is unavailable", false},
	{ErrorExecutionStateRequired, "host did not provide checked execution state", false},
	{ErrorDeadlineExceeded, "request deadline has been exceeded", true},
	{ErrorCancellationRequested, "request cancellation was requested", false},
	{ErrorInvalidBase64, "value is not canonical standard padded Base64", false},
	{ErrorInvalidUTF8, "value is not valid UTF-8", false},
	{ErrorInputTooLarge, "operation input exceeds the configured byte limit", false},
	{ErrorInvalidKey, "cryptographic key has an invalid length", false},
	{ErrorInvalidNonce, "AES-GCM nonce must be exactly 12 bytes", false},
	{ErrorAuthenticationFailed, "AES-GCM authentication failed", false},
	{ErrorInternal, "portable operation failed without a safe public detail", false},
}

func newABIError(code ErrorCode, field string) *ABIError {
	for _, definition := range errorCatalog {
		if definition.Code == code {
			return &ABIError{
				Code:      definition.Code,
				Message:   definition.Message,
				Retryable: definition.Retryable,
				Field:     field,
			}
		}
	}
	return &ABIError{Code: ErrorInternal, Message: "portable operation failed without a safe public detail"}
}

func errorDefinitions() []ErrorDefinition {
	definitions := make([]ErrorDefinition, len(errorCatalog))
	copy(definitions, errorCatalog)
	return definitions
}
