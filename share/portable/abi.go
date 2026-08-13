package portable

import "encoding/json"

const (
	// PackageName is the canonical Component Model package name.
	PackageName = "pointerbyte:goforge"
	// PackageVersion is the version of the portable contract package.
	PackageVersion = "0.1.0"
	// ABIVersion identifies the JSON bridge contract.
	ABIVersion = "goforge.abi.v1"
	// ManifestSchema identifies the manifest JSON schema family.
	ManifestSchema = "goforge.manifest.v1"
)

// Operation is a stable ABI operation identifier.
type Operation string

const (
	OperationNormalize     Operation = "text.normalize"
	OperationValidate      Operation = "text.validate"
	OperationSHA256        Operation = "crypto.sha256"
	OperationHMACSHA256    Operation = "crypto.hmac-sha256"
	OperationAESGCMEncrypt Operation = "crypto.aes-gcm.encrypt"
	OperationAESGCMDecrypt Operation = "crypto.aes-gcm.decrypt"
	OperationBase64Encode  Operation = "encoding.base64.encode"
	OperationBase64Decode  Operation = "encoding.base64.decode"
)

// Limits defines hard resource bounds enforced by a Dispatcher.
type Limits struct {
	MaxRequestBytes           int `json:"max_request_bytes"`
	MaxResponseBytes          int `json:"max_response_bytes"`
	MaxBinaryBytes            int `json:"max_binary_bytes"`
	MaxStringBytes            int `json:"max_string_bytes"`
	MaxIDBytes                int `json:"max_id_bytes"`
	MaxCancellationTokenBytes int `json:"max_cancellation_token_bytes"`
	MaxRequiredCapabilities   int `json:"max_required_capabilities"`
	MaxJSONDepth              int `json:"max_json_depth"`
}

// DefaultLimits returns the ABI v1 resource limits.
func DefaultLimits() Limits {
	return Limits{
		MaxRequestBytes:           1 << 20,
		MaxResponseBytes:          1 << 20,
		MaxBinaryBytes:            512 << 10,
		MaxStringBytes:            64 << 10,
		MaxIDBytes:                128,
		MaxCancellationTokenBytes: 256,
		MaxRequiredCapabilities:   32,
		MaxJSONDepth:              32,
	}
}

// EncodingDefinition describes the only serialization profile supported by
// ABI v1.
type EncodingDefinition struct {
	JSON   string `json:"json"`
	Binary string `json:"binary"`
}

// OperationDefinition connects an operation to its required capability.
type OperationDefinition struct {
	Name       Operation `json:"name"`
	Capability string    `json:"capability"`
}

// CapabilityDefinition describes a portable or host-control capability.
type CapabilityDefinition struct {
	Name       string      `json:"name"`
	Version    string      `json:"version"`
	Host       bool        `json:"host"`
	Operations []Operation `json:"operations,omitempty"`
}

// Manifest is the deterministic ABI v1 contract manifest.
type Manifest struct {
	Schema       string                 `json:"schema"`
	Package      string                 `json:"package"`
	Version      string                 `json:"version"`
	ABI          string                 `json:"abi"`
	Encoding     EncodingDefinition     `json:"encoding"`
	Limits       Limits                 `json:"limits"`
	Operations   []OperationDefinition  `json:"operations"`
	Capabilities []CapabilityDefinition `json:"capabilities"`
	Errors       []ErrorDefinition      `json:"errors"`
}

// Request is the strict ABI v1 request envelope.
type Request struct {
	ABI       string           `json:"abi"`
	ID        string           `json:"id"`
	Operation Operation        `json:"operation"`
	Metadata  *RequestMetadata `json:"metadata,omitempty"`
	Payload   json.RawMessage  `json:"payload"`
}

// RequestMetadata carries portable control metadata. The host supplies the
// corresponding checked state through ExecutionState.
type RequestMetadata struct {
	DeadlineUnixMilliseconds *int64   `json:"deadline_unix_ms,omitempty"`
	CancellationToken        string   `json:"cancellation_token,omitempty"`
	RequiredCapabilities     []string `json:"required_capabilities,omitempty"`
}

// ExecutionState is deterministic, host-observed state for one dispatch.
// ClockChecked and CancellationChecked prevent controls from being silently
// ignored. CancellationToken must equal the request token.
type ExecutionState struct {
	ClockChecked          bool
	NowUnixMilliseconds   int64
	CancellationChecked   bool
	CancellationToken     string
	CancellationRequested bool
}

// Response is the strict ABI v1 response envelope. Exactly one of Result and
// Error is populated.
type Response struct {
	ABI    string          `json:"abi"`
	ID     string          `json:"id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *ABIError       `json:"error,omitempty"`
}
