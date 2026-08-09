package portable

import (
	"encoding/json"
	"unicode"
	"unicode/utf8"
)

const (
	minimumResponseLimit = 512
	minimumBinaryLimit   = 32
)

// Dispatcher validates ABI envelopes, enforces execution controls and bounds,
// and invokes portable operations.
type Dispatcher struct {
	limits Limits
}

// NewDispatcher constructs a dispatcher with explicit resource limits.
func NewDispatcher(limits Limits) (*Dispatcher, *ABIError) {
	if limits.MaxRequestBytes <= 0 ||
		limits.MaxResponseBytes < minimumResponseLimit ||
		limits.MaxBinaryBytes < minimumBinaryLimit ||
		limits.MaxStringBytes <= 0 ||
		limits.MaxIDBytes <= 0 ||
		limits.MaxCancellationTokenBytes <= 0 ||
		limits.MaxRequiredCapabilities <= 0 ||
		limits.MaxJSONDepth <= 0 ||
		limits.MaxBinaryBytes > limits.MaxRequestBytes ||
		limits.MaxStringBytes > limits.MaxRequestBytes {
		return nil, newABIError(ErrorInvalidRequest, "limits")
	}
	return &Dispatcher{limits: limits}, nil
}

// DefaultDispatcher constructs an ABI v1 dispatcher with DefaultLimits.
func DefaultDispatcher() *Dispatcher {
	dispatcher, _ := NewDispatcher(DefaultLimits())
	return dispatcher
}

// Manifest returns a fresh deterministic manifest for the dispatcher.
func (d *Dispatcher) Manifest() Manifest {
	return manifestFor(d.limits)
}

// ManifestJSON returns the deterministic JSON encoding of Manifest.
func (d *Dispatcher) ManifestJSON() []byte {
	encoded, err := json.Marshal(d.Manifest())
	if err != nil {
		return nil
	}
	return encoded
}

// DispatchJSON decodes one strict request and always returns an ABI response.
// Malformed input receives an error response with an empty correlation ID.
func (d *Dispatcher) DispatchJSON(encoded []byte, state ExecutionState) []byte {
	if len(encoded) > d.limits.MaxRequestBytes {
		return d.encodeResponse(errorResponse("", newABIError(ErrorRequestTooLarge, "")))
	}

	var request Request
	if err := strictDecodeObject(encoded, &request, d.limits.MaxJSONDepth); err != nil {
		return d.encodeResponse(errorResponse("", err))
	}
	return d.encodeResponse(d.Dispatch(request, state))
}

// Dispatch validates and executes one already-decoded request.
func (d *Dispatcher) Dispatch(request Request, state ExecutionState) Response {
	responseID := safeResponseID(request.ID, d.limits.MaxIDBytes)
	if err := d.validateRequest(request, state); err != nil {
		return errorResponse(responseID, err)
	}

	result, err := d.execute(request.Operation, request.Payload)
	if err != nil {
		return errorResponse(responseID, err)
	}
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return errorResponse(responseID, newABIError(ErrorInternal, ""))
	}
	return Response{ABI: ABIVersion, ID: responseID, OK: true, Result: encoded}
}

func (d *Dispatcher) validateRequest(request Request, state ExecutionState) *ABIError {
	if request.ABI != ABIVersion {
		return newABIError(ErrorInvalidABI, "abi")
	}
	if err := validateIdentifier(request.ID, d.limits.MaxIDBytes); err != nil {
		return err
	}
	if !isKnownOperation(request.Operation) {
		return newABIError(ErrorUnknownOperation, "operation")
	}
	if len(request.Payload) == 0 {
		return newABIError(ErrorInvalidRequest, "payload")
	}
	if request.Metadata == nil {
		return nil
	}

	metadata := request.Metadata
	if len(metadata.RequiredCapabilities) > d.limits.MaxRequiredCapabilities {
		return newABIError(ErrorInputTooLarge, "metadata.required_capabilities")
	}
	seen := make(map[string]struct{}, len(metadata.RequiredCapabilities))
	for _, capability := range metadata.RequiredCapabilities {
		if validateCapabilityName(capability) != nil {
			return newABIError(ErrorInvalidRequest, "metadata.required_capabilities")
		}
		if _, duplicate := seen[capability]; duplicate {
			return newABIError(ErrorInvalidRequest, "metadata.required_capabilities")
		}
		seen[capability] = struct{}{}
		if !supportsCapability(capability) {
			return newABIError(ErrorCapabilityUnavailable, "metadata.required_capabilities")
		}
	}

	if metadata.DeadlineUnixMilliseconds != nil {
		if *metadata.DeadlineUnixMilliseconds <= 0 {
			return newABIError(ErrorInvalidRequest, "metadata.deadline_unix_ms")
		}
		if !state.ClockChecked {
			return newABIError(ErrorExecutionStateRequired, "metadata.deadline_unix_ms")
		}
		if state.NowUnixMilliseconds >= *metadata.DeadlineUnixMilliseconds {
			return newABIError(ErrorDeadlineExceeded, "metadata.deadline_unix_ms")
		}
	}

	if metadata.CancellationToken != "" {
		if validateToken(metadata.CancellationToken, d.limits.MaxCancellationTokenBytes) != nil {
			return newABIError(ErrorInvalidRequest, "metadata.cancellation_token")
		}
		if !state.CancellationChecked || state.CancellationToken != metadata.CancellationToken {
			return newABIError(ErrorExecutionStateRequired, "metadata.cancellation_token")
		}
		if state.CancellationRequested {
			return newABIError(ErrorCancellationRequested, "metadata.cancellation_token")
		}
	}
	return nil
}

func (d *Dispatcher) encodeResponse(response Response) []byte {
	encoded, err := json.Marshal(response)
	if err == nil && len(encoded) <= d.limits.MaxResponseBytes {
		return encoded
	}

	fallback := errorResponse("", newABIError(ErrorResponseTooLarge, ""))
	encoded, err = json.Marshal(fallback)
	if err != nil || len(encoded) > d.limits.MaxResponseBytes {
		return []byte(`{"abi":"goforge.abi.v1","id":"","ok":false,"error":{"code":"internal","message":"portable operation failed without a safe public detail","retryable":false}}`)
	}
	return encoded
}

func errorResponse(id string, err *ABIError) Response {
	return Response{ABI: ABIVersion, ID: id, OK: false, Error: err}
}

func safeResponseID(id string, max int) string {
	if validateIdentifier(id, max) != nil {
		return ""
	}
	return id
}

func validateIdentifier(value string, max int) *ABIError {
	if value == "" || len(value) > max || !utf8.ValidString(value) {
		return newABIError(ErrorInvalidRequest, "id")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return newABIError(ErrorInvalidRequest, "id")
		}
	}
	return nil
}

func validateToken(value string, max int) *ABIError {
	if value == "" || len(value) > max || !utf8.ValidString(value) {
		return newABIError(ErrorInvalidRequest, "metadata.cancellation_token")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return newABIError(ErrorInvalidRequest, "metadata.cancellation_token")
		}
	}
	return nil
}

func validateCapabilityName(value string) *ABIError {
	if value == "" || len(value) > 128 {
		return newABIError(ErrorInvalidRequest, "metadata.required_capabilities")
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') &&
			!(character >= '0' && character <= '9') &&
			character != '.' && character != '-' {
			return newABIError(ErrorInvalidRequest, "metadata.required_capabilities")
		}
	}
	return nil
}
