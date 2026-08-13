package portable

import (
	"encoding/base64"
	"unicode/utf8"
)

func decodeBinary(encoded, field string, maxBytes int) ([]byte, *ABIError) {
	if len(encoded) > base64.StdEncoding.EncodedLen(maxBytes) {
		return nil, newABIError(ErrorInputTooLarge, field)
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return nil, newABIError(ErrorInvalidBase64, field)
	}
	if len(decoded) > maxBytes {
		zeroBytes(decoded)
		return nil, newABIError(ErrorInputTooLarge, field)
	}
	return decoded, nil
}

func encodeBinary(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

type base64EncodePayload struct {
	Text string `json:"text"`
}

type base64EncodeResult struct {
	Encoded string `json:"encoded"`
}

func (d *Dispatcher) base64Encode(payload []byte) (any, *ABIError) {
	var input base64EncodePayload
	if err := strictDecodeObject(payload, &input, d.limits.MaxJSONDepth); err != nil {
		return nil, err
	}
	if err := requireJSONFields(payload, "text"); err != nil {
		return nil, err
	}
	if !utf8.ValidString(input.Text) {
		return nil, newABIError(ErrorInvalidUTF8, "payload.text")
	}
	if len(input.Text) > d.limits.MaxStringBytes {
		return nil, newABIError(ErrorInputTooLarge, "payload.text")
	}
	return base64EncodeResult{Encoded: encodeBinary([]byte(input.Text))}, nil
}

type base64DecodePayload struct {
	Encoded string `json:"encoded"`
}

type base64DecodeResult struct {
	Text string `json:"text"`
}

func (d *Dispatcher) base64Decode(payload []byte) (any, *ABIError) {
	var input base64DecodePayload
	if err := strictDecodeObject(payload, &input, d.limits.MaxJSONDepth); err != nil {
		return nil, err
	}
	if err := requireJSONFields(payload, "encoded"); err != nil {
		return nil, err
	}
	decoded, err := decodeBinary(input.Encoded, "payload.encoded", d.limits.MaxStringBytes)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(decoded)
	if !utf8.Valid(decoded) {
		return nil, newABIError(ErrorInvalidUTF8, "payload.encoded")
	}
	return base64DecodeResult{Text: string(decoded)}, nil
}
