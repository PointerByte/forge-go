package portable

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
)

const (
	aesGCMNonceBytes    = 12
	aesGCMTagBytes      = 16
	minimumHMACKeyBytes = 16
)

type sha256Payload struct {
	Data string `json:"data"`
}

type sha256Result struct {
	Digest string `json:"digest"`
}

func (d *Dispatcher) sha256(payload []byte) (any, *ABIError) {
	var input sha256Payload
	if err := strictDecodeObject(payload, &input, d.limits.MaxJSONDepth); err != nil {
		return nil, err
	}
	if err := requireJSONFields(payload, "data"); err != nil {
		return nil, err
	}
	data, err := decodeBinary(input.Data, "payload.data", d.limits.MaxBinaryBytes)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(data)
	digest := sha256.Sum256(data)
	return sha256Result{Digest: encodeBinary(digest[:])}, nil
}

type hmacSHA256Payload struct {
	Key  string `json:"key"`
	Data string `json:"data"`
}

type hmacSHA256Result struct {
	MAC string `json:"mac"`
}

func (d *Dispatcher) hmacSHA256(payload []byte) (any, *ABIError) {
	var input hmacSHA256Payload
	if err := strictDecodeObject(payload, &input, d.limits.MaxJSONDepth); err != nil {
		return nil, err
	}
	if err := requireJSONFields(payload, "key", "data"); err != nil {
		return nil, err
	}
	key, err := decodeBinary(input.Key, "payload.key", d.limits.MaxBinaryBytes)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	if len(key) < minimumHMACKeyBytes {
		return nil, newABIError(ErrorInvalidKey, "payload.key")
	}
	data, err := decodeBinary(input.Data, "payload.data", d.limits.MaxBinaryBytes)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(data)

	calculator := hmac.New(sha256.New, key)
	_, _ = calculator.Write(data)
	return hmacSHA256Result{MAC: encodeBinary(calculator.Sum(nil))}, nil
}

type aesGCMEncryptPayload struct {
	Key       string `json:"key"`
	Nonce     string `json:"nonce"`
	AAD       string `json:"aad"`
	Plaintext string `json:"plaintext"`
}

type aesGCMEncryptResult struct {
	Ciphertext string `json:"ciphertext"`
}

func (d *Dispatcher) aesGCMEncrypt(payload []byte) (any, *ABIError) {
	var input aesGCMEncryptPayload
	if err := strictDecodeObject(payload, &input, d.limits.MaxJSONDepth); err != nil {
		return nil, err
	}
	if err := requireJSONFields(payload, "key", "nonce", "aad", "plaintext"); err != nil {
		return nil, err
	}
	key, nonce, aad, plaintext, err := d.decodeAESInputs(
		input.Key,
		input.Nonce,
		input.AAD,
		input.Plaintext,
		false,
	)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	defer zeroBytes(nonce)
	defer zeroBytes(aad)
	defer zeroBytes(plaintext)

	aead, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	defer zeroBytes(ciphertext)
	return aesGCMEncryptResult{Ciphertext: encodeBinary(ciphertext)}, nil
}

type aesGCMDecryptPayload struct {
	Key        string `json:"key"`
	Nonce      string `json:"nonce"`
	AAD        string `json:"aad"`
	Ciphertext string `json:"ciphertext"`
}

type aesGCMDecryptResult struct {
	Plaintext string `json:"plaintext"`
}

func (d *Dispatcher) aesGCMDecrypt(payload []byte) (any, *ABIError) {
	var input aesGCMDecryptPayload
	if err := strictDecodeObject(payload, &input, d.limits.MaxJSONDepth); err != nil {
		return nil, err
	}
	if err := requireJSONFields(payload, "key", "nonce", "aad", "ciphertext"); err != nil {
		return nil, err
	}
	key, nonce, aad, ciphertext, err := d.decodeAESInputs(
		input.Key,
		input.Nonce,
		input.AAD,
		input.Ciphertext,
		true,
	)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	defer zeroBytes(nonce)
	defer zeroBytes(aad)
	defer zeroBytes(ciphertext)

	aead, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}
	plaintext, openErr := aead.Open(nil, nonce, ciphertext, aad)
	if openErr != nil {
		return nil, newABIError(ErrorAuthenticationFailed, "payload.ciphertext")
	}
	defer zeroBytes(plaintext)
	return aesGCMDecryptResult{Plaintext: encodeBinary(plaintext)}, nil
}

func (d *Dispatcher) decodeAESInputs(
	encodedKey string,
	encodedNonce string,
	encodedAAD string,
	encodedValue string,
	decrypt bool,
) ([]byte, []byte, []byte, []byte, *ABIError) {
	key, err := decodeBinary(encodedKey, "payload.key", d.limits.MaxBinaryBytes)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		zeroBytes(key)
		return nil, nil, nil, nil, newABIError(ErrorInvalidKey, "payload.key")
	}

	nonce, err := decodeBinary(encodedNonce, "payload.nonce", d.limits.MaxBinaryBytes)
	if err != nil {
		zeroBytes(key)
		return nil, nil, nil, nil, err
	}
	if len(nonce) != aesGCMNonceBytes {
		zeroBytes(key)
		zeroBytes(nonce)
		return nil, nil, nil, nil, newABIError(ErrorInvalidNonce, "payload.nonce")
	}

	aad, err := decodeBinary(encodedAAD, "payload.aad", d.limits.MaxBinaryBytes)
	if err != nil {
		zeroBytes(key)
		zeroBytes(nonce)
		return nil, nil, nil, nil, err
	}
	valueLimit := d.limits.MaxBinaryBytes
	if !decrypt {
		valueLimit -= aesGCMTagBytes
		if valueLimit < 0 {
			valueLimit = 0
		}
	}
	field := "payload.plaintext"
	if decrypt {
		field = "payload.ciphertext"
	}
	value, err := decodeBinary(encodedValue, field, valueLimit)
	if err != nil {
		zeroBytes(key)
		zeroBytes(nonce)
		zeroBytes(aad)
		return nil, nil, nil, nil, err
	}
	if decrypt && len(value) < aesGCMTagBytes {
		zeroBytes(key)
		zeroBytes(nonce)
		zeroBytes(aad)
		zeroBytes(value)
		return nil, nil, nil, nil, newABIError(ErrorAuthenticationFailed, field)
	}
	return key, nonce, aad, value, nil
}

func newAESGCM(key []byte) (cipher.AEAD, *ABIError) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, newABIError(ErrorInvalidKey, "payload.key")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, newABIError(ErrorInternal, "")
	}
	return aead, nil
}
