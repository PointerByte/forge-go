package portable

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
)

var (
	benchmarkResultSink   any
	benchmarkResponseSink []byte
)

func BenchmarkNormalize(b *testing.B) {
	benchmarkOperation(b, OperationNormalize, []byte(`{"value":"  HELLO   portable world  ","trim":true,"collapse_whitespace":true,"lowercase_ascii":true}`), 24)
}

func BenchmarkValidate(b *testing.B) {
	benchmarkOperation(b, OperationValidate, []byte(`{"value":"portable-123","rules":{"required":true,"ascii":true,"forbid_control":true,"forbid_whitespace":true,"min_bytes":8,"max_bytes":64,"min_runes":8,"max_runes":64,"prefix":"portable-","suffix":"123"}}`), 12)
}

func BenchmarkSHA256(b *testing.B) {
	data := make([]byte, 1024)
	payload, _ := json.Marshal(sha256Payload{Data: base64.StdEncoding.EncodeToString(data)})
	benchmarkOperation(b, OperationSHA256, payload, int64(len(data)))
}

func BenchmarkHMACSHA256(b *testing.B) {
	data := make([]byte, 1024)
	key := make([]byte, 32)
	payload, _ := json.Marshal(hmacSHA256Payload{
		Key:  base64.StdEncoding.EncodeToString(key),
		Data: base64.StdEncoding.EncodeToString(data),
	})
	benchmarkOperation(b, OperationHMACSHA256, payload, int64(len(data)))
}

func BenchmarkAESGCMEncrypt(b *testing.B) {
	dispatcher := DefaultDispatcher()
	key := make([]byte, 32)
	nonce := make([]byte, aesGCMNonceBytes)
	plaintext := make([]byte, 1024)
	encodedKey := base64.StdEncoding.EncodeToString(key)
	encodedPlaintext := base64.StdEncoding.EncodeToString(plaintext)
	b.ReportAllocs()
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		binary.BigEndian.PutUint64(nonce[4:], uint64(index))
		payload, _ := json.Marshal(aesGCMEncryptPayload{
			Key:       encodedKey,
			Nonce:     base64.StdEncoding.EncodeToString(nonce),
			AAD:       "",
			Plaintext: encodedPlaintext,
		})
		result, err := dispatcher.execute(OperationAESGCMEncrypt, payload)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkResultSink = result
	}
}

func BenchmarkAESGCMDecrypt(b *testing.B) {
	dispatcher := DefaultDispatcher()
	encryptPayload := []byte(`{"key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","nonce":"AAAAAAAAAAAAAAAA","aad":"","plaintext":"AAAAAAAAAAAAAAAAAAAAAA=="}`)
	encrypted, err := dispatcher.aesGCMEncrypt(encryptPayload)
	if err != nil {
		b.Fatal(err)
	}
	ciphertext := encrypted.(aesGCMEncryptResult).Ciphertext
	decryptPayload, _ := json.Marshal(aesGCMDecryptPayload{
		Key:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Nonce:      "AAAAAAAAAAAAAAAA",
		AAD:        "",
		Ciphertext: ciphertext,
	})
	benchmarkOperation(b, OperationAESGCMDecrypt, decryptPayload, 16)
}

func BenchmarkBase64Encode(b *testing.B) {
	payload, _ := json.Marshal(base64EncodePayload{Text: string(make([]byte, 1024))})
	benchmarkOperation(b, OperationBase64Encode, payload, 1024)
}

func BenchmarkBase64Decode(b *testing.B) {
	payload, _ := json.Marshal(base64DecodePayload{Encoded: base64.StdEncoding.EncodeToString(make([]byte, 1024))})
	benchmarkOperation(b, OperationBase64Decode, payload, 1024)
}

func BenchmarkDispatchJSON(b *testing.B) {
	dispatcher := DefaultDispatcher()
	request := []byte(`{"abi":"goforge.abi.v1","id":"benchmark","operation":"crypto.sha256","payload":{"data":"YWJj"}}`)
	b.ReportAllocs()
	b.SetBytes(3)
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		benchmarkResponseSink = dispatcher.DispatchJSON(request, ExecutionState{})
	}
}

func benchmarkOperation(b *testing.B, operation Operation, payload []byte, processedBytes int64) {
	b.Helper()
	dispatcher := DefaultDispatcher()
	b.ReportAllocs()
	b.SetBytes(processedBytes)
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		result, err := dispatcher.execute(operation, payload)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkResultSink = result
	}
}
