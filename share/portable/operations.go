package portable

func (d *Dispatcher) execute(operation Operation, payload []byte) (any, *ABIError) {
	switch operation {
	case OperationNormalize:
		return d.normalize(payload)
	case OperationValidate:
		return d.validate(payload)
	case OperationSHA256:
		return d.sha256(payload)
	case OperationHMACSHA256:
		return d.hmacSHA256(payload)
	case OperationAESGCMEncrypt:
		return d.aesGCMEncrypt(payload)
	case OperationAESGCMDecrypt:
		return d.aesGCMDecrypt(payload)
	case OperationBase64Encode:
		return d.base64Encode(payload)
	case OperationBase64Decode:
		return d.base64Decode(payload)
	default:
		return nil, newABIError(ErrorUnknownOperation, "operation")
	}
}
