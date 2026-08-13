package portable

func manifestFor(limits Limits) Manifest {
	operations := []OperationDefinition{
		{Name: OperationNormalize, Capability: "portable.normalize"},
		{Name: OperationValidate, Capability: "portable.validate"},
		{Name: OperationSHA256, Capability: "crypto.sha256"},
		{Name: OperationHMACSHA256, Capability: "crypto.hmac-sha256"},
		{Name: OperationAESGCMEncrypt, Capability: "crypto.aes-gcm"},
		{Name: OperationAESGCMDecrypt, Capability: "crypto.aes-gcm"},
		{Name: OperationBase64Encode, Capability: "encoding.base64"},
		{Name: OperationBase64Decode, Capability: "encoding.base64"},
	}
	capabilities := []CapabilityDefinition{
		{Name: "portable.normalize", Version: "1", Operations: []Operation{OperationNormalize}},
		{Name: "portable.validate", Version: "1", Operations: []Operation{OperationValidate}},
		{Name: "crypto.sha256", Version: "1", Operations: []Operation{OperationSHA256}},
		{Name: "crypto.hmac-sha256", Version: "1", Operations: []Operation{OperationHMACSHA256}},
		{Name: "crypto.aes-gcm", Version: "1", Operations: []Operation{OperationAESGCMEncrypt, OperationAESGCMDecrypt}},
		{Name: "encoding.base64", Version: "1", Operations: []Operation{OperationBase64Encode, OperationBase64Decode}},
		{Name: "control.deadline", Version: "1", Host: true},
		{Name: "control.cancellation", Version: "1", Host: true},
	}
	return Manifest{
		Schema:  ManifestSchema,
		Package: PackageName,
		Version: PackageVersion,
		ABI:     ABIVersion,
		Encoding: EncodingDefinition{
			JSON:   "RFC 8259; UTF-8; unique object fields; unknown fields rejected",
			Binary: "RFC 4648 standard alphabet with required padding",
		},
		Limits:       limits,
		Operations:   operations,
		Capabilities: capabilities,
		Errors:       errorDefinitions(),
	}
}

func isKnownOperation(operation Operation) bool {
	switch operation {
	case OperationNormalize,
		OperationValidate,
		OperationSHA256,
		OperationHMACSHA256,
		OperationAESGCMEncrypt,
		OperationAESGCMDecrypt,
		OperationBase64Encode,
		OperationBase64Decode:
		return true
	default:
		return false
	}
}

func supportsCapability(capability string) bool {
	switch capability {
	case "portable.normalize",
		"portable.validate",
		"crypto.sha256",
		"crypto.hmac-sha256",
		"crypto.aes-gcm",
		"encoding.base64",
		"control.deadline",
		"control.cancellation":
		return true
	default:
		return false
	}
}
