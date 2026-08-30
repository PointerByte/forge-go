// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package pkcs11

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// uriScheme is the RFC 7512 scheme prefix. It is the discriminator the
// repository uses to tell a token reference from local key material, which
// makes the decision exact rather than heuristic.
const uriScheme = "pkcs11:"

// objectClass is a PKCS#11 CKO_ object class.
type objectClass uint64

const (
	classData        objectClass = 0x00000000
	classCertificate objectClass = 0x00000001
	classPublicKey   objectClass = 0x00000002
	classPrivateKey  objectClass = 0x00000003
	classSecretKey   objectClass = 0x00000004
)

// keyURI is a parsed RFC 7512 "pkcs11:" URI. Only the path attributes the
// package acts on are modelled; query attributes (pin-source and friends) are
// deliberately ignored because the PIN is supplied through a PinProvider.
type keyURI struct {
	// Token is the CKA_LABEL of the token ("token" attribute).
	Token string
	// Object is the CKA_LABEL of the key object ("object" attribute).
	Object string
	// ID is the raw CKA_ID bytes ("id" attribute, percent-decoded).
	ID []byte
	// Class is the object class implied by the "type" attribute.
	Class objectClass
	// HasClass reports whether "type" was present.
	HasClass bool
}

// isKeyURI reports whether reference is a PKCS#11 URI. Callers use it to route
// between the token and the local implementation.
func isKeyURI(reference string) bool {
	return strings.HasPrefix(strings.TrimSpace(reference), uriScheme)
}

// classFromType maps the RFC 7512 "type" attribute to a CKO_ class.
func classFromType(value string) (objectClass, error) {
	switch value {
	case "private":
		return classPrivateKey, nil
	case "public":
		return classPublicKey, nil
	case "secret-key":
		return classSecretKey, nil
	case "cert":
		return classCertificate, nil
	case "data":
		return classData, nil
	default:
		return 0, fmt.Errorf("pkcs11: unsupported object type %q in key uri", value)
	}
}

// typeFromClass is the inverse of classFromType, used when formatting a URI.
func typeFromClass(class objectClass) (string, error) {
	switch class {
	case classPrivateKey:
		return "private", nil
	case classPublicKey:
		return "public", nil
	case classSecretKey:
		return "secret-key", nil
	case classCertificate:
		return "cert", nil
	case classData:
		return "data", nil
	default:
		return "", fmt.Errorf("pkcs11: unsupported object class %d", uint64(class))
	}
}

// parseKeyURI parses an RFC 7512 "pkcs11:" URI. Attributes are separated by
// ";" and percent-encoded, so a CKA_ID holding arbitrary bytes round-trips.
func parseKeyURI(reference string) (*keyURI, error) {
	trimmed := strings.TrimSpace(reference)
	if !isKeyURI(trimmed) {
		return nil, fmt.Errorf("pkcs11: %q is not a pkcs11 uri", trimmed)
	}

	body := strings.TrimPrefix(trimmed, uriScheme)
	// RFC 7512 separates the path component from the query component with "?".
	query := ""
	if index := strings.IndexByte(body, '?'); index >= 0 {
		query = body[index+1:]
		body = body[:index]
	}
	if err := rejectPinAttributes(query); err != nil {
		return nil, err
	}

	parsed := &keyURI{}
	if body == "" {
		return nil, fmt.Errorf("pkcs11: key uri %q has no attributes", trimmed)
	}

	for _, segment := range strings.Split(body, ";") {
		if segment == "" {
			continue
		}
		name, rawValue, found := strings.Cut(segment, "=")
		if !found {
			return nil, fmt.Errorf("pkcs11: malformed attribute %q in key uri", segment)
		}
		value, err := url.PathUnescape(rawValue)
		if err != nil {
			return nil, fmt.Errorf("pkcs11: decode attribute %q in key uri: %w", name, err)
		}

		switch name {
		case "token":
			parsed.Token = value
		case "object":
			parsed.Object = value
		case "id":
			parsed.ID = []byte(value)
		case "type":
			class, err := classFromType(value)
			if err != nil {
				return nil, err
			}
			parsed.Class = class
			parsed.HasClass = true
		default:
			// Unknown attributes (model, manufacturer, serial, library-*) are
			// accepted and ignored so a vendor-supplied URI still parses.
		}
	}

	if parsed.Object == "" && len(parsed.ID) == 0 {
		return nil, fmt.Errorf("pkcs11: key uri %q must set object or id", trimmed)
	}
	return parsed, nil
}

// rejectPinAttributes refuses a URI that tries to carry the token PIN. RFC 7512
// allows "pin-value" and "pin-source" as query attributes, but honouring them
// would put the PIN in configuration, in logs, and in every KeyRef this package
// returns. The PIN comes from a PinProvider and from nowhere else.
func rejectPinAttributes(query string) error {
	if query == "" {
		return nil
	}
	for _, segment := range strings.Split(query, "&") {
		name, _, _ := strings.Cut(segment, "=")
		switch name {
		case "pin-value", "pin-source":
			return fmt.Errorf("pkcs11: key uri must not carry %q; supply the pin with WithPinProvider", name)
		}
	}
	return nil
}

// String formats the URI back to its RFC 7512 form. Attribute order is fixed
// so the value is stable and comparable across calls.
func (u *keyURI) String() string {
	var builder strings.Builder
	builder.WriteString(uriScheme)

	first := true
	appendAttribute := func(name, value string) {
		if !first {
			builder.WriteByte(';')
		}
		first = false
		builder.WriteString(name)
		builder.WriteByte('=')
		builder.WriteString(escapeAttribute(value))
	}

	if u.Token != "" {
		appendAttribute("token", u.Token)
	}
	if u.Object != "" {
		appendAttribute("object", u.Object)
	}
	if len(u.ID) > 0 {
		appendAttribute("id", string(u.ID))
	}
	if u.HasClass {
		if name, err := typeFromClass(u.Class); err == nil {
			appendAttribute("type", name)
		}
	}
	return builder.String()
}

// hexID renders CKA_ID as lowercase hexadecimal for KeyData.KeyID.
func (u *keyURI) hexID() string {
	return hex.EncodeToString(u.ID)
}

// unreservedAttributeByte reports whether b can appear literally in an
// attribute value. RFC 7512 builds on RFC 3986 unreserved characters plus the
// path-safe subset that does not collide with the ";" and "=" separators.
func unreservedAttributeByte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	case b == '-', b == '.', b == '_', b == '~':
		return true
	case b == ':', b == '[', b == ']', b == '@', b == '!', b == '$',
		b == '\'', b == '(', b == ')', b == '*', b == '+', b == ',':
		return true
	default:
		return false
	}
}

// escapeAttribute percent-encodes every byte that is not attribute-safe, so
// binary CKA_ID values survive a String/parse round trip.
func escapeAttribute(value string) string {
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		b := value[index]
		if unreservedAttributeByte(b) {
			builder.WriteByte(b)
			continue
		}
		builder.WriteByte('%')
		builder.WriteString(strings.ToUpper(hex.EncodeToString([]byte{b})))
	}
	return builder.String()
}
