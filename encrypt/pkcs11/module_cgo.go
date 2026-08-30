// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build pkcs11 && cgo && !windows

package pkcs11

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include "cryptoki.h"

// forge_get_function_list resolves and calls C_GetFunctionList through the
// loaded library. Calling a function pointer from Go is not possible, so the
// indirection lives here.
static CK_RV forge_get_function_list(void *handle, CK_FUNCTION_LIST **list) {
  CK_C_GetFunctionList entry = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  if (entry == NULL) {
    return 0x00000005; // CKR_GENERAL_ERROR
  }
  return entry(list);
}

// The remaining wrappers exist for the same reason: each dereferences a
// function pointer out of the table, which cgo cannot do from Go.
static CK_RV forge_initialize(CK_FUNCTION_LIST *fl) {
  CK_C_INITIALIZE_ARGS args;
  memset(&args, 0, sizeof(args));
  // CKF_OS_LOCKING_OK is mandatory here: without it the module is told the
  // application is single-threaded and may skip internal locking.
  args.flags = CKF_OS_LOCKING_OK;
  return fl->C_Initialize(&args);
}

static CK_RV forge_finalize(CK_FUNCTION_LIST *fl) { return fl->C_Finalize(NULL); }

static CK_RV forge_get_slot_list(CK_FUNCTION_LIST *fl, CK_BBOOL present, CK_SLOT_ID_PTR slots, CK_ULONG_PTR count) {
  return fl->C_GetSlotList(present, slots, count);
}

static CK_RV forge_get_token_info(CK_FUNCTION_LIST *fl, CK_SLOT_ID slot, CK_TOKEN_INFO *info) {
  return fl->C_GetTokenInfo(slot, info);
}

static CK_RV forge_get_mechanism_list(CK_FUNCTION_LIST *fl, CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
  return fl->C_GetMechanismList(slot, list, count);
}

static CK_RV forge_open_session(CK_FUNCTION_LIST *fl, CK_SLOT_ID slot, CK_SESSION_HANDLE *session) {
  return fl->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, session);
}

static CK_RV forge_close_session(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session) {
  return fl->C_CloseSession(session);
}

static CK_RV forge_login(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR pin, CK_ULONG len) {
  return fl->C_Login(session, CKU_USER, pin, len);
}

static CK_RV forge_logout(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session) { return fl->C_Logout(session); }

static CK_RV forge_find_objects(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR tmpl,
                                CK_ULONG count, CK_OBJECT_HANDLE_PTR found, CK_ULONG max, CK_ULONG_PTR actual) {
  CK_RV rv = fl->C_FindObjectsInit(session, tmpl, count);
  if (rv != CKR_OK) {
    return rv;
  }
  rv = fl->C_FindObjects(session, found, max, actual);
  CK_RV final = fl->C_FindObjectsFinal(session);
  return rv != CKR_OK ? rv : final;
}

static CK_RV forge_get_attribute_value(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                                       CK_ATTRIBUTE_PTR tmpl, CK_ULONG count) {
  return fl->C_GetAttributeValue(session, object, tmpl, count);
}

static CK_RV forge_set_attribute_value(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                                       CK_ATTRIBUTE_PTR tmpl, CK_ULONG count) {
  return fl->C_SetAttributeValue(session, object, tmpl, count);
}

static CK_RV forge_destroy_object(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object) {
  return fl->C_DestroyObject(session, object);
}

static CK_RV forge_generate_key(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech,
                                CK_ATTRIBUTE_PTR tmpl, CK_ULONG count, CK_OBJECT_HANDLE_PTR key) {
  return fl->C_GenerateKey(session, mech, tmpl, count, key);
}

static CK_RV forge_generate_key_pair(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech,
                                     CK_ATTRIBUTE_PTR pub, CK_ULONG pubCount, CK_ATTRIBUTE_PTR priv,
                                     CK_ULONG privCount, CK_OBJECT_HANDLE_PTR pubKey, CK_OBJECT_HANDLE_PTR privKey) {
  return fl->C_GenerateKeyPair(session, mech, pub, pubCount, priv, privCount, pubKey, privKey);
}

static CK_RV forge_derive_key(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech,
                              CK_OBJECT_HANDLE base, CK_ATTRIBUTE_PTR tmpl, CK_ULONG count, CK_OBJECT_HANDLE_PTR key) {
  return fl->C_DeriveKey(session, mech, base, tmpl, count, key);
}

// Init and the operation are separate because the two-call size-then-fill
// convention issues the operation twice. Re-running C_XxxInit before the second
// call fails with CKR_OPERATION_ACTIVE, since the sizing call leaves the
// operation open by design.
static CK_RV forge_encrypt_init(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech,
                                CK_OBJECT_HANDLE key) {
  return fl->C_EncryptInit(session, mech, key);
}

static CK_RV forge_encrypt(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session, CK_BYTE_PTR in, CK_ULONG inLen,
                           CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
  return fl->C_Encrypt(session, in, inLen, out, outLen);
}

static CK_RV forge_decrypt_init(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech,
                                CK_OBJECT_HANDLE key) {
  return fl->C_DecryptInit(session, mech, key);
}

static CK_RV forge_decrypt(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session, CK_BYTE_PTR in, CK_ULONG inLen,
                           CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
  return fl->C_Decrypt(session, in, inLen, out, outLen);
}

static CK_RV forge_sign_init(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech,
                             CK_OBJECT_HANDLE key) {
  return fl->C_SignInit(session, mech, key);
}

static CK_RV forge_sign(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session, CK_BYTE_PTR in, CK_ULONG inLen,
                        CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
  return fl->C_Sign(session, in, inLen, out, outLen);
}

static CK_RV forge_verify(CK_FUNCTION_LIST *fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech,
                          CK_OBJECT_HANDLE key, CK_BYTE_PTR in, CK_ULONG inLen, CK_BYTE_PTR sig, CK_ULONG sigLen) {
  CK_RV rv = fl->C_VerifyInit(session, mech, key);
  if (rv != CKR_OK) {
    return rv;
  }
  return fl->C_Verify(session, in, inLen, sig, sigLen);
}

// Accessors for the attribute array, which Go cannot index as a C array of
// structs without unsafe arithmetic.
static CK_ATTRIBUTE_PTR forge_attr_at(CK_ATTRIBUTE_PTR base, int index) { return &base[index]; }
static void forge_attr_set(CK_ATTRIBUTE_PTR attr, CK_ATTRIBUTE_TYPE type, CK_VOID_PTR value, CK_ULONG len) {
  attr->type = type;
  attr->pValue = value;
  attr->ulValueLen = len;
}
static CK_ULONG forge_attr_len(CK_ATTRIBUTE_PTR attr) { return attr->ulValueLen; }
static CK_VOID_PTR forge_attr_value(CK_ATTRIBUTE_PTR attr) { return attr->pValue; }
static int forge_attr_unavailable(CK_ATTRIBUTE_PTR attr) {
  return attr->ulValueLen == CK_UNAVAILABLE_INFORMATION;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// cgoModule is the real PKCS#11 binding. Every C type, every allocation, and
// the two-call size-then-fill convention is confined to this file; everything
// above the module interface is pure Go.
type cgoModule struct {
	handle unsafe.Pointer
	list   *C.CK_FUNCTION_LIST
}

// newModule loads a vendor PKCS#11 library and resolves its function table.
func newModule(path string) (module, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	// RTLD_NOW surfaces missing symbols at load time rather than on the first
	// call inside a cryptographic operation.
	handle := C.dlopen(cPath, C.RTLD_NOW)
	if handle == nil {
		return nil, fmt.Errorf("pkcs11: dlopen %q: %s", path, C.GoString(C.dlerror()))
	}

	var list *C.CK_FUNCTION_LIST
	if rv := C.forge_get_function_list(handle, &list); rv != C.CKR_OK {
		C.dlclose(handle)
		return nil, newTokenError("C_GetFunctionList", returnValue(rv))
	}
	if list == nil {
		C.dlclose(handle)
		return nil, fmt.Errorf("pkcs11: %q returned a nil function list", path)
	}
	if major := uint8(list.version.major); major != 2 && major != 3 {
		C.dlclose(handle)
		return nil, fmt.Errorf("pkcs11: %q reports unsupported Cryptoki version %d.%d",
			path, major, uint8(list.version.minor))
	}

	return &cgoModule{handle: handle, list: list}, nil
}

func (m *cgoModule) Initialize() error {
	rv := returnValue(C.forge_initialize(m.list))
	// Another consumer in this process may already have initialized the
	// library, which is success as far as this package is concerned.
	if rv == ckrCryptokiAlreadyInit {
		return nil
	}
	return newTokenError("C_Initialize", rv)
}

// Finalize releases the library's state but deliberately does not dlclose it.
// Several vendor modules leave background threads or atexit handlers behind and
// crash when unloaded, so the mapping stays for the life of the process.
func (m *cgoModule) Finalize() error {
	return newTokenError("C_Finalize", returnValue(C.forge_finalize(m.list)))
}

func (m *cgoModule) Slots(tokenPresent bool) ([]slotInfo, error) {
	present := C.CK_BBOOL(C.CK_FALSE)
	if tokenPresent {
		present = C.CK_BBOOL(C.CK_TRUE)
	}

	var count C.CK_ULONG
	if rv := C.forge_get_slot_list(m.list, present, nil, &count); rv != C.CKR_OK {
		return nil, newTokenError("C_GetSlotList", returnValue(rv))
	}
	if count == 0 {
		return nil, nil
	}

	ids := (*C.CK_SLOT_ID)(C.malloc(C.size_t(count) * C.size_t(unsafe.Sizeof(C.CK_SLOT_ID(0)))))
	defer C.free(unsafe.Pointer(ids))

	if rv := C.forge_get_slot_list(m.list, present, ids, &count); rv != C.CKR_OK {
		return nil, newTokenError("C_GetSlotList", returnValue(rv))
	}

	slice := unsafe.Slice(ids, int(count))
	slots := make([]slotInfo, 0, int(count))
	for _, id := range slice {
		info := slotInfo{ID: uint64(id), TokenPresent: tokenPresent}

		var token C.CK_TOKEN_INFO
		if rv := C.forge_get_token_info(m.list, id, &token); rv == C.CKR_OK {
			info.TokenLabel = trimTokenField(C.GoBytes(unsafe.Pointer(&token.label[0]), C.int(len(token.label))))
			if token.ulMaxSessionCount != C.CK_EFFECTIVELY_INFINITE {
				info.MaxSessions = uint64(token.ulMaxSessionCount)
			}
			info.TokenPresent = true
		}
		slots = append(slots, info)
	}
	return slots, nil
}

// trimTokenField strips the trailing spaces PKCS#11 pads fixed-width fields
// with.
func trimTokenField(raw []byte) string {
	end := len(raw)
	for end > 0 && (raw[end-1] == ' ' || raw[end-1] == 0) {
		end--
	}
	return string(raw[:end])
}

func (m *cgoModule) Mechanisms(slot uint64) ([]mechanism, error) {
	var count C.CK_ULONG
	if rv := C.forge_get_mechanism_list(m.list, C.CK_SLOT_ID(slot), nil, &count); rv != C.CKR_OK {
		return nil, newTokenError("C_GetMechanismList", returnValue(rv))
	}
	if count == 0 {
		return nil, nil
	}

	buffer := (*C.CK_MECHANISM_TYPE)(C.malloc(C.size_t(count) * C.size_t(unsafe.Sizeof(C.CK_MECHANISM_TYPE(0)))))
	defer C.free(unsafe.Pointer(buffer))

	if rv := C.forge_get_mechanism_list(m.list, C.CK_SLOT_ID(slot), buffer, &count); rv != C.CKR_OK {
		return nil, newTokenError("C_GetMechanismList", returnValue(rv))
	}

	slice := unsafe.Slice(buffer, int(count))
	mechanisms := make([]mechanism, 0, int(count))
	for _, value := range slice {
		mechanisms = append(mechanisms, mechanism(value))
	}
	return mechanisms, nil
}

func (m *cgoModule) OpenSession(slot uint64) (sessionHandle, error) {
	var session C.CK_SESSION_HANDLE
	if rv := C.forge_open_session(m.list, C.CK_SLOT_ID(slot), &session); rv != C.CKR_OK {
		return 0, newTokenError("C_OpenSession", returnValue(rv))
	}
	return sessionHandle(session), nil
}

func (m *cgoModule) CloseSession(session sessionHandle) error {
	return newTokenError("C_CloseSession", returnValue(C.forge_close_session(m.list, C.CK_SESSION_HANDLE(session))))
}

// Login authenticates the user. The PIN is copied into C memory and wiped as
// soon as the call returns, so it never lingers in a Go string the collector
// might move or keep alive.
func (m *cgoModule) Login(session sessionHandle, pin string) error {
	raw := []byte(pin)
	buffer := C.CBytes(raw)
	defer func() {
		C.memset(buffer, 0, C.size_t(len(raw)))
		C.free(buffer)
	}()
	clear(raw)

	rv := returnValue(C.forge_login(m.list, C.CK_SESSION_HANDLE(session),
		(C.CK_UTF8CHAR_PTR)(buffer), C.CK_ULONG(len(pin))))
	if rv == ckrUserAlreadyLoggedIn {
		return nil
	}
	return newTokenError("C_Login", rv)
}

func (m *cgoModule) Logout(session sessionHandle) error {
	return newTokenError("C_Logout", returnValue(C.forge_logout(m.list, C.CK_SESSION_HANDLE(session))))
}

// cTemplate is a CK_ATTRIBUTE array allocated in C memory.
//
// The values must be C-allocated too: a CK_ATTRIBUTE.pValue pointing into a Go
// slice would store a Go pointer in C-visible memory, which violates the cgo
// pointer rules and is caught by GODEBUG=cgocheck=2.
type cTemplate struct {
	base  C.CK_ATTRIBUTE_PTR
	count C.CK_ULONG
	freed []unsafe.Pointer
}

func newCTemplate(attributes []attribute) *cTemplate {
	if len(attributes) == 0 {
		return &cTemplate{}
	}

	base := (C.CK_ATTRIBUTE_PTR)(C.calloc(C.size_t(len(attributes)), C.size_t(unsafe.Sizeof(C.CK_ATTRIBUTE{}))))
	template := &cTemplate{base: base, count: C.CK_ULONG(len(attributes))}

	for index, attr := range attributes {
		slot := C.forge_attr_at(base, C.int(index))
		if len(attr.Value) == 0 {
			C.forge_attr_set(slot, C.CK_ATTRIBUTE_TYPE(attr.Type), nil, 0)
			continue
		}
		value := C.CBytes(attr.Value)
		template.freed = append(template.freed, value)
		C.forge_attr_set(slot, C.CK_ATTRIBUTE_TYPE(attr.Type), C.CK_VOID_PTR(value), C.CK_ULONG(len(attr.Value)))
	}
	return template
}

func (t *cTemplate) free() {
	for _, pointer := range t.freed {
		C.free(pointer)
	}
	if t.base != nil {
		C.free(unsafe.Pointer(t.base))
	}
}

func (m *cgoModule) FindObjects(session sessionHandle, template []attribute) ([]objectHandle, error) {
	cTmpl := newCTemplate(template)
	defer cTmpl.free()

	const maxObjects = 64
	found := (*C.CK_OBJECT_HANDLE)(C.malloc(maxObjects * C.size_t(unsafe.Sizeof(C.CK_OBJECT_HANDLE(0)))))
	defer C.free(unsafe.Pointer(found))

	var actual C.CK_ULONG
	rv := C.forge_find_objects(m.list, C.CK_SESSION_HANDLE(session), cTmpl.base, cTmpl.count,
		found, maxObjects, &actual)
	if rv != C.CKR_OK {
		return nil, newTokenError("C_FindObjects", returnValue(rv))
	}
	if actual == 0 {
		return nil, nil
	}

	slice := unsafe.Slice(found, int(actual))
	handles := make([]objectHandle, 0, int(actual))
	for _, handle := range slice {
		handles = append(handles, objectHandle(handle))
	}
	return handles, nil
}

// GetAttributes reads attributes with the PKCS#11 two-call convention: the
// first call sizes each value, the second fills it. An attribute the object
// does not carry comes back with CK_UNAVAILABLE_INFORMATION and is reported as
// absent rather than failing the whole read, which is what lets DeactivateKey
// probe before it writes.
func (m *cgoModule) GetAttributes(session sessionHandle, object objectHandle, types []attributeType) ([]attribute, error) {
	if len(types) == 0 {
		return nil, nil
	}

	base := (C.CK_ATTRIBUTE_PTR)(C.calloc(C.size_t(len(types)), C.size_t(unsafe.Sizeof(C.CK_ATTRIBUTE{}))))
	defer C.free(unsafe.Pointer(base))

	for index, kind := range types {
		C.forge_attr_set(C.forge_attr_at(base, C.int(index)), C.CK_ATTRIBUTE_TYPE(kind), nil, 0)
	}

	// The sizing call returns a failure code when any attribute is missing,
	// which is expected: the per-attribute lengths are what matters.
	sizeRV := C.forge_get_attribute_value(m.list, C.CK_SESSION_HANDLE(session),
		C.CK_OBJECT_HANDLE(object), base, C.CK_ULONG(len(types)))

	allocated := make([]unsafe.Pointer, 0, len(types))
	defer func() {
		for _, pointer := range allocated {
			C.free(pointer)
		}
	}()

	anySized := false
	for index := range types {
		slot := C.forge_attr_at(base, C.int(index))
		if C.forge_attr_unavailable(slot) != 0 {
			continue
		}
		length := C.forge_attr_len(slot)
		if length == 0 {
			anySized = true
			continue
		}
		buffer := C.malloc(C.size_t(length))
		allocated = append(allocated, buffer)
		C.forge_attr_set(slot, C.CK_ATTRIBUTE_TYPE(types[index]), C.CK_VOID_PTR(buffer), length)
		anySized = true
	}

	if anySized {
		if rv := C.forge_get_attribute_value(m.list, C.CK_SESSION_HANDLE(session),
			C.CK_OBJECT_HANDLE(object), base, C.CK_ULONG(len(types))); rv != C.CKR_OK {
			// A partial failure is still usable: absent attributes are marked
			// absent below. Only a hard failure with nothing readable is an
			// error.
			if returnValue(rv) != ckrAttributeSensitive && returnValue(rv) != ckrAttributeTypeInalid {
				return nil, newTokenError("C_GetAttributeValue", returnValue(rv))
			}
		}
	} else if sizeRV != C.CKR_OK && returnValue(sizeRV) != ckrAttributeTypeInalid &&
		returnValue(sizeRV) != ckrAttributeSensitive {
		return nil, newTokenError("C_GetAttributeValue", returnValue(sizeRV))
	}

	result := make([]attribute, 0, len(types))
	for index, kind := range types {
		slot := C.forge_attr_at(base, C.int(index))
		if C.forge_attr_unavailable(slot) != 0 {
			result = append(result, attribute{Type: kind, Present: false})
			continue
		}
		length := C.forge_attr_len(slot)
		value := C.forge_attr_value(slot)
		if length == 0 || value == nil {
			result = append(result, attribute{Type: kind, Present: true})
			continue
		}
		result = append(result, attribute{
			Type:    kind,
			Value:   C.GoBytes(unsafe.Pointer(value), C.int(length)),
			Present: true,
		})
	}
	return result, nil
}

func (m *cgoModule) SetAttributes(session sessionHandle, object objectHandle, template []attribute) error {
	cTmpl := newCTemplate(template)
	defer cTmpl.free()

	rv := C.forge_set_attribute_value(m.list, C.CK_SESSION_HANDLE(session),
		C.CK_OBJECT_HANDLE(object), cTmpl.base, cTmpl.count)
	return newTokenError("C_SetAttributeValue", returnValue(rv))
}

func (m *cgoModule) DestroyObject(session sessionHandle, object objectHandle) error {
	rv := C.forge_destroy_object(m.list, C.CK_SESSION_HANDLE(session), C.CK_OBJECT_HANDLE(object))
	return newTokenError("C_DestroyObject", returnValue(rv))
}

func (m *cgoModule) GenerateKey(session sessionHandle, mech mechanism, template []attribute) (objectHandle, error) {
	cTmpl := newCTemplate(template)
	defer cTmpl.free()

	cMech, release := newCMechanism(mech, nil)
	defer release()

	var key C.CK_OBJECT_HANDLE
	rv := C.forge_generate_key(m.list, C.CK_SESSION_HANDLE(session), cMech, cTmpl.base, cTmpl.count, &key)
	if rv != C.CKR_OK {
		return 0, newTokenError("C_GenerateKey", returnValue(rv))
	}
	return objectHandle(key), nil
}

func (m *cgoModule) GenerateKeyPair(session sessionHandle, mech mechanism, public, private []attribute) (objectHandle, objectHandle, error) {
	publicTmpl := newCTemplate(public)
	defer publicTmpl.free()
	privateTmpl := newCTemplate(private)
	defer privateTmpl.free()

	cMech, release := newCMechanism(mech, nil)
	defer release()

	var publicKey, privateKey C.CK_OBJECT_HANDLE
	rv := C.forge_generate_key_pair(m.list, C.CK_SESSION_HANDLE(session), cMech,
		publicTmpl.base, publicTmpl.count, privateTmpl.base, privateTmpl.count, &publicKey, &privateKey)
	if rv != C.CKR_OK {
		return 0, 0, newTokenError("C_GenerateKeyPair", returnValue(rv))
	}
	return objectHandle(publicKey), objectHandle(privateKey), nil
}

func (m *cgoModule) DeriveKey(session sessionHandle, mech mechanism, params mechanismParams, base objectHandle, template []attribute) (objectHandle, error) {
	cTmpl := newCTemplate(template)
	defer cTmpl.free()

	cMech, release := newCMechanism(mech, params)
	defer release()

	var derived C.CK_OBJECT_HANDLE
	rv := C.forge_derive_key(m.list, C.CK_SESSION_HANDLE(session), cMech,
		C.CK_OBJECT_HANDLE(base), cTmpl.base, cTmpl.count, &derived)
	if rv != C.CKR_OK {
		return 0, newTokenError("C_DeriveKey", returnValue(rv))
	}
	return objectHandle(derived), nil
}

func (m *cgoModule) Encrypt(session sessionHandle, mech mechanism, params mechanismParams, key objectHandle, plaintext []byte) ([]byte, error) {
	return m.transform("C_Encrypt", mech, params, plaintext,
		func(cMech C.CK_MECHANISM_PTR) C.CK_RV {
			return C.forge_encrypt_init(m.list, C.CK_SESSION_HANDLE(session), cMech, C.CK_OBJECT_HANDLE(key))
		},
		func(in C.CK_BYTE_PTR, inLen C.CK_ULONG, out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
			return C.forge_encrypt(m.list, C.CK_SESSION_HANDLE(session), in, inLen, out, outLen)
		})
}

func (m *cgoModule) Decrypt(session sessionHandle, mech mechanism, params mechanismParams, key objectHandle, ciphertext []byte) ([]byte, error) {
	return m.transform("C_Decrypt", mech, params, ciphertext,
		func(cMech C.CK_MECHANISM_PTR) C.CK_RV {
			return C.forge_decrypt_init(m.list, C.CK_SESSION_HANDLE(session), cMech, C.CK_OBJECT_HANDLE(key))
		},
		func(in C.CK_BYTE_PTR, inLen C.CK_ULONG, out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
			return C.forge_decrypt(m.list, C.CK_SESSION_HANDLE(session), in, inLen, out, outLen)
		})
}

func (m *cgoModule) Sign(session sessionHandle, mech mechanism, params mechanismParams, key objectHandle, message []byte) ([]byte, error) {
	return m.transform("C_Sign", mech, params, message,
		func(cMech C.CK_MECHANISM_PTR) C.CK_RV {
			return C.forge_sign_init(m.list, C.CK_SESSION_HANDLE(session), cMech, C.CK_OBJECT_HANDLE(key))
		},
		func(in C.CK_BYTE_PTR, inLen C.CK_ULONG, out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
			return C.forge_sign(m.list, C.CK_SESSION_HANDLE(session), in, inLen, out, outLen)
		})
}

func (m *cgoModule) Verify(session sessionHandle, mech mechanism, params mechanismParams, key objectHandle, message, signature []byte) error {
	cMech, release := newCMechanism(mech, params)
	defer release()

	in := C.CBytes(message)
	defer C.free(in)
	sig := C.CBytes(signature)
	defer C.free(sig)

	rv := C.forge_verify(m.list, C.CK_SESSION_HANDLE(session), cMech, C.CK_OBJECT_HANDLE(key),
		(C.CK_BYTE_PTR)(in), C.CK_ULONG(len(message)), (C.CK_BYTE_PTR)(sig), C.CK_ULONG(len(signature)))
	return newTokenError("C_Verify", returnValue(rv))
}

// transform runs a single-part operation with the PKCS#11 two-call convention.
//
// The operation is initialised exactly once; the operation itself then runs
// twice, first with a nil output buffer to learn the size and then to fill it.
// Re-initialising between the two calls is what a token reports as
// CKR_OPERATION_ACTIVE, because the sizing call deliberately leaves the
// operation open.
func (m *cgoModule) transform(
	name string,
	mech mechanism,
	params mechanismParams,
	input []byte,
	initialise func(C.CK_MECHANISM_PTR) C.CK_RV,
	call func(C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, *C.CK_ULONG) C.CK_RV,
) ([]byte, error) {
	cMech, release := newCMechanism(mech, params)
	defer release()

	if rv := initialise(cMech); rv != C.CKR_OK {
		return nil, newTokenError(name+"Init", returnValue(rv))
	}

	in := C.CBytes(input)
	defer C.free(in)

	var outLen C.CK_ULONG
	if rv := call((C.CK_BYTE_PTR)(in), C.CK_ULONG(len(input)), nil, &outLen); rv != C.CKR_OK {
		return nil, newTokenError(name, returnValue(rv))
	}
	if outLen == 0 {
		return nil, nil
	}

	out := C.malloc(C.size_t(outLen))
	defer C.free(out)

	if rv := call((C.CK_BYTE_PTR)(in), C.CK_ULONG(len(input)), (C.CK_BYTE_PTR)(out), &outLen); rv != C.CKR_OK {
		return nil, newTokenError(name, returnValue(rv))
	}
	return C.GoBytes(out, C.int(outLen)), nil
}

// newCMechanism builds a CK_MECHANISM with its parameter block in C memory,
// returning a release function that frees everything it allocated.
func newCMechanism(mech mechanism, params mechanismParams) (C.CK_MECHANISM_PTR, func()) {
	cMech := (C.CK_MECHANISM_PTR)(C.calloc(1, C.size_t(unsafe.Sizeof(C.CK_MECHANISM{}))))
	cMech.mechanism = C.CK_MECHANISM_TYPE(mech)

	var owned []unsafe.Pointer
	release := func() {
		for _, pointer := range owned {
			C.free(pointer)
		}
		C.free(unsafe.Pointer(cMech))
	}

	switch typed := params.(type) {
	case nil:
		cMech.pParameter = nil
		cMech.ulParameterLen = 0

	case gcmParams:
		block := (*C.CK_GCM_PARAMS)(C.calloc(1, C.size_t(unsafe.Sizeof(C.CK_GCM_PARAMS{}))))
		owned = append(owned, unsafe.Pointer(block))
		iv := C.CBytes(typed.IV)
		owned = append(owned, iv)
		block.pIv = (C.CK_BYTE_PTR)(iv)
		block.ulIvLen = C.CK_ULONG(len(typed.IV))
		// ulIvBits is ambiguous across vendors; filling it consistently with
		// ulIvLen is what the modules that read it expect.
		block.ulIvBits = C.CK_ULONG(len(typed.IV) * 8)
		if len(typed.AAD) > 0 {
			aad := C.CBytes(typed.AAD)
			owned = append(owned, aad)
			block.pAAD = (C.CK_BYTE_PTR)(aad)
			block.ulAADLen = C.CK_ULONG(len(typed.AAD))
		}
		block.ulTagBits = C.CK_ULONG(typed.TagBits)
		cMech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(block))
		cMech.ulParameterLen = C.CK_ULONG(unsafe.Sizeof(C.CK_GCM_PARAMS{}))

	case oaepParams:
		block := (*C.CK_RSA_PKCS_OAEP_PARAMS)(C.calloc(1, C.size_t(unsafe.Sizeof(C.CK_RSA_PKCS_OAEP_PARAMS{}))))
		owned = append(owned, unsafe.Pointer(block))
		block.hashAlg = C.CK_MECHANISM_TYPE(typed.HashAlg)
		block.mgf = C.CK_ULONG(typed.MGF)
		block.source = C.CK_ULONG(typed.Source)
		block.pSourceData = nil
		block.ulSourceDataLen = 0
		cMech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(block))
		cMech.ulParameterLen = C.CK_ULONG(unsafe.Sizeof(C.CK_RSA_PKCS_OAEP_PARAMS{}))

	case pssParams:
		block := (*C.CK_RSA_PKCS_PSS_PARAMS)(C.calloc(1, C.size_t(unsafe.Sizeof(C.CK_RSA_PKCS_PSS_PARAMS{}))))
		owned = append(owned, unsafe.Pointer(block))
		block.hashAlg = C.CK_MECHANISM_TYPE(typed.HashAlg)
		block.mgf = C.CK_ULONG(typed.MGF)
		block.sLen = C.CK_ULONG(typed.SaltLen)
		cMech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(block))
		cMech.ulParameterLen = C.CK_ULONG(unsafe.Sizeof(C.CK_RSA_PKCS_PSS_PARAMS{}))

	case ecdh1Params:
		block := (*C.CK_ECDH1_DERIVE_PARAMS)(C.calloc(1, C.size_t(unsafe.Sizeof(C.CK_ECDH1_DERIVE_PARAMS{}))))
		owned = append(owned, unsafe.Pointer(block))
		block.kdf = C.CK_ULONG(typed.KDF)
		if len(typed.SharedData) > 0 {
			shared := C.CBytes(typed.SharedData)
			owned = append(owned, shared)
			block.pSharedData = (C.CK_BYTE_PTR)(shared)
			block.ulSharedDataLen = C.CK_ULONG(len(typed.SharedData))
		}
		if len(typed.PublicData) > 0 {
			public := C.CBytes(typed.PublicData)
			owned = append(owned, public)
			block.pPublicData = (C.CK_BYTE_PTR)(public)
			block.ulPublicDataLen = C.CK_ULONG(len(typed.PublicData))
		}
		cMech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(block))
		cMech.ulParameterLen = C.CK_ULONG(unsafe.Sizeof(C.CK_ECDH1_DERIVE_PARAMS{}))

	case hkdfParams:
		block := (*C.CK_HKDF_PARAMS)(C.calloc(1, C.size_t(unsafe.Sizeof(C.CK_HKDF_PARAMS{}))))
		owned = append(owned, unsafe.Pointer(block))
		block.bExtract = cBool(typed.Extract)
		block.bExpand = cBool(typed.Expand)
		block.prfHashMechanism = C.CK_MECHANISM_TYPE(typed.PRF)
		block.ulSaltType = C.CK_ULONG(typed.SaltType)
		if len(typed.Info) > 0 {
			info := C.CBytes(typed.Info)
			owned = append(owned, info)
			block.pInfo = (C.CK_BYTE_PTR)(info)
			block.ulInfoLen = C.CK_ULONG(len(typed.Info))
		}
		cMech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(block))
		cMech.ulParameterLen = C.CK_ULONG(unsafe.Sizeof(C.CK_HKDF_PARAMS{}))

	case eddsaParams:
		block := (*C.CK_EDDSA_PARAMS)(C.calloc(1, C.size_t(unsafe.Sizeof(C.CK_EDDSA_PARAMS{}))))
		owned = append(owned, unsafe.Pointer(block))
		block.phFlag = cBool(typed.PhFlag)
		cMech.pParameter = C.CK_VOID_PTR(unsafe.Pointer(block))
		cMech.ulParameterLen = C.CK_ULONG(unsafe.Sizeof(C.CK_EDDSA_PARAMS{}))
	}

	return cMech, release
}

func cBool(value bool) C.CK_BBOOL {
	if value {
		return C.CK_BBOOL(C.CK_TRUE)
	}
	return C.CK_BBOOL(C.CK_FALSE)
}
