/* Copyright 2026 PointerByte Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal PKCS#11 (Cryptoki) declarations.
 *
 * This declares only what the Go binding calls, plus the exact layout of
 * CK_FUNCTION_LIST. That struct is an ordered table of 68 function pointers and
 * the loader reaches every function through it, so an entry declared out of
 * order would silently call the wrong function -- in cryptographic code, with
 * no compiler error. Unused entries are declared as void* rather than omitted:
 * every entry is a function pointer, so void* is layout-identical, and keeping
 * all 68 preserves the offsets of the ones that matter.
 *
 * The _Static_assert block at the bottom turns a layout mistake into a compile
 * error. The risk it guards is real: CK_VERSION is two bytes and is padded
 * before the first pointer, and the canonical vendor header packs structures to
 * one byte on Windows, which shifts every offset. That is why the cgo build tag
 * excludes Windows.
 *
 * Targeting the v2.40 function list is deliberate. C_GetFunctionList returns
 * this 68-entry table even on v3.0 modules, and the v3.0 mechanisms this
 * package uses (CKM_HKDF_DERIVE, CKM_EDDSA, CKM_EC_EDWARDS_KEY_PAIR_GEN) are
 * plain numeric constants that do not change the struct.
 */

#ifndef FORGE_CRYPTOKI_H
#define FORGE_CRYPTOKI_H

#include <stddef.h>
#include <stdint.h>

typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_CHAR;
typedef CK_BYTE CK_UTF8CHAR;
typedef CK_BYTE CK_BBOOL;
typedef unsigned long int CK_ULONG;
typedef long int CK_LONG;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_ULONG CK_USER_TYPE;
typedef CK_ULONG CK_NOTIFICATION;
typedef void *CK_VOID_PTR;
typedef CK_VOID_PTR *CK_VOID_PTR_PTR;
typedef CK_BYTE *CK_BYTE_PTR;
typedef CK_UTF8CHAR *CK_UTF8CHAR_PTR;
typedef CK_ULONG *CK_ULONG_PTR;
typedef CK_SLOT_ID *CK_SLOT_ID_PTR;
typedef CK_MECHANISM_TYPE *CK_MECHANISM_TYPE_PTR;
typedef CK_OBJECT_HANDLE *CK_OBJECT_HANDLE_PTR;

#define CK_TRUE 1
#define CK_FALSE 0

/* CKF_OS_LOCKING_OK tells the module the application is multi-threaded and it
 * must use OS locking primitives. Passing NULL instead declares a single
 * threaded application, and several modules then skip internal locking, which
 * corrupts state under concurrency. */
#define CKF_OS_LOCKING_OK 0x00000002
#define CKF_SERIAL_SESSION 0x00000004
#define CKF_RW_SESSION 0x00000002

#define CKU_USER 1

#define CK_UNAVAILABLE_INFORMATION (~0UL)
#define CK_EFFECTIVELY_INFINITE 0
#define CKR_OK 0x00000000

typedef struct CK_VERSION {
  CK_BYTE major;
  CK_BYTE minor;
} CK_VERSION;

typedef struct CK_INFO {
  CK_VERSION cryptokiVersion;
  CK_UTF8CHAR manufacturerID[32];
  CK_FLAGS flags;
  CK_UTF8CHAR libraryDescription[32];
  CK_VERSION libraryVersion;
} CK_INFO;

typedef struct CK_SLOT_INFO {
  CK_UTF8CHAR slotDescription[64];
  CK_UTF8CHAR manufacturerID[32];
  CK_FLAGS flags;
  CK_VERSION hardwareVersion;
  CK_VERSION firmwareVersion;
} CK_SLOT_INFO;

typedef struct CK_TOKEN_INFO {
  CK_UTF8CHAR label[32];
  CK_UTF8CHAR manufacturerID[32];
  CK_UTF8CHAR model[16];
  CK_CHAR serialNumber[16];
  CK_FLAGS flags;
  CK_ULONG ulMaxSessionCount;
  CK_ULONG ulSessionCount;
  CK_ULONG ulMaxRwSessionCount;
  CK_ULONG ulRwSessionCount;
  CK_ULONG ulMaxPinLen;
  CK_ULONG ulMinPinLen;
  CK_ULONG ulTotalPublicMemory;
  CK_ULONG ulFreePublicMemory;
  CK_ULONG ulTotalPrivateMemory;
  CK_ULONG ulFreePrivateMemory;
  CK_VERSION hardwareVersion;
  CK_VERSION firmwareVersion;
  CK_CHAR utcTime[16];
} CK_TOKEN_INFO;

typedef struct CK_ATTRIBUTE {
  CK_ATTRIBUTE_TYPE type;
  CK_VOID_PTR pValue;
  CK_ULONG ulValueLen;
} CK_ATTRIBUTE;
typedef CK_ATTRIBUTE *CK_ATTRIBUTE_PTR;

typedef struct CK_MECHANISM {
  CK_MECHANISM_TYPE mechanism;
  CK_VOID_PTR pParameter;
  CK_ULONG ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM *CK_MECHANISM_PTR;

/* Mechanism parameter blocks. Each embeds raw pointers, which is why they are
 * built here in C memory and never marshalled from Go: storing a Go pointer in
 * C-visible memory violates the cgo pointer rules. */
typedef struct CK_GCM_PARAMS {
  CK_BYTE_PTR pIv;
  CK_ULONG ulIvLen;
  CK_ULONG ulIvBits;
  CK_BYTE_PTR pAAD;
  CK_ULONG ulAADLen;
  CK_ULONG ulTagBits;
} CK_GCM_PARAMS;

typedef struct CK_RSA_PKCS_OAEP_PARAMS {
  CK_MECHANISM_TYPE hashAlg;
  CK_ULONG mgf;
  CK_ULONG source;
  CK_VOID_PTR pSourceData;
  CK_ULONG ulSourceDataLen;
} CK_RSA_PKCS_OAEP_PARAMS;

typedef struct CK_RSA_PKCS_PSS_PARAMS {
  CK_MECHANISM_TYPE hashAlg;
  CK_ULONG mgf;
  CK_ULONG sLen;
} CK_RSA_PKCS_PSS_PARAMS;

typedef struct CK_ECDH1_DERIVE_PARAMS {
  CK_ULONG kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
} CK_ECDH1_DERIVE_PARAMS;

typedef struct CK_HKDF_PARAMS {
  CK_BBOOL bExtract;
  CK_BBOOL bExpand;
  CK_MECHANISM_TYPE prfHashMechanism;
  CK_ULONG ulSaltType;
  CK_BYTE_PTR pSalt;
  CK_ULONG ulSaltLen;
  CK_OBJECT_HANDLE hSaltKey;
  CK_BYTE_PTR pInfo;
  CK_ULONG ulInfoLen;
} CK_HKDF_PARAMS;

typedef struct CK_EDDSA_PARAMS {
  CK_BBOOL phFlag;
  CK_ULONG ulContextDataLen;
  CK_BYTE_PTR pContextData;
} CK_EDDSA_PARAMS;

typedef struct CK_C_INITIALIZE_ARGS {
  CK_VOID_PTR CreateMutex;
  CK_VOID_PTR DestroyMutex;
  CK_VOID_PTR LockMutex;
  CK_VOID_PTR UnlockMutex;
  CK_FLAGS flags;
  CK_VOID_PTR pReserved;
} CK_C_INITIALIZE_ARGS;
typedef CK_C_INITIALIZE_ARGS *CK_C_INITIALIZE_ARGS_PTR;

/* The v2.40 function table: 68 entries in specification order. */
typedef struct CK_FUNCTION_LIST {
  CK_VERSION version;

  CK_RV (*C_Initialize)(CK_VOID_PTR);
  CK_RV (*C_Finalize)(CK_VOID_PTR);
  CK_RV (*C_GetInfo)(CK_INFO *);
  void *C_GetFunctionList;
  CK_RV (*C_GetSlotList)(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
  CK_RV (*C_GetSlotInfo)(CK_SLOT_ID, CK_SLOT_INFO *);
  CK_RV (*C_GetTokenInfo)(CK_SLOT_ID, CK_TOKEN_INFO *);
  CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);
  void *C_GetMechanismInfo;
  void *C_InitToken;
  void *C_InitPIN;
  void *C_SetPIN;
  CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_VOID_PTR, CK_SESSION_HANDLE *);
  CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
  void *C_CloseAllSessions;
  void *C_GetSessionInfo;
  void *C_GetOperationState;
  void *C_SetOperationState;
  CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG);
  CK_RV (*C_Logout)(CK_SESSION_HANDLE);
  void *C_CreateObject;
  void *C_CopyObject;
  CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
  void *C_GetObjectSize;
  CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
  CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
  CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
  CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR);
  CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
  CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
  CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
  void *C_EncryptUpdate;
  void *C_EncryptFinal;
  CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
  CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
  void *C_DecryptUpdate;
  void *C_DecryptFinal;
  void *C_DigestInit;
  void *C_Digest;
  void *C_DigestUpdate;
  void *C_DigestKey;
  void *C_DigestFinal;
  CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
  CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
  void *C_SignUpdate;
  void *C_SignFinal;
  void *C_SignRecoverInit;
  void *C_SignRecover;
  CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
  CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
  void *C_VerifyUpdate;
  void *C_VerifyFinal;
  void *C_VerifyRecoverInit;
  void *C_VerifyRecover;
  void *C_DigestEncryptUpdate;
  void *C_DecryptDigestUpdate;
  void *C_SignEncryptUpdate;
  void *C_DecryptVerifyUpdate;
  CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
  CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG,
                             CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR);
  void *C_WrapKey;
  void *C_UnwrapKey;
  CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR,
                       CK_ULONG, CK_OBJECT_HANDLE_PTR);
  void *C_SeedRandom;
  void *C_GenerateRandom;
  void *C_GetFunctionStatus;
  void *C_CancelFunction;
  void *C_WaitForSlotEvent;
} CK_FUNCTION_LIST;

typedef CK_RV (*CK_C_GetFunctionList)(CK_FUNCTION_LIST **);

/* Layout guards. CK_VERSION is two bytes and pads to the pointer alignment
 * before the first entry; if a compiler or a stray pragma changed that, every
 * offset below would shift and the loader would call the wrong function. These
 * make that a compile error instead. */
#define FORGE_ENTRY_OFFSET(n) (sizeof(void *) + (n) * sizeof(void *))

_Static_assert(sizeof(void *) == 8, "forge pkcs11 binding requires 64-bit pointers");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_Initialize) == FORGE_ENTRY_OFFSET(0), "C_Initialize moved");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_GetSlotList) == FORGE_ENTRY_OFFSET(4), "C_GetSlotList moved");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_GetTokenInfo) == FORGE_ENTRY_OFFSET(6), "C_GetTokenInfo moved");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_GetMechanismList) == FORGE_ENTRY_OFFSET(7), "C_GetMechanismList moved");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_OpenSession) == FORGE_ENTRY_OFFSET(12), "C_OpenSession moved");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_Login) == FORGE_ENTRY_OFFSET(18), "C_Login moved");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_DestroyObject) == FORGE_ENTRY_OFFSET(22), "C_DestroyObject moved");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_GetAttributeValue) == FORGE_ENTRY_OFFSET(24), "C_GetAttributeValue moved");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_FindObjectsInit) == FORGE_ENTRY_OFFSET(26), "C_FindObjectsInit moved");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_EncryptInit) == FORGE_ENTRY_OFFSET(29), "C_EncryptInit moved");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_DecryptInit) == FORGE_ENTRY_OFFSET(33), "C_DecryptInit moved");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_SignInit) == FORGE_ENTRY_OFFSET(42), "C_SignInit moved");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_Sign) == FORGE_ENTRY_OFFSET(43), "C_Sign moved");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_VerifyInit) == FORGE_ENTRY_OFFSET(48), "C_VerifyInit moved");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_GenerateKey) == FORGE_ENTRY_OFFSET(58), "C_GenerateKey moved");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_GenerateKeyPair) == FORGE_ENTRY_OFFSET(59), "C_GenerateKeyPair moved");
_Static_assert(offsetof(CK_FUNCTION_LIST, C_DeriveKey) == FORGE_ENTRY_OFFSET(62), "C_DeriveKey moved");
_Static_assert(sizeof(CK_FUNCTION_LIST) == FORGE_ENTRY_OFFSET(68), "CK_FUNCTION_LIST is not 68 entries");

#endif /* FORGE_CRYPTOKI_H */
