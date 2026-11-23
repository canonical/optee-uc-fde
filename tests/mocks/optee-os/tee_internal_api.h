/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 *
 * Mock of OP-TEE's tee_internal_api.h, GP TEE Internal Core API 1.3.1
 */

#ifndef MOCK_TEE_INTERNAL_API_H
#define MOCK_TEE_INTERNAL_API_H

#include <tee_api_defines.h>
#include <tee_api_types.h>

/* Trusted Core Framework API */

void TEE_Panic(TEE_Result panicCode);

TEE_Result TEE_OpenTASession(const TEE_UUID *destination,
			     uint32_t cancellationRequestTimeout,
			     uint32_t paramTypes,
			     TEE_Param params[TEE_NUM_PARAMS],
			     TEE_TASessionHandle *session,
			     uint32_t *returnOrigin);

void TEE_CloseTASession(TEE_TASessionHandle session);

TEE_Result TEE_InvokeTACommand(TEE_TASessionHandle session,
			       uint32_t cancellationRequestTimeout,
			       uint32_t commandID, uint32_t paramTypes,
			       TEE_Param params[TEE_NUM_PARAMS],
			       uint32_t *returnOrigin);

void *TEE_Malloc(size_t size, uint32_t hint);
void TEE_Free(void *buffer);

/* Trusted Storage API for Data and Keys */

TEE_Result TEE_AllocateTransientObject(TEE_ObjectType objectType,
				       uint32_t maxObjectSize,
				       TEE_ObjectHandle *object);
void TEE_FreeTransientObject(TEE_ObjectHandle object);
TEE_Result TEE_PopulateTransientObject(TEE_ObjectHandle object,
				       const TEE_Attribute *attrs,
				       uint32_t attrCount);

/* Cryptographic Operations API */

TEE_Result TEE_AllocateOperation(TEE_OperationHandle *operation,
				 uint32_t algorithm, uint32_t mode,
				 uint32_t maxKeySize);
void TEE_FreeOperation(TEE_OperationHandle operation);
TEE_Result TEE_SetOperationKey(TEE_OperationHandle operation,
			       TEE_ObjectHandle key);

TEE_Result TEE_AEInit(TEE_OperationHandle operation, const void *nonce,
		      size_t nonceLen, uint32_t tagLen, size_t AADLen,
		      size_t payloadLen);
TEE_Result TEE_AEEncryptFinal(TEE_OperationHandle operation,
			      const void *srcData, size_t srcLen,
			      void *destData, size_t *destLen, void *tag,
			      size_t *tagLen);
TEE_Result TEE_AEDecryptFinal(TEE_OperationHandle operation,
			      const void *srcData, size_t srcLen,
			      void *destData, size_t *destLen, void *tag,
			      size_t tagLen);

void TEE_GenerateRandom(void *randomBuffer, size_t randomBufferLen);

/* Entry points implemented by the TA */

TEE_Result TA_CreateEntryPoint(void);
void TA_DestroyEntryPoint(void);
TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,
				    TEE_Param params[TEE_NUM_PARAMS],
				    void **sessionContext);
void TA_CloseSessionEntryPoint(void *sessionContext);
TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
				      uint32_t paramTypes,
				      TEE_Param params[TEE_NUM_PARAMS]);

#endif /* MOCK_TEE_INTERNAL_API_H */
