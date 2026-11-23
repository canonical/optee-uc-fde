/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 *
 * cmocka fakes for the functions in the mock tee_internal_api.h, see
 * tests/mocks/README.md for how to use them.
 */

#include <string.h>

#include <cmocka.h>

#include <tee_internal_api.h>

/*
 * Copy the data a test queued with will_set_parameter_ptr() for an output
 * buffer, whose length was queued with will_set_parameter_uint().
 */
#define SET_OUTPUT_BUFFER(buf, len)                            \
	do {                                                   \
		size_t out_len = mock_parameter_uint(len);     \
                                                               \
		assert_true(out_len <= *(len));                \
		memcpy(buf, mock_parameter_ptr(buf), out_len); \
		*(len) = out_len;                              \
	} while (0)

/* Trusted Core Framework API */

void TEE_Panic(TEE_Result panicCode)
{
	check_expected_uint(panicCode);
	mock_assert(false, "TEE_Panic()", __FILE__, __LINE__);
}

TEE_Result TEE_OpenTASession(const TEE_UUID *destination,
			     uint32_t cancellationRequestTimeout,
			     uint32_t paramTypes,
			     TEE_Param params[TEE_NUM_PARAMS],
			     TEE_TASessionHandle *session,
			     uint32_t *returnOrigin)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	check_expected_ptr(destination);
	check_expected_uint(cancellationRequestTimeout);
	check_expected_uint(paramTypes);
	check_expected_ptr(params);

	res = (TEE_Result)mock_uint();
	if (res == TEE_SUCCESS)
		*session = mock_parameter_ptr(session);
	if (returnOrigin)
		*returnOrigin = TEE_ORIGIN_TRUSTED_APP;

	return res;
}

void TEE_CloseTASession(TEE_TASessionHandle session)
{
	check_expected_ptr(session);
}

TEE_Result TEE_InvokeTACommand(TEE_TASessionHandle session,
			       uint32_t cancellationRequestTimeout,
			       uint32_t commandID, uint32_t paramTypes,
			       TEE_Param params[TEE_NUM_PARAMS],
			       uint32_t *returnOrigin)
{
	check_expected_ptr(session);
	check_expected_uint(cancellationRequestTimeout);
	check_expected_uint(commandID);
	check_expected_uint(paramTypes);
	check_expected_ptr(params);

	if (returnOrigin)
		*returnOrigin = TEE_ORIGIN_TRUSTED_APP;

	return (TEE_Result)mock_uint();
}

void *TEE_Malloc(size_t size, uint32_t hint)
{
	(void)hint;

	/* test_calloc() reports leaks when the test ends */
	return test_calloc(1, size);
}

void TEE_Free(void *buffer)
{
	if (buffer)
		test_free(buffer);
}

/* Trusted Storage API for Data and Keys */

TEE_Result TEE_AllocateTransientObject(TEE_ObjectType objectType,
				       uint32_t maxObjectSize,
				       TEE_ObjectHandle *object)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	check_expected_uint(objectType);
	check_expected_uint(maxObjectSize);

	res = (TEE_Result)mock_uint();
	if (res == TEE_SUCCESS)
		*object = mock_parameter_ptr(object);

	return res;
}

void TEE_FreeTransientObject(TEE_ObjectHandle object)
{
	check_expected_ptr(object);
}

TEE_Result TEE_PopulateTransientObject(TEE_ObjectHandle object,
				       const TEE_Attribute *attrs,
				       uint32_t attrCount)
{
	check_expected_ptr(object);
	check_expected_ptr(attrs);
	check_expected_uint(attrCount);

	return (TEE_Result)mock_uint();
}

/* Cryptographic Operations API */

TEE_Result TEE_AllocateOperation(TEE_OperationHandle *operation,
				 uint32_t algorithm, uint32_t mode,
				 uint32_t maxKeySize)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	check_expected_uint(algorithm);
	check_expected_uint(mode);
	check_expected_uint(maxKeySize);

	res = (TEE_Result)mock_uint();
	if (res == TEE_SUCCESS)
		*operation = mock_parameter_ptr(operation);

	return res;
}

void TEE_FreeOperation(TEE_OperationHandle operation)
{
	check_expected_ptr(operation);
}

TEE_Result TEE_SetOperationKey(TEE_OperationHandle operation,
			       TEE_ObjectHandle key)
{
	check_expected_ptr(operation);
	check_expected_ptr(key);

	return (TEE_Result)mock_uint();
}

TEE_Result TEE_AEInit(TEE_OperationHandle operation, const void *nonce,
		      size_t nonceLen, uint32_t tagLen, size_t AADLen,
		      size_t payloadLen)
{
	check_expected_ptr(operation);
	check_expected_ptr(nonce);
	check_expected_uint(nonceLen);
	check_expected_uint(tagLen);
	check_expected_uint(AADLen);
	check_expected_uint(payloadLen);

	return (TEE_Result)mock_uint();
}

TEE_Result TEE_AEEncryptFinal(TEE_OperationHandle operation,
			      const void *srcData, size_t srcLen,
			      void *destData, size_t *destLen, void *tag,
			      size_t *tagLen)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	check_expected_ptr(operation);
	check_expected_ptr(srcData);
	check_expected_uint(srcLen);

	res = (TEE_Result)mock_uint();
	if (res == TEE_SUCCESS) {
		SET_OUTPUT_BUFFER(destData, destLen);
		SET_OUTPUT_BUFFER(tag, tagLen);
	}

	return res;
}

TEE_Result TEE_AEDecryptFinal(TEE_OperationHandle operation,
			      const void *srcData, size_t srcLen,
			      void *destData, size_t *destLen, void *tag,
			      size_t tagLen)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	check_expected_ptr(operation);
	check_expected_ptr(srcData);
	check_expected_uint(srcLen);
	check_expected_ptr(tag);
	check_expected_uint(tagLen);

	res = (TEE_Result)mock_uint();
	if (res == TEE_SUCCESS)
		SET_OUTPUT_BUFFER(destData, destLen);

	return res;
}

void TEE_GenerateRandom(void *randomBuffer, size_t randomBufferLen)
{
	check_expected_uint(randomBufferLen);

	memcpy(randomBuffer, mock_parameter_ptr(randomBuffer), randomBufferLen);
}
