/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 *
 * Tests for fde_key_handler_ta_handle.c: sealing and unsealing keys, random
 * data and the TA version.
 */

#include <string.h>

#include <cmocka.h>

#include <pta_system.h>
#include <tee_internal_api.h>

#include "fde_key_handler_ta_handle.h"
#include "fde_key_handler_ta_type.h"

#define NO_PARAMS                                                 \
	TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, \
			TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)
#define VALUE_OUTPUT                                                      \
	TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE, \
			TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)
#define MEMREF_OUTPUT                                                      \
	TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE, \
			TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)
#define ENCRYPT_PARAMS                                \
	TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,  \
			TEE_PARAM_TYPE_MEMREF_OUTPUT, \
			TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE)
#define DECRYPT_PARAMS                               \
	TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, \
			TEE_PARAM_TYPE_MEMREF_INPUT, \
			TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE)
#define DERIVE_KEY_PARAMS                                                  \
	TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,                       \
			TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE, \
			TEE_PARAM_TYPE_NONE)

/* The key handle: version, IV, nonce and tag */
#define IV_SIZE 16
#define NONCE_SIZE 32
#define TAG_SIZE 16
#define HANDLE_VERSION 'U'
#define HANDLE_IV 1
#define HANDLE_NONCE (HANDLE_IV + IV_SIZE)
#define HANDLE_TAG (HANDLE_NONCE + NONCE_SIZE)

#define KEY_SIZE 64

/* Stand-ins for the OP-TEE handles */
static int operation;
static int session;
static int object;

/* Data returned by the fakes */
static uint8_t random_data[IV_SIZE + NONCE_SIZE];
static uint8_t derived_key[TA_DERIVED_KEY_MAX_SIZE];
static uint8_t plain_key[KEY_SIZE];
static uint8_t sealed_key[KEY_SIZE];
static uint8_t tag[TAG_SIZE];

/* The buffers passed to the TA, see setup_encrypt() and setup_decrypt() */
static uint8_t in[MAX_BUF_SIZE];
static uint8_t handle[HANDLE_SIZE];
static uint8_t out[MAX_BUF_SIZE];
static TEE_Param params[TEE_NUM_PARAMS];

static void fill(uint8_t *buf, size_t len, uint8_t first)
{
	for (size_t i = 0; i < len; i++) {
		buf[i] = (uint8_t)(first + i);
	}
}

static int setup_data(void **state)
{
	(void)state;
	fill(random_data, sizeof(random_data), 0x10);
	fill(derived_key, sizeof(derived_key), 0x40);
	fill(plain_key, sizeof(plain_key), 0x80);
	fill(sealed_key, sizeof(sealed_key), 0xc0);
	fill(tag, sizeof(tag), 0xf0);
	memset(in, 0, sizeof(in));
	memset(handle, 0, sizeof(handle));
	memset(out, 0, sizeof(out));
	memset(params, 0, sizeof(params));
	return 0;
}

/* Seal plain_key, with a handle and sealed key buffer of the usual sizes */
static int setup_encrypt(void **state)
{
	setup_data(state);
	memcpy(in, plain_key, KEY_SIZE);
	params[0].memref.buffer = in;
	params[0].memref.size = KEY_SIZE;
	params[1].memref.buffer = handle;
	params[1].memref.size = HANDLE_SIZE;
	params[2].memref.buffer = out;
	params[2].memref.size = MAX_BUF_SIZE;
	return 0;
}

/* Unseal sealed_key, with a handle as returned by sealing a key */
static int setup_decrypt(void **state)
{
	setup_data(state);
	memcpy(in, sealed_key, KEY_SIZE);
	handle[0] = HANDLE_VERSION;
	memcpy(handle + HANDLE_IV, random_data, sizeof(random_data));
	memcpy(handle + HANDLE_TAG, tag, TAG_SIZE);
	params[0].memref.buffer = in;
	params[0].memref.size = KEY_SIZE;
	params[1].memref.buffer = handle;
	params[1].memref.size = HANDLE_SIZE;
	params[2].memref.buffer = out;
	params[2].memref.size = MAX_BUF_SIZE;
	return 0;
}

/* Check the key derivation parameters, and return the derived key */
static int check_derive_key_params(CMockaValueData value,
				   CMockaValueData check_data)
{
	TEE_Param *p = value.ptr;

	(void)check_data;
	if (p[0].memref.buffer != handle + HANDLE_NONCE ||
	    p[0].memref.size != NONCE_SIZE ||
	    p[1].memref.size != sizeof(derived_key)) {
		return 0;
	}
	memcpy(p[1].memref.buffer, derived_key, sizeof(derived_key));
	return 1;
}

/* Check that the derived key is used as the AES key */
static int check_key_attr(CMockaValueData value, CMockaValueData check_data)
{
	const TEE_Attribute *attr = value.const_ptr;

	(void)check_data;
	return attr->attributeID == TEE_ATTR_SECRET_VALUE &&
	       attr->content.ref.length == sizeof(derived_key) &&
	       !memcmp(attr->content.ref.buffer, derived_key,
		       sizeof(derived_key));
}

/* The steps of setting up the AES-GCM operation, in order */
enum step {
	ALLOCATE_OPERATION,
	OPEN_SESSION,
	DERIVE_KEY,
	ALLOCATE_OBJECT,
	POPULATE_OBJECT,
	SET_KEY,
	AE_INIT,
	NO_FAILURE,
};

static TEE_Result result(enum step step, enum step fail, TEE_Result err)
{
	return step == fail ? err : TEE_SUCCESS;
}

/*
 * Expect the calls that set up the AES-GCM operation, with a key derived
 * from the hardware unique key and the handle's nonce, and then free it
 * again. The step fail returns err instead of succeeding. Without a failure,
 * the test still needs to expect TEE_AEEncryptFinal() or
 * TEE_AEDecryptFinal().
 */
static void expect_key_setup(TEE_OperationMode mode, enum step fail,
			     TEE_Result err)
{
	static const TEE_UUID pta_system_uuid = PTA_SYSTEM_UUID;

	expect_uint_value(TEE_AllocateOperation, algorithm, TEE_ALG_AES_GCM);
	expect_uint_value(TEE_AllocateOperation, mode, mode);
	expect_uint_value(TEE_AllocateOperation, maxKeySize,
			  sizeof(derived_key) * 8);
	will_return_uint(TEE_AllocateOperation,
			 result(ALLOCATE_OPERATION, fail, err));
	if (fail == ALLOCATE_OPERATION) {
		return;
	}
	will_set_parameter_ptr(TEE_AllocateOperation, operation, &operation);
	expect_uint_value(TEE_FreeOperation, operation, (uintptr_t)&operation);

	expect_memory(TEE_OpenTASession, destination, &pta_system_uuid,
		      sizeof(pta_system_uuid));
	expect_uint_value(TEE_OpenTASession, cancellationRequestTimeout,
			  TEE_TIMEOUT_INFINITE);
	expect_uint_value(TEE_OpenTASession, paramTypes, 0);
	expect_uint_value(TEE_OpenTASession, params, (uintptr_t)NULL);
	will_return_uint(TEE_OpenTASession, result(OPEN_SESSION, fail, err));
	if (fail == OPEN_SESSION) {
		return;
	}
	will_set_parameter_ptr(TEE_OpenTASession, session, &session);
	expect_uint_value(TEE_CloseTASession, session, (uintptr_t)&session);

	expect_uint_value(TEE_InvokeTACommand, session, (uintptr_t)&session);
	expect_uint_value(TEE_InvokeTACommand, cancellationRequestTimeout,
			  TEE_TIMEOUT_INFINITE);
	expect_uint_value(TEE_InvokeTACommand, commandID,
			  PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY);
	expect_uint_value(TEE_InvokeTACommand, paramTypes, DERIVE_KEY_PARAMS);
	expect_check_data(TEE_InvokeTACommand, params, check_derive_key_params,
			  cast_ptr_to_cmocka_value(NULL));
	will_return_uint(TEE_InvokeTACommand, result(DERIVE_KEY, fail, err));
	if (fail == DERIVE_KEY) {
		return;
	}

	expect_uint_value(TEE_AllocateTransientObject, objectType,
			  TEE_TYPE_AES);
	expect_uint_value(TEE_AllocateTransientObject, maxObjectSize,
			  sizeof(derived_key) * 8);
	will_return_uint(TEE_AllocateTransientObject,
			 result(ALLOCATE_OBJECT, fail, err));
	if (fail == ALLOCATE_OBJECT) {
		return;
	}
	will_set_parameter_ptr(TEE_AllocateTransientObject, object, &object);
	expect_uint_value(TEE_FreeTransientObject, object, (uintptr_t)&object);

	expect_uint_value(TEE_PopulateTransientObject, object,
			  (uintptr_t)&object);
	expect_check_data(TEE_PopulateTransientObject, attrs, check_key_attr,
			  cast_ptr_to_cmocka_value(NULL));
	expect_uint_value(TEE_PopulateTransientObject, attrCount, 1);
	will_return_uint(TEE_PopulateTransientObject,
			 result(POPULATE_OBJECT, fail, err));
	if (fail == POPULATE_OBJECT) {
		return;
	}

	expect_uint_value(TEE_SetOperationKey, operation,
			  (uintptr_t)&operation);
	expect_uint_value(TEE_SetOperationKey, key, (uintptr_t)&object);
	will_return_uint(TEE_SetOperationKey, result(SET_KEY, fail, err));
	if (fail == SET_KEY) {
		return;
	}

	expect_uint_value(TEE_AEInit, operation, (uintptr_t)&operation);
	expect_uint_value(TEE_AEInit, nonce, (uintptr_t)(handle + HANDLE_IV));
	expect_uint_value(TEE_AEInit, nonceLen, IV_SIZE);
	expect_uint_value(TEE_AEInit, tagLen, TAG_SIZE * 8);
	expect_uint_value(TEE_AEInit, AADLen, 0);
	expect_uint_value(TEE_AEInit, payloadLen, 0);
	will_return_uint(TEE_AEInit, result(AE_INIT, fail, err));
}

/* Expect the random IV and nonce of a new handle */
static void expect_random_handle(void)
{
	expect_uint_value(TEE_GenerateRandom, randomBufferLen,
			  sizeof(random_data));
	will_set_parameter_ptr(TEE_GenerateRandom, randomBuffer, random_data);
}

/* Expect encrypting plain_key, returning sealed_len bytes of sealed_key */
static void expect_encrypt_final(TEE_Result res, size_t sealed_len,
				 size_t tag_len)
{
	expect_uint_value(TEE_AEEncryptFinal, operation, (uintptr_t)&operation);
	expect_uint_value(TEE_AEEncryptFinal, srcData, (uintptr_t)in);
	expect_uint_value(TEE_AEEncryptFinal, srcLen, KEY_SIZE);
	will_return_uint(TEE_AEEncryptFinal, res);
	if (res == TEE_SUCCESS) {
		will_set_parameter_ptr(TEE_AEEncryptFinal, destData,
				       sealed_key);
		will_set_parameter_uint(TEE_AEEncryptFinal, destLen,
					sealed_len);
		will_set_parameter_ptr(TEE_AEEncryptFinal, tag, tag);
		will_set_parameter_uint(TEE_AEEncryptFinal, tagLen, tag_len);
	}
}

/* Expect decrypting sealed_key, returning plain_len bytes of plain_key */
static void expect_decrypt_final(TEE_Result res, size_t plain_len)
{
	expect_uint_value(TEE_AEDecryptFinal, operation, (uintptr_t)&operation);
	expect_uint_value(TEE_AEDecryptFinal, srcData, (uintptr_t)in);
	expect_uint_value(TEE_AEDecryptFinal, srcLen, KEY_SIZE);
	expect_memory(TEE_AEDecryptFinal, tag, tag, TAG_SIZE);
	expect_uint_value(TEE_AEDecryptFinal, tagLen, TAG_SIZE);
	will_return_uint(TEE_AEDecryptFinal, res);
	if (res == TEE_SUCCESS) {
		will_set_parameter_ptr(TEE_AEDecryptFinal, destData, plain_key);
		will_set_parameter_uint(TEE_AEDecryptFinal, destLen, plain_len);
	}
}

static TEE_Result run_encrypt(void)
{
	return cmd_symmetric_key_crypto(TEE_MODE_ENCRYPT, ENCRYPT_PARAMS,
					params);
}

static TEE_Result run_decrypt(void)
{
	return cmd_symmetric_key_crypto(TEE_MODE_DECRYPT, DECRYPT_PARAMS,
					params);
}

/* Check that a failed call didn't return any output */
static void assert_no_output(void)
{
	assert_uint_equal(params[1].memref.size, HANDLE_SIZE);
	assert_uint_equal(params[2].memref.size, MAX_BUF_SIZE);
}

/* get_ta_version() */

static void test_version(void **state)
{
	(void)state;
	assert_uint_equal(get_ta_version(VALUE_OUTPUT, params), TEE_SUCCESS);
	assert_uint_equal(params[0].value.a, FDE_TA_VERSION_V1);
}

static void test_version_bad_params(void **state)
{
	(void)state;
	assert_uint_equal(get_ta_version(NO_PARAMS, params),
			  TEE_ERROR_BAD_PARAMETERS);
	assert_uint_equal(get_ta_version(MEMREF_OUTPUT, params),
			  TEE_ERROR_BAD_PARAMETERS);
	assert_uint_equal(params[0].value.a, 0);
}

/* generate_random() */

static void test_random(void **state)
{
	(void)state;
	params[0].memref.buffer = out;
	params[0].memref.size = sizeof(random_data);
	expect_uint_value(TEE_GenerateRandom, randomBufferLen,
			  sizeof(random_data));
	will_set_parameter_ptr(TEE_GenerateRandom, randomBuffer, random_data);

	assert_uint_equal(generate_random(MEMREF_OUTPUT, params), TEE_SUCCESS);
	assert_memory_equal(out, random_data, sizeof(random_data));
	assert_uint_equal(params[0].memref.size, sizeof(random_data));
}

static void test_random_bad_params(void **state)
{
	(void)state;
	params[0].memref.buffer = out;
	params[0].memref.size = sizeof(out);
	assert_uint_equal(generate_random(VALUE_OUTPUT, params),
			  TEE_ERROR_BAD_PARAMETERS);
	assert_uint_equal(generate_random(ENCRYPT_PARAMS, params),
			  TEE_ERROR_BAD_PARAMETERS);

	params[0].memref.buffer = NULL;
	assert_uint_equal(generate_random(MEMREF_OUTPUT, params),
			  TEE_ERROR_BAD_PARAMETERS);

	params[0].memref.buffer = out;
	params[0].memref.size = 0;
	assert_uint_equal(generate_random(MEMREF_OUTPUT, params),
			  TEE_ERROR_BAD_PARAMETERS);
}

/* cmd_symmetric_key_crypto(): sealing a key */

static void test_encrypt(void **state)
{
	(void)state;
	expect_random_handle();
	expect_key_setup(TEE_MODE_ENCRYPT, NO_FAILURE, TEE_SUCCESS);
	expect_encrypt_final(TEE_SUCCESS, KEY_SIZE, TAG_SIZE);

	assert_uint_equal(run_encrypt(), TEE_SUCCESS);
	assert_uint_equal(params[1].memref.size, HANDLE_SIZE);
	assert_uint_equal(handle[0], HANDLE_VERSION);
	assert_memory_equal(handle + HANDLE_IV, random_data, IV_SIZE);
	assert_memory_equal(handle + HANDLE_NONCE, random_data + IV_SIZE,
			    NONCE_SIZE);
	assert_memory_equal(handle + HANDLE_TAG, tag, TAG_SIZE);
	assert_uint_equal(params[2].memref.size, KEY_SIZE);
	assert_memory_equal(out, sealed_key, KEY_SIZE);
}

static void test_encrypt_setup_fails(void **state)
{
	(void)state;
	for (enum step fail = ALLOCATE_OPERATION; fail < NO_FAILURE; fail++) {
		expect_random_handle();
		expect_key_setup(TEE_MODE_ENCRYPT, fail, TEE_ERROR_GENERIC);
		assert_uint_equal(run_encrypt(), TEE_ERROR_GENERIC);
		assert_no_output();
	}
}

static void test_encrypt_final_fails(void **state)
{
	(void)state;
	expect_random_handle();
	expect_key_setup(TEE_MODE_ENCRYPT, NO_FAILURE, TEE_SUCCESS);
	expect_encrypt_final(TEE_ERROR_GENERIC, 0, 0);

	assert_uint_equal(run_encrypt(), TEE_ERROR_GENERIC);
	assert_no_output();
}

static void test_encrypt_short_tag(void **state)
{
	(void)state;
	expect_random_handle();
	expect_key_setup(TEE_MODE_ENCRYPT, NO_FAILURE, TEE_SUCCESS);
	expect_encrypt_final(TEE_SUCCESS, KEY_SIZE, TAG_SIZE - 1);

	assert_uint_equal(run_encrypt(), TEE_ERROR_SECURITY);
	assert_uint_equal(params[1].memref.size, HANDLE_SIZE);
}

static void test_encrypt_short_output(void **state)
{
	(void)state;
	expect_random_handle();
	expect_key_setup(TEE_MODE_ENCRYPT, NO_FAILURE, TEE_SUCCESS);
	expect_encrypt_final(TEE_SUCCESS, KEY_SIZE - 1, TAG_SIZE);

	assert_uint_equal(run_encrypt(), TEE_ERROR_SECURITY);
	assert_no_output();
}

/* cmd_symmetric_key_crypto(): unsealing a key */

static void test_decrypt(void **state)
{
	(void)state;
	expect_key_setup(TEE_MODE_DECRYPT, NO_FAILURE, TEE_SUCCESS);
	expect_decrypt_final(TEE_SUCCESS, KEY_SIZE);

	assert_uint_equal(run_decrypt(), TEE_SUCCESS);
	assert_uint_equal(params[2].memref.size, KEY_SIZE);
	assert_memory_equal(out, plain_key, KEY_SIZE);
	assert_uint_equal(params[1].memref.size, HANDLE_SIZE);
}

static void test_decrypt_setup_fails(void **state)
{
	(void)state;
	for (enum step fail = ALLOCATE_OPERATION; fail < NO_FAILURE; fail++) {
		expect_key_setup(TEE_MODE_DECRYPT, fail, TEE_ERROR_GENERIC);
		assert_uint_equal(run_decrypt(), TEE_ERROR_GENERIC);
		assert_no_output();
	}
}

/* Also covers a wrong tag, which fails the decryption */
static void test_decrypt_final_fails(void **state)
{
	(void)state;
	expect_key_setup(TEE_MODE_DECRYPT, NO_FAILURE, TEE_SUCCESS);
	expect_decrypt_final(TEE_ERROR_GENERIC, 0);

	assert_uint_equal(run_decrypt(), TEE_ERROR_GENERIC);
	assert_no_output();
}

static void test_decrypt_short_output(void **state)
{
	(void)state;
	expect_key_setup(TEE_MODE_DECRYPT, NO_FAILURE, TEE_SUCCESS);
	expect_decrypt_final(TEE_SUCCESS, KEY_SIZE - 1);

	assert_uint_equal(run_decrypt(), TEE_ERROR_SECURITY);
	assert_no_output();
}

static void test_decrypt_bad_handle_version(void **state)
{
	(void)state;
	handle[0] = HANDLE_VERSION + 1;
	assert_uint_equal(run_decrypt(), TEE_ERROR_BAD_PARAMETERS);
	assert_no_output();
}

/* cmd_symmetric_key_crypto(): parameter checks, before any TEE call */

static void test_crypto_bad_mode(void **state)
{
	(void)state;
	assert_uint_equal(cmd_symmetric_key_crypto(TEE_MODE_DECRYPT + 1,
						   ENCRYPT_PARAMS, params),
			  TEE_ERROR_BAD_PARAMETERS);
	assert_uint_equal(cmd_symmetric_key_crypto(TEE_MODE_DECRYPT + 1,
						   DECRYPT_PARAMS, params),
			  TEE_ERROR_BAD_PARAMETERS);
}

static void test_crypto_bad_param_types(void **state)
{
	(void)state;
	assert_uint_equal(cmd_symmetric_key_crypto(TEE_MODE_ENCRYPT,
						   DECRYPT_PARAMS, params),
			  TEE_ERROR_BAD_PARAMETERS);
	assert_uint_equal(cmd_symmetric_key_crypto(TEE_MODE_DECRYPT,
						   ENCRYPT_PARAMS, params),
			  TEE_ERROR_BAD_PARAMETERS);
	assert_uint_equal(cmd_symmetric_key_crypto(TEE_MODE_ENCRYPT, NO_PARAMS,
						   params),
			  TEE_ERROR_BAD_PARAMETERS);
	assert_no_output();
}

static void test_crypto_bad_input(void **state)
{
	(void)state;
	params[0].memref.buffer = NULL;
	assert_uint_equal(run_encrypt(), TEE_ERROR_BAD_PARAMETERS);

	params[0].memref.buffer = in;
	params[0].memref.size = MAX_BUF_SIZE + 1;
	assert_uint_equal(run_encrypt(), TEE_ERROR_BAD_PARAMETERS);
	assert_no_output();
}

static void test_crypto_bad_output(void **state)
{
	(void)state;
	params[2].memref.buffer = NULL;
	assert_uint_equal(run_encrypt(), TEE_ERROR_BAD_PARAMETERS);

	params[2].memref.buffer = out;
	params[2].memref.size = MAX_BUF_SIZE + 1;
	assert_uint_equal(run_encrypt(), TEE_ERROR_BAD_PARAMETERS);
}

static void test_crypto_bad_handle(void **state)
{
	(void)state;
	params[1].memref.buffer = NULL;
	assert_uint_equal(run_encrypt(), TEE_ERROR_BAD_PARAMETERS);

	params[1].memref.buffer = handle;
	params[1].memref.size = HANDLE_SIZE - 1;
	assert_uint_equal(run_encrypt(), TEE_ERROR_BAD_PARAMETERS);
	params[1].memref.size = HANDLE_SIZE + 1;
	assert_uint_equal(run_decrypt(), TEE_ERROR_BAD_PARAMETERS);
	assert_uint_equal(params[2].memref.size, MAX_BUF_SIZE);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_version, setup_data),
		cmocka_unit_test_setup(test_version_bad_params, setup_data),
		cmocka_unit_test_setup(test_random, setup_data),
		cmocka_unit_test_setup(test_random_bad_params, setup_data),
		cmocka_unit_test_setup(test_encrypt, setup_encrypt),
		cmocka_unit_test_setup(test_encrypt_setup_fails, setup_encrypt),
		cmocka_unit_test_setup(test_encrypt_final_fails, setup_encrypt),
		cmocka_unit_test_setup(test_encrypt_short_tag, setup_encrypt),
		cmocka_unit_test_setup(test_encrypt_short_output,
				       setup_encrypt),
		cmocka_unit_test_setup(test_decrypt, setup_decrypt),
		cmocka_unit_test_setup(test_decrypt_setup_fails, setup_decrypt),
		cmocka_unit_test_setup(test_decrypt_final_fails, setup_decrypt),
		cmocka_unit_test_setup(test_decrypt_short_output,
				       setup_decrypt),
		cmocka_unit_test_setup(test_decrypt_bad_handle_version,
				       setup_decrypt),
		cmocka_unit_test_setup(test_crypto_bad_mode, setup_encrypt),
		cmocka_unit_test_setup(test_crypto_bad_param_types,
				       setup_encrypt),
		cmocka_unit_test_setup(test_crypto_bad_input, setup_encrypt),
		cmocka_unit_test_setup(test_crypto_bad_output, setup_encrypt),
		cmocka_unit_test_setup(test_crypto_bad_handle, setup_decrypt),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
