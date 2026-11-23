/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 *
 * Tests for fde_key_handler_ta_entry.c: command dispatch and the TA lock.
 */

#include <cmocka.h>

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

/* Fakes for the commands in fde_key_handler_ta_handle.c */

TEE_Result cmd_symmetric_key_crypto(TEE_OperationMode mode,
				    unsigned int paramTypes,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	check_expected_uint(mode);
	check_expected_uint(paramTypes);
	check_expected_ptr(params);
	return (TEE_Result)mock_uint();
}

TEE_Result generate_random(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	check_expected_uint(types);
	check_expected_ptr(params);
	return (TEE_Result)mock_uint();
}

TEE_Result get_ta_version(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	check_expected_uint(types);
	check_expected_ptr(params);
	return (TEE_Result)mock_uint();
}

static void expect_crypto(TEE_OperationMode mode, uint32_t types,
			  TEE_Param *params, TEE_Result res)
{
	expect_uint_value(cmd_symmetric_key_crypto, mode, mode);
	expect_uint_value(cmd_symmetric_key_crypto, paramTypes, types);
	expect_uint_value(cmd_symmetric_key_crypto, params, (uintptr_t)params);
	will_return_uint(cmd_symmetric_key_crypto, res);
}

static void expect_generate_random(TEE_Param *params, TEE_Result res)
{
	expect_uint_value(generate_random, types, MEMREF_OUTPUT);
	expect_uint_value(generate_random, params, (uintptr_t)params);
	will_return_uint(generate_random, res);
}

static void expect_get_ta_version(TEE_Param *params, TEE_Result res)
{
	expect_uint_value(get_ta_version, types, VALUE_OUTPUT);
	expect_uint_value(get_ta_version, params, (uintptr_t)params);
	will_return_uint(get_ta_version, res);
}

static TEE_Result invoke(uint32_t cmd, uint32_t types, TEE_Param *params)
{
	return TA_InvokeCommandEntryPoint(NULL, cmd, types, params);
}

static uint32_t get_lock_status(void)
{
	TEE_Param params[TEE_NUM_PARAMS] = { 0 };

	assert_uint_equal(invoke(TA_CMD_GET_LOCK, VALUE_OUTPUT, params),
			  TEE_SUCCESS);
	return params[0].value.a;
}

/* Every test starts with a newly created, so unlocked, TA */
static int create_ta(void **state)
{
	(void)state;
	assert_uint_equal(TA_CreateEntryPoint(), TEE_SUCCESS);
	return 0;
}

static void test_session(void **state)
{
	TEE_Param params[TEE_NUM_PARAMS] = { 0 };
	void *session = NULL;

	(void)state;
	assert_uint_equal(TA_OpenSessionEntryPoint(NO_PARAMS, params, &session),
			  TEE_SUCCESS);
	TA_CloseSessionEntryPoint(session);
	TA_DestroyEntryPoint();
}

static void test_encrypt(void **state)
{
	TEE_Param params[TEE_NUM_PARAMS] = { 0 };

	(void)state;
	expect_crypto(TEE_MODE_ENCRYPT, ENCRYPT_PARAMS, params, TEE_SUCCESS);
	assert_uint_equal(invoke(TA_CMD_KEY_ENCRYPT, ENCRYPT_PARAMS, params),
			  TEE_SUCCESS);

	expect_crypto(TEE_MODE_ENCRYPT, ENCRYPT_PARAMS, params,
		      TEE_ERROR_SECURITY);
	assert_uint_equal(invoke(TA_CMD_KEY_ENCRYPT, ENCRYPT_PARAMS, params),
			  TEE_ERROR_SECURITY);
}

static void test_decrypt(void **state)
{
	TEE_Param params[TEE_NUM_PARAMS] = { 0 };

	(void)state;
	expect_crypto(TEE_MODE_DECRYPT, DECRYPT_PARAMS, params, TEE_SUCCESS);
	assert_uint_equal(invoke(TA_CMD_KEY_DECRYPT, DECRYPT_PARAMS, params),
			  TEE_SUCCESS);

	expect_crypto(TEE_MODE_DECRYPT, DECRYPT_PARAMS, params,
		      TEE_ERROR_SECURITY);
	assert_uint_equal(invoke(TA_CMD_KEY_DECRYPT, DECRYPT_PARAMS, params),
			  TEE_ERROR_SECURITY);
}

static void test_generate_random(void **state)
{
	TEE_Param params[TEE_NUM_PARAMS] = { 0 };

	(void)state;
	expect_generate_random(params, TEE_SUCCESS);
	assert_uint_equal(invoke(TA_CMD_GEN_RANDOM, MEMREF_OUTPUT, params),
			  TEE_SUCCESS);

	expect_generate_random(params, TEE_ERROR_OUT_OF_MEMORY);
	assert_uint_equal(invoke(TA_CMD_GEN_RANDOM, MEMREF_OUTPUT, params),
			  TEE_ERROR_OUT_OF_MEMORY);
}

static void test_get_ta_version(void **state)
{
	TEE_Param params[TEE_NUM_PARAMS] = { 0 };

	(void)state;
	expect_get_ta_version(params, TEE_SUCCESS);
	assert_uint_equal(invoke(TA_CMD_TA_VERSION, VALUE_OUTPUT, params),
			  TEE_SUCCESS);

	expect_get_ta_version(params, TEE_ERROR_BAD_PARAMETERS);
	assert_uint_equal(invoke(TA_CMD_TA_VERSION, VALUE_OUTPUT, params),
			  TEE_ERROR_BAD_PARAMETERS);
}

static void test_unknown_command(void **state)
{
	TEE_Param params[TEE_NUM_PARAMS] = { 0 };

	(void)state;
	assert_uint_equal(invoke(0, NO_PARAMS, params),
			  TEE_ERROR_NOT_SUPPORTED);
	assert_uint_equal(invoke(TA_CMD_TA_VERSION + 1, NO_PARAMS, params),
			  TEE_ERROR_NOT_SUPPORTED);
}

static void test_starts_unlocked(void **state)
{
	(void)state;
	assert_uint_equal(get_lock_status(), TA_UNLOCKED);
}

static void test_lock(void **state)
{
	TEE_Param params[TEE_NUM_PARAMS] = { 0 };

	(void)state;
	assert_uint_equal(invoke(TA_CMD_LOCK, NO_PARAMS, params), TEE_SUCCESS);
	assert_uint_equal(get_lock_status(), TA_LOCKED);

	/* Locking again keeps it locked */
	assert_uint_equal(invoke(TA_CMD_LOCK, NO_PARAMS, params), TEE_SUCCESS);
	assert_uint_equal(get_lock_status(), TA_LOCKED);
}

static void test_lock_bad_params(void **state)
{
	TEE_Param params[TEE_NUM_PARAMS] = { 0 };

	(void)state;
	assert_uint_equal(invoke(TA_CMD_LOCK, VALUE_OUTPUT, params),
			  TEE_ERROR_BAD_PARAMETERS);
	assert_uint_equal(get_lock_status(), TA_UNLOCKED);
}

static void test_get_lock_bad_params(void **state)
{
	TEE_Param params[TEE_NUM_PARAMS] = { 0 };

	(void)state;
	params[0].value.a = 0xdead;
	assert_uint_equal(invoke(TA_CMD_GET_LOCK, NO_PARAMS, params),
			  TEE_ERROR_BAD_PARAMETERS);
	assert_uint_equal(params[0].value.a, 0xdead);
}

/* No decrypt is expected, so the fake fails the test if it's called */
static void test_locked_denies_decrypt(void **state)
{
	TEE_Param params[TEE_NUM_PARAMS] = { 0 };

	(void)state;
	assert_uint_equal(invoke(TA_CMD_LOCK, NO_PARAMS, params), TEE_SUCCESS);
	assert_uint_equal(invoke(TA_CMD_KEY_DECRYPT, DECRYPT_PARAMS, params),
			  TEE_ERROR_ACCESS_DENIED);
}

static void test_locked_allows_other_commands(void **state)
{
	TEE_Param params[TEE_NUM_PARAMS] = { 0 };

	(void)state;
	assert_uint_equal(invoke(TA_CMD_LOCK, NO_PARAMS, params), TEE_SUCCESS);

	expect_crypto(TEE_MODE_ENCRYPT, ENCRYPT_PARAMS, params, TEE_SUCCESS);
	assert_uint_equal(invoke(TA_CMD_KEY_ENCRYPT, ENCRYPT_PARAMS, params),
			  TEE_SUCCESS);
	expect_generate_random(params, TEE_SUCCESS);
	assert_uint_equal(invoke(TA_CMD_GEN_RANDOM, MEMREF_OUTPUT, params),
			  TEE_SUCCESS);
	expect_get_ta_version(params, TEE_SUCCESS);
	assert_uint_equal(invoke(TA_CMD_TA_VERSION, VALUE_OUTPUT, params),
			  TEE_SUCCESS);
}

static void test_create_unlocks(void **state)
{
	TEE_Param params[TEE_NUM_PARAMS] = { 0 };

	(void)state;
	assert_uint_equal(invoke(TA_CMD_LOCK, NO_PARAMS, params), TEE_SUCCESS);
	assert_uint_equal(TA_CreateEntryPoint(), TEE_SUCCESS);
	assert_uint_equal(get_lock_status(), TA_UNLOCKED);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_session, create_ta),
		cmocka_unit_test_setup(test_encrypt, create_ta),
		cmocka_unit_test_setup(test_decrypt, create_ta),
		cmocka_unit_test_setup(test_generate_random, create_ta),
		cmocka_unit_test_setup(test_get_ta_version, create_ta),
		cmocka_unit_test_setup(test_unknown_command, create_ta),
		cmocka_unit_test_setup(test_starts_unlocked, create_ta),
		cmocka_unit_test_setup(test_lock, create_ta),
		cmocka_unit_test_setup(test_lock_bad_params, create_ta),
		cmocka_unit_test_setup(test_get_lock_bad_params, create_ta),
		cmocka_unit_test_setup(test_locked_denies_decrypt, create_ta),
		cmocka_unit_test_setup(test_locked_allows_other_commands,
				       create_ta),
		cmocka_unit_test_setup(test_create_unlocks, create_ta),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
