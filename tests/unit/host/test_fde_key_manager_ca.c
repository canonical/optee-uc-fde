/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 *
 * Tests for fde_key_manager_ca.c: the base64 helpers, and the calls to the
 * TA through the TEE Client API.
 */

#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <tee_client_api.h>

#include "fde_key_handler_ta_type.h"
#include "fde_key_manager_ca.h"

#include "fake_ta.h"

/* The RFC 4648 test vectors */
static const struct {
	const char *data;
	const char *base64;
} vectors[] = {
	{ "", "" },
	{ "f", "Zg==" },
	{ "fo", "Zm8=" },
	{ "foo", "Zm9v" },
	{ "foob", "Zm9vYg==" },
	{ "fooba", "Zm9vYmE=" },
	{ "foobar", "Zm9vYmFy" },
};

#define NUM_VECTORS (sizeof(vectors) / sizeof(vectors[0]))

/* "key!", and the same key sealed by the fake TA */
static const unsigned char key[] = { 'k', 'e', 'y', '!' };
static const unsigned char sealed[] = { 0x94, 0x9a, 0x86, 0xde };

static unsigned char in[MAX_BUF_SIZE];
static unsigned char handle[HANDLE_SIZE];
static unsigned char out[MAX_BUF_SIZE];

static int clear_buffers(void **state)
{
	(void)state;
	memset(in, 0, sizeof(in));
	memset(handle, 0, sizeof(handle));
	memset(out, 0, sizeof(out));
	return 0;
}

static void fill_handle(void)
{
	for (size_t i = 0; i < HANDLE_SIZE; i++) {
		handle[i] = (uint8_t)(FAKE_HANDLE_FIRST + i);
	}
}

/* base64_encode() and base64_decode() */

static void test_base64_encode(void **state)
{
	(void)state;
	for (size_t i = 0; i < NUM_VECTORS; i++) {
		char *base64 =
			base64_encode((const unsigned char *)vectors[i].data,
				      strlen(vectors[i].data));

		assert_non_null(base64);
		assert_string_equal(base64, vectors[i].base64);
		free(base64);
	}
}

static void test_base64_decode(void **state)
{
	(void)state;
	for (size_t i = 0; i < NUM_VECTORS; i++) {
		size_t len = 0;
		unsigned char *data = base64_decode(
			vectors[i].base64, strlen(vectors[i].base64), &len);

		assert_non_null(data);
		assert_uint_equal(len, strlen(vectors[i].data));
		assert_memory_equal(data, vectors[i].data, len);
		free(data);
	}
}

static void test_base64_binary(void **state)
{
	unsigned char data[256];
	unsigned char *decoded = NULL;
	char *base64 = NULL;
	size_t len = 0;

	(void)state;
	for (size_t i = 0; i < sizeof(data); i++) {
		data[i] = (unsigned char)i;
	}
	base64 = base64_encode(data, sizeof(data));
	assert_non_null(base64);
	decoded = base64_decode(base64, strlen(base64), &len);
	assert_non_null(decoded);
	assert_uint_equal(len, sizeof(data));
	assert_memory_equal(decoded, data, sizeof(data));
	free(decoded);
	free(base64);
}

static void test_base64_decode_invalid(void **state)
{
	size_t len = 0;

	(void)state;
	assert_null(base64_decode("Zm9v!", 5, &len));
	assert_null(base64_decode("Zm=v", 4, &len));
	assert_null(base64_decode("Zm9v====", 8, &len));
}

static void test_base64_decode_wrong_length(void **state)
{
	size_t len = 0;

	(void)state;
	assert_null(base64_decode("Zm9v", 3, &len));
	assert_null(base64_decode("Zm9v", 5, &len));
}

/* Opening and closing the TA session, in invoke_command() */

static void test_initialize_context_fails(void **state)
{
	(void)state;
	expect_uint_value(TEEC_InitializeContext, name, (uintptr_t)NULL);
	will_return_uint(TEEC_InitializeContext, TEEC_ERROR_GENERIC);

	assert_uint_equal(lock_ta(), TEEC_ERROR_GENERIC);
}

static void test_open_session_fails(void **state)
{
	(void)state;
	expect_uint_value(TEEC_InitializeContext, name, (uintptr_t)NULL);
	will_return_uint(TEEC_InitializeContext, TEEC_SUCCESS);
	expect_any(TEEC_OpenSession, destination);
	expect_any(TEEC_OpenSession, connectionMethod);
	expect_any(TEEC_OpenSession, connectionData);
	expect_any(TEEC_OpenSession, operation);
	will_return_uint(TEEC_OpenSession, TEEC_ERROR_GENERIC);
	expect_function_call(TEEC_FinalizeContext);

	assert_uint_equal(lock_ta(), TEEC_ERROR_GENERIC);
}

/* The TA commands */

static void test_encrypt_key(void **state)
{
	size_t handle_len = HANDLE_SIZE;
	size_t out_len = MAX_BUF_SIZE;

	(void)state;
	memcpy(in, key, sizeof(key));
	expect_ta_command(TA_CMD_KEY_ENCRYPT, fake_ta_encrypt, 0, TEEC_SUCCESS);

	assert_uint_equal(encrypt_key(in, sizeof(key), handle, &handle_len, out,
				      &out_len),
			  TEEC_SUCCESS);
	assert_uint_equal(out_len, sizeof(sealed));
	assert_memory_equal(out, sealed, sizeof(sealed));
	assert_uint_equal(handle_len, HANDLE_SIZE);
	assert_uint_equal(handle[0], FAKE_HANDLE_FIRST);
}

static void test_encrypt_key_fails(void **state)
{
	size_t handle_len = HANDLE_SIZE;
	size_t out_len = MAX_BUF_SIZE;

	(void)state;
	memcpy(in, key, sizeof(key));
	expect_ta_command(TA_CMD_KEY_ENCRYPT, fake_ta_encrypt, 0,
			  TEEC_ERROR_GENERIC);

	assert_uint_equal(encrypt_key(in, sizeof(key), handle, &handle_len, out,
				      &out_len),
			  TEEC_ERROR_GENERIC);
	assert_uint_equal(out_len, MAX_BUF_SIZE);
	assert_uint_equal(handle_len, HANDLE_SIZE);
}

static void test_decrypt_key(void **state)
{
	size_t out_len = MAX_BUF_SIZE;

	(void)state;
	memcpy(in, sealed, sizeof(sealed));
	fill_handle();
	expect_ta_command(TA_CMD_KEY_DECRYPT, fake_ta_decrypt, 0, TEEC_SUCCESS);

	assert_uint_equal(decrypt_key(in, sizeof(sealed), handle, HANDLE_SIZE,
				      out, &out_len),
			  TEEC_SUCCESS);
	assert_uint_equal(out_len, sizeof(key));
	assert_memory_equal(out, key, sizeof(key));
}

static void test_decrypt_key_fails(void **state)
{
	size_t out_len = MAX_BUF_SIZE;

	(void)state;
	memcpy(in, sealed, sizeof(sealed));
	fill_handle();
	expect_ta_command(TA_CMD_KEY_DECRYPT, fake_ta_decrypt, 0,
			  TEEC_ERROR_GENERIC);

	assert_uint_equal(decrypt_key(in, sizeof(sealed), handle, HANDLE_SIZE,
				      out, &out_len),
			  TEEC_ERROR_GENERIC);
	assert_uint_equal(out_len, MAX_BUF_SIZE);
}

static void test_get_ta_lock(void **state)
{
	uint32_t lock = 0;

	(void)state;
	expect_ta_command(TA_CMD_GET_LOCK, fake_ta_value, 1, TEEC_SUCCESS);
	assert_uint_equal(get_ta_lock(&lock), TEEC_SUCCESS);
	assert_uint_equal(lock, 1);

	expect_ta_command(TA_CMD_GET_LOCK, fake_ta_value, 0, TEEC_SUCCESS);
	assert_uint_equal(get_ta_lock(&lock), TEEC_SUCCESS);
	assert_uint_equal(lock, 0);
}

static void test_get_ta_lock_fails(void **state)
{
	uint32_t lock = 42;

	(void)state;
	expect_ta_command(TA_CMD_GET_LOCK, fake_ta_value, 1,
			  TEEC_ERROR_GENERIC);
	assert_uint_equal(get_ta_lock(&lock), TEEC_ERROR_GENERIC);
	assert_uint_equal(lock, 42);
}

static void test_lock_ta(void **state)
{
	(void)state;
	expect_ta_command(TA_CMD_LOCK, fake_ta_lock, 0, TEEC_SUCCESS);
	assert_uint_equal(lock_ta(), TEEC_SUCCESS);

	expect_ta_command(TA_CMD_LOCK, fake_ta_lock, 0, TEEC_ERROR_GENERIC);
	assert_uint_equal(lock_ta(), TEEC_ERROR_GENERIC);
}

static void test_generate_rng(void **state)
{
	unsigned char *buf = NULL;

	(void)state;
	expect_ta_command(TA_CMD_GEN_RANDOM, fake_ta_random, 0, TEEC_SUCCESS);

	buf = generate_rng(16);
	assert_non_null(buf);
	for (size_t i = 0; i < 16; i++) {
		assert_uint_equal(buf[i], i);
	}
	free(buf);
}

static void test_generate_rng_fails(void **state)
{
	(void)state;
	expect_ta_command(TA_CMD_GEN_RANDOM, fake_ta_random, 0,
			  TEEC_ERROR_GENERIC);
	assert_null(generate_rng(16));
}

static void test_get_ta_version(void **state)
{
	uint32_t version = 0;

	(void)state;
	expect_ta_command(TA_CMD_TA_VERSION, fake_ta_value, FDE_TA_VERSION_V1,
			  TEEC_SUCCESS);
	assert_uint_equal(get_ta_version(&version), TEEC_SUCCESS);
	assert_uint_equal(version, FDE_TA_VERSION_V1);
}

static void test_get_ta_version_fails(void **state)
{
	uint32_t version = 0;

	(void)state;
	expect_ta_command(TA_CMD_TA_VERSION, fake_ta_value, FDE_TA_VERSION_V1,
			  TEEC_ERROR_GENERIC);
	assert_uint_equal(get_ta_version(&version), TEEC_ERROR_GENERIC);
	assert_uint_equal(version, 0);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_base64_encode),
		cmocka_unit_test(test_base64_decode),
		cmocka_unit_test(test_base64_binary),
		cmocka_unit_test(test_base64_decode_invalid),
		cmocka_unit_test(test_base64_decode_wrong_length),
		cmocka_unit_test(test_initialize_context_fails),
		cmocka_unit_test(test_open_session_fails),
		cmocka_unit_test_setup(test_encrypt_key, clear_buffers),
		cmocka_unit_test_setup(test_encrypt_key_fails, clear_buffers),
		cmocka_unit_test_setup(test_decrypt_key, clear_buffers),
		cmocka_unit_test_setup(test_decrypt_key_fails, clear_buffers),
		cmocka_unit_test(test_get_ta_lock),
		cmocka_unit_test(test_get_ta_lock_fails),
		cmocka_unit_test(test_lock_ta),
		cmocka_unit_test(test_generate_rng),
		cmocka_unit_test(test_generate_rng_fails),
		cmocka_unit_test(test_get_ta_version),
		cmocka_unit_test(test_get_ta_version_fails),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
