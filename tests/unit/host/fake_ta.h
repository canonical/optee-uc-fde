/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 *
 * A fake fde_key_handler TA for the host tests, called through the mock TEE
 * Client API. Its "sealing" flips every bit of the key, and its handles and
 * random data are counting patterns, so tests can predict all its outputs.
 */

#ifndef FAKE_TA_H
#define FAKE_TA_H

#include <stdint.h>

#include <cmocka.h>

#include <tee_client_api.h>

#include "fde_key_handler_ta_type.h"

#define FAKE_HANDLE_FIRST 0xa0

/*
 * Expect the host to open a session with the TA, invoke cmd and close the
 * session again. check is called with the TEEC_Operation and data, and
 * returns whether the operation is right: the fake_ta_*() functions below
 * also fill in the TA's outputs. The command returns res.
 */
static inline void expect_ta_command(uint32_t cmd,
				     CheckParameterValueData check,
				     uintmax_t data, TEEC_Result res)
{
	static const TEEC_UUID uuid = FDE_KEY_HANDLER_UUID_ID;

	expect_uint_value(TEEC_InitializeContext, name, (uintptr_t)NULL);
	will_return_uint(TEEC_InitializeContext, TEEC_SUCCESS);

	expect_memory(TEEC_OpenSession, destination, &uuid, sizeof(uuid));
	expect_uint_value(TEEC_OpenSession, connectionMethod,
			  TEEC_LOGIN_PUBLIC);
	expect_uint_value(TEEC_OpenSession, connectionData, (uintptr_t)NULL);
	expect_uint_value(TEEC_OpenSession, operation, (uintptr_t)NULL);
	will_return_uint(TEEC_OpenSession, TEEC_SUCCESS);

	expect_uint_value(TEEC_InvokeCommand, commandID, cmd);
	expect_check_data(TEEC_InvokeCommand, operation, check,
			  assign_uint_to_cmocka_value(data));
	will_return_uint(TEEC_InvokeCommand, res);

	expect_function_call(TEEC_CloseSession);
	expect_function_call(TEEC_FinalizeContext);
}

static inline uint8_t *tmpref_buffer(TEEC_Operation *op, int i)
{
	return op->params[i].tmpref.buffer;
}

/* TA_CMD_KEY_ENCRYPT: seal the key and return a new handle */
static inline int fake_ta_encrypt(CMockaValueData value, CMockaValueData data)
{
	TEEC_Operation *op = value.ptr;
	size_t len = op->params[0].tmpref.size;

	(void)data;
	if (op->paramTypes != TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					       TEEC_MEMREF_TEMP_OUTPUT,
					       TEEC_MEMREF_TEMP_OUTPUT,
					       TEEC_NONE) ||
	    op->params[1].tmpref.size < HANDLE_SIZE ||
	    op->params[2].tmpref.size < len) {
		return 0;
	}
	for (size_t i = 0; i < len; i++) {
		tmpref_buffer(op, 2)[i] = (uint8_t)~tmpref_buffer(op, 0)[i];
	}
	for (size_t i = 0; i < HANDLE_SIZE; i++) {
		tmpref_buffer(op, 1)[i] = (uint8_t)(FAKE_HANDLE_FIRST + i);
	}
	op->params[1].tmpref.size = HANDLE_SIZE;
	op->params[2].tmpref.size = len;
	return 1;
}

/* TA_CMD_KEY_DECRYPT: unseal a key sealed by fake_ta_encrypt() */
static inline int fake_ta_decrypt(CMockaValueData value, CMockaValueData data)
{
	TEEC_Operation *op = value.ptr;
	size_t len = op->params[0].tmpref.size;

	(void)data;
	if (op->paramTypes != TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					       TEEC_MEMREF_TEMP_INPUT,
					       TEEC_MEMREF_TEMP_OUTPUT,
					       TEEC_NONE) ||
	    op->params[1].tmpref.size != HANDLE_SIZE ||
	    op->params[2].tmpref.size < len) {
		return 0;
	}
	for (size_t i = 0; i < HANDLE_SIZE; i++) {
		if (tmpref_buffer(op, 1)[i] !=
		    (uint8_t)(FAKE_HANDLE_FIRST + i)) {
			return 0;
		}
	}
	for (size_t i = 0; i < len; i++) {
		tmpref_buffer(op, 2)[i] = (uint8_t)~tmpref_buffer(op, 0)[i];
	}
	op->params[2].tmpref.size = len;
	return 1;
}

/* TA_CMD_GEN_RANDOM: return 0, 1, 2... */
static inline int fake_ta_random(CMockaValueData value, CMockaValueData data)
{
	TEEC_Operation *op = value.ptr;

	(void)data;
	if (op->paramTypes != TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					       TEEC_NONE, TEEC_NONE,
					       TEEC_NONE)) {
		return 0;
	}
	for (size_t i = 0; i < op->params[0].tmpref.size; i++) {
		tmpref_buffer(op, 0)[i] = (uint8_t)i;
	}
	return 1;
}

/* TA_CMD_GET_LOCK and TA_CMD_TA_VERSION: return the value data */
static inline int fake_ta_value(CMockaValueData value, CMockaValueData data)
{
	TEEC_Operation *op = value.ptr;

	if (op->paramTypes != TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					       TEEC_NONE, TEEC_NONE)) {
		return 0;
	}
	op->params[0].value.a = (uint32_t)data.uint_val;
	return 1;
}

/* TA_CMD_LOCK */
static inline int fake_ta_lock(CMockaValueData value, CMockaValueData data)
{
	TEEC_Operation *op = value.ptr;

	(void)data;
	return op->paramTypes ==
	       TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
}

#endif /* FAKE_TA_H */
