/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 *
 * cmocka fakes for the functions in the mock tee_client_api.h, see
 * tests/mocks/README.md for how to use them.
 */

#include <cmocka.h>

#include <tee_client_api.h>

/*
 * The context and session are allocated by the code under test, so tests
 * can't know their addresses: these fakes don't check them.
 */

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
	(void)context;
	check_expected_ptr(name);

	return (TEEC_Result)mock_uint();
}

void TEEC_FinalizeContext(TEEC_Context *context)
{
	(void)context;
	function_called();
}

TEEC_Result TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session,
			     const TEEC_UUID *destination,
			     uint32_t connectionMethod,
			     const void *connectionData,
			     TEEC_Operation *operation, uint32_t *returnOrigin)
{
	(void)context;
	(void)session;
	check_expected_ptr(destination);
	check_expected_uint(connectionMethod);
	check_expected_ptr(connectionData);
	check_expected_ptr(operation);

	if (returnOrigin)
		*returnOrigin = TEEC_ORIGIN_TRUSTED_APP;

	return (TEEC_Result)mock_uint();
}

void TEEC_CloseSession(TEEC_Session *session)
{
	(void)session;
	function_called();
}

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t commandID,
			       TEEC_Operation *operation,
			       uint32_t *returnOrigin)
{
	(void)session;
	check_expected_uint(commandID);
	check_expected_ptr(operation);

	if (returnOrigin)
		*returnOrigin = TEEC_ORIGIN_TRUSTED_APP;

	return (TEEC_Result)mock_uint();
}
