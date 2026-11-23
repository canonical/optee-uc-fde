/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 *
 * Mock of optee_client's tee_client_api.h, GP TEE Client API
 */

#ifndef MOCK_TEE_CLIENT_API_H
#define MOCK_TEE_CLIENT_API_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TEEC_CONFIG_PAYLOAD_REF_COUNT 4

#define TEEC_NONE 0x00000000
#define TEEC_VALUE_OUTPUT 0x00000002
#define TEEC_MEMREF_TEMP_INPUT 0x00000005
#define TEEC_MEMREF_TEMP_OUTPUT 0x00000006

#define TEEC_SUCCESS 0x00000000
#define TEEC_ERROR_GENERIC 0xFFFF0000

#define TEEC_LOGIN_PUBLIC 0x00000000

#define TEEC_ORIGIN_TRUSTED_APP 0x00000004

#define TEEC_PARAM_TYPES(p0, p1, p2, p3) \
	((p0) | ((p1) << 4) | ((p2) << 8) | ((p3) << 12))

typedef uint32_t TEEC_Result;

typedef struct {
	/* Implementation defined */
	struct {
		int fd;
	} imp;
} TEEC_Context;

typedef struct {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
} TEEC_UUID;

typedef struct {
	void *buffer;
	size_t size;
} TEEC_TempMemoryReference;

typedef struct {
	uint32_t a;
	uint32_t b;
} TEEC_Value;

typedef union {
	TEEC_TempMemoryReference tmpref;
	TEEC_Value value;
} TEEC_Parameter;

typedef struct {
	/* Implementation defined */
	struct {
		TEEC_Context *ctx;
		uint32_t session_id;
	} imp;
} TEEC_Session;

typedef struct {
	uint32_t started;
	uint32_t paramTypes;
	TEEC_Parameter params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
	/* Implementation defined */
	struct {
		TEEC_Session *session;
	} imp;
} TEEC_Operation;

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context);
void TEEC_FinalizeContext(TEEC_Context *context);

TEEC_Result TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session,
			     const TEEC_UUID *destination,
			     uint32_t connectionMethod,
			     const void *connectionData,
			     TEEC_Operation *operation, uint32_t *returnOrigin);
void TEEC_CloseSession(TEEC_Session *session);

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t commandID,
			       TEEC_Operation *operation,
			       uint32_t *returnOrigin);

#endif /* MOCK_TEE_CLIENT_API_H */
