/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 *
 * Mock of OP-TEE's tee_api_types.h, GP TEE Internal Core API 1.3.1
 */

#ifndef MOCK_TEE_API_TYPES_H
#define MOCK_TEE_API_TYPES_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <compiler.h>
#include <tee_api_defines.h>

typedef uint32_t TEE_Result;

typedef struct {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
} TEE_UUID;

typedef union {
	struct {
		void *buffer;
		size_t size;
	} memref;
	struct {
		uint32_t a;
		uint32_t b;
	} value;
} TEE_Param;

typedef struct __TEE_TASessionHandle *TEE_TASessionHandle;
typedef struct __TEE_ObjectHandle *TEE_ObjectHandle;
typedef struct __TEE_OperationHandle *TEE_OperationHandle;

typedef uint32_t TEE_ObjectType;

typedef struct {
	uint32_t attributeID;
	union {
		struct {
			void *buffer;
			size_t length;
		} ref;
		struct {
			uint32_t a, b;
		} value;
	} content;
} TEE_Attribute;

typedef uint32_t TEE_OperationMode;

#endif /* MOCK_TEE_API_TYPES_H */
