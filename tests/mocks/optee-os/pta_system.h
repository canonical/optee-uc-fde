/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 *
 * Mock of OP-TEE's pta_system.h
 */

#ifndef MOCK_PTA_SYSTEM_H
#define MOCK_PTA_SYSTEM_H

#define PTA_SYSTEM_UUID \
	{ 0x3a2f8978,   \
	  0x5dc0,       \
	  0x11e8,       \
	  { 0x9c, 0x2d, 0xfa, 0x7a, 0xe0, 0x1b, 0xbe, 0xbc } }

#define TA_DERIVED_KEY_MAX_SIZE 32

#define PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY 1

#endif /* MOCK_PTA_SYSTEM_H */
