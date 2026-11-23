/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 *
 * Mock of OP-TEE's string_ext.h
 */

#ifndef MOCK_STRING_EXT_H
#define MOCK_STRING_EXT_H

#include <stddef.h>

void memzero_explicit(void *s, size_t count);

#endif /* MOCK_STRING_EXT_H */
