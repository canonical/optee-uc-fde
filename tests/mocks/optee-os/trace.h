/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 *
 * Mock of OP-TEE's trace.h
 */

#ifndef MOCK_TRACE_H
#define MOCK_TRACE_H

#include <stdbool.h>
#include <stddef.h>

#include <compiler.h>

#define TRACE_ERROR 1
#define TRACE_DEBUG 3

void trace_printf(const char *func, int line, int level, bool level_ok,
		  const char *fmt, ...) __printf(5, 6);

#define EMSG(...) \
	trace_printf(__func__, __LINE__, TRACE_ERROR, true, __VA_ARGS__)
#define DMSG(...) \
	trace_printf(__func__, __LINE__, TRACE_DEBUG, true, __VA_ARGS__)
#define MSG_RAW(...) trace_printf(NULL, 0, 0, false, __VA_ARGS__)

#endif /* MOCK_TRACE_H */
