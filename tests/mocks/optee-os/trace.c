/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 *
 * trace_printf() from the mock trace.h. Messages are discarded, so tests of
 * error paths don't clutter the test output.
 */

#include <trace.h>

void trace_printf(const char *func, int line, int level, bool level_ok,
		  const char *fmt, ...)
{
	(void)func;
	(void)line;
	(void)level;
	(void)level_ok;
	(void)fmt;
}
