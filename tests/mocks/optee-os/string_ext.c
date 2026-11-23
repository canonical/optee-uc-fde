/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 *
 * Real implementation of memzero_explicit() from the mock string_ext.h, so
 * code under test really clears its buffers.
 */

#include <string.h>

#include <string_ext.h>

void memzero_explicit(void *s, size_t count)
{
	memset(s, 0, count);
	/* Stop the compiler from dropping the memset() */
	__asm__ volatile("" : : "r"(s) : "memory");
}
