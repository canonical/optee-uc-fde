/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 *
 * Mock of OP-TEE's compiler.h
 */

#ifndef MOCK_COMPILER_H
#define MOCK_COMPILER_H

#define __maybe_unused __attribute__((unused))
#define __printf(a, b) __attribute__((format(printf, a, b)))

#endif /* MOCK_COMPILER_H */
