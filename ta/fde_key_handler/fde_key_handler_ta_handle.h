/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2025, Canonical Ltd.
 */

#ifndef FDE_KEY_HANDLER_TA_HANDLE_H_
#define FDE_KEY_HANDLER_TA_HANDLE_H_

#include <tee_internal_api.h>

#define TA_UNLOCKED  0
#define TA_LOCKED    1

/* =========================================================================
 * Session context
 * ========================================================================= */

typedef struct {
    TEE_ObjectHandle  key_pair;     /* transient keypair – NULL until derived */
    uint32_t          algo;         /* ALGO_RSA | ALGO_ECDSA                  */
    uint32_t          key_bits;     /* e.g. 2048, 256                         */
    bool              key_ready;
} session_ctx_t;


extern TEE_Result cmd_symmetric_key_crypto(TEE_OperationMode mode,
                             unsigned int paramTypes,
                             TEE_Param params[TEE_NUM_PARAMS]);
extern TEE_Result generate_random(uint32_t types,
                                  TEE_Param params[TEE_NUM_PARAMS]);
extern TEE_Result get_ta_version(uint32_t types,
                                  TEE_Param params[TEE_NUM_PARAMS]);

/* Asymetric crypto operations */
extern TEE_Result cmd_asymmetric_derive_keypair(session_ctx_t *ctx,
                                               uint32_t param_types,
                                               TEE_Param params[4]);
extern TEE_Result cmd_asymmetric_sign(session_ctx_t *ctx,
                              uint32_t param_types,
                              TEE_Param params[4]);

extern TEE_Result cmd_asymmetric_decrypt(session_ctx_t *ctx,
                                 uint32_t param_types,
                                 TEE_Param params[4]);
extern TEE_Result cmd_asymmetric_get_pubkey(session_ctx_t *ctx,
                                    uint32_t param_types,
                                    TEE_Param params[4]);
#endif
