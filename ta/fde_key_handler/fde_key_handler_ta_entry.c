/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2025, Canonical Ltd.
 */

#include <trace.h>

#include "fde_key_handler_ta_type.h"
#include "fde_key_handler_ta_handle.h"

// TA lock status
static int _ta_lock;

static TEE_Result lock_ta( uint32_t paramTypes,
                           TEE_Param params[TEE_NUM_PARAMS]);
static TEE_Result get_ta_lock( uint32_t paramTypes,
                               TEE_Param params[TEE_NUM_PARAMS]);


TEE_Result TA_CreateEntryPoint(void) {
    DMSG("fde_key_handler: TA_CreateEntryPoint\n");
    _ta_lock = TA_UNLOCKED;
    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint( uint32_t paramTypes,
                               TEE_Param __maybe_unused params[TEE_NUM_PARAMS],
                               void **session_context) {

    session_ctx_t *ctx;
    DMSG("fde_key_handler: TA_OpenSessionEntryPoint\n");
    (void)paramTypes;
    ctx = TEE_Malloc(sizeof(*ctx), TEE_MALLOC_FILL_ZERO);
    if (!ctx) return TEE_ERROR_OUT_OF_MEMORY;

    ctx->key_pair  = TEE_HANDLE_NULL;
    ctx->key_ready = false;

    *session_context = ctx;
    DMSG("fde_key_handler: session opened");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint( void *session_context) {

    session_ctx_t *ctx;
    DMSG("fde_key_handler: TA_CloseSessionEntryPoint\n");
    ctx = (session_ctx_t *)session_context;
    if (ctx) {
        if (ctx->key_pair != TEE_HANDLE_NULL)
            TEE_FreeTransientObject(ctx->key_pair);
        TEE_Free(ctx);
    }
    DMSG("fde_key_handler: session closed – key material zeroised");
}

void TA_DestroyEntryPoint(void) {
    DMSG("fde_key_handler: TA_DestroyEntryPoint\n");
}

TEE_Result TA_InvokeCommandEntryPoint( void *session_context,
                                       uint32_t cmd_id,
                                       uint32_t paramTypes,
                                       TEE_Param params[TEE_NUM_PARAMS]) {

    session_ctx_t *ctx;
    DLOG("FDE cmd_id = %#"PRIx32"\n", cmd_id);
    ctx = (session_ctx_t *)session_context;

    switch (cmd_id) {
        case TA_CMD_KEY_ENCRYPT:
            return cmd_symmetric_key_crypto(TEE_MODE_ENCRYPT, paramTypes, params);
        case TA_CMD_KEY_DECRYPT:
            // make sure crypto opperations are not locked
            if ( _ta_lock == TA_LOCKED) {
                EMSG("fde_key_handler: TA is locked for further decrypt oprerations!!");
                return TEE_ERROR_ACCESS_DENIED;
            }
            return cmd_symmetric_key_crypto(TEE_MODE_DECRYPT, paramTypes, params);
        case TA_CMD_LOCK:
            return lock_ta(paramTypes, params);
        case TA_CMD_GET_LOCK:
            return get_ta_lock(paramTypes, params);
        case TA_CMD_GEN_RANDOM:
            return generate_random(paramTypes, params);
        case TA_CMD_TA_VERSION:
            return get_ta_version(paramTypes, params);
        /* Asynchronous crypto functions */
        case TA_CMD_ASYMMETRIC_DERIVE_KEYPAIR:
            return cmd_asymmetric_derive_keypair(ctx, paramTypes, params);
        case TA_CMD_ASYMMETRIC_SIGN:
            return cmd_asymmetric_sign(ctx, paramTypes, params);
case TA_CMD_ASYMMETRIC_DECRYPT:
            return cmd_asymmetric_decrypt(ctx, paramTypes, params);
        case TA_CMD_ASYMMETRIC_GET_PUBKEY:
            return cmd_asymmetric_get_pubkey(ctx, paramTypes, params);
        default:
            EMSG("fde_key_handler: Command ID %#"PRIx32" is not supported", cmd_id);
            return TEE_ERROR_NOT_SUPPORTED;
    }
}

static TEE_Result lock_ta( uint32_t paramTypes,
                           TEE_Param params[TEE_NUM_PARAMS]) {

    UNUSED(params);
    if (paramTypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;

    DMSG("fde_key_handler: Locking TA for further use\n");
    _ta_lock = TA_LOCKED;
    return TEE_SUCCESS;
}

static TEE_Result get_ta_lock( uint32_t paramTypes,
                               TEE_Param params[TEE_NUM_PARAMS]) {

    if (paramTypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;

    params[0].value.a = _ta_lock;
    return TEE_SUCCESS;
}
