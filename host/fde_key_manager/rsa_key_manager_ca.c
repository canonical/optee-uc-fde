/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2025, Canonical Ltd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>

#include "base64.h"
#include "fde_key_handler_ta_type.h"
#include "rsa_key_manager_ca.h"

/* -----------------------------------------------------------------------
 * Session management
 * ----------------------------------------------------------------------- */

TEEC_Result rsa_open_session(rsa_session_t *sess)
{
    TEEC_Result ret;
    TEEC_UUID svc_id = FDE_KEY_HANDLER_UUID_ID;
    uint32_t origin;

    ret = TEEC_InitializeContext(NULL, &sess->context);
    if (ret != TEEC_SUCCESS) {
        fprintf(stderr, "TEEC_InitializeContext fail, result=0x%x\n", ret);
        return ret;
    }

    ret = TEEC_OpenSession(&sess->context, &sess->session, &svc_id,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (ret != TEEC_SUCCESS) {
        fprintf(stderr, "TEEC_OpenSession failed, result=0x%x, origin=0x%x\n",
                ret, origin);
        TEEC_FinalizeContext(&sess->context);
    }
    return ret;
}

void rsa_close_session(rsa_session_t *sess)
{
    TEEC_CloseSession(&sess->session);
    TEEC_FinalizeContext(&sess->context);
}

static TEEC_Result invoke_asym(rsa_session_t *sess, uint32_t cmd_id,
                               TEEC_Operation *op)
{
    uint32_t origin;
    TEEC_Result ret = TEEC_InvokeCommand(&sess->session, cmd_id, op, &origin);
    if (ret != TEEC_SUCCESS)
        fprintf(stderr,
                "TEEC_InvokeCommand(cmd=0x%x) fail, result=0x%x, origin=0x%x\n",
                cmd_id, ret, origin);
    return ret;
}

/* -----------------------------------------------------------------------
 * TA command wrappers
 * ----------------------------------------------------------------------- */

TEEC_Result rsa_derive_keypair(rsa_session_t *sess,
                               const unsigned char *seed, size_t seed_len,
                               uint32_t algo, uint32_t key_bits,
                               unsigned char *pubkey_buf, size_t *pubkey_len)
{
    TEEC_Operation op;
    TEEC_Result ret;

    memset(&op, 0, sizeof(op));
    op.started    = 1;
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)seed;
    op.params[0].tmpref.size   = seed_len;
    op.params[1].value.a       = algo;
    op.params[1].value.b       = key_bits;
    op.params[2].tmpref.buffer = pubkey_buf;
    op.params[2].tmpref.size   = *pubkey_len;

    ret = invoke_asym(sess, TA_CMD_ASYMMETRIC_DERIVE_KEYPAIR, &op);
    if (ret == TEEC_SUCCESS)
        *pubkey_len = op.params[2].tmpref.size;
    return ret;
}

TEEC_Result rsa_get_pubkey(rsa_session_t *sess,
                           unsigned char *pubkey_buf, size_t *pubkey_len)
{
    TEEC_Operation op;
    TEEC_Result ret;

    memset(&op, 0, sizeof(op));
    op.started    = 1;
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = pubkey_buf;
    op.params[0].tmpref.size   = *pubkey_len;

    ret = invoke_asym(sess, TA_CMD_ASYMMETRIC_GET_PUBKEY, &op);
    if (ret == TEEC_SUCCESS)
        *pubkey_len = op.params[0].tmpref.size;
    return ret;
}

TEEC_Result rsa_sign(rsa_session_t *sess,
                     const unsigned char *data, size_t data_len,
                     unsigned char *sig_buf, size_t *sig_len)
{
    TEEC_Operation op;
    TEEC_Result ret;

    memset(&op, 0, sizeof(op));
    op.started    = 1;
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)data;
    op.params[0].tmpref.size   = data_len;
    op.params[1].tmpref.buffer = sig_buf;
    op.params[1].tmpref.size   = *sig_len;

    ret = invoke_asym(sess, TA_CMD_ASYMMETRIC_SIGN, &op);
    if (ret == TEEC_SUCCESS)
        *sig_len = op.params[1].tmpref.size;
    return ret;
}

TEEC_Result rsa_decrypt(rsa_session_t *sess,
                        const unsigned char *ct, size_t ct_len,
                        unsigned char *pt, size_t *pt_len)
{
    TEEC_Operation op;
    TEEC_Result ret;

    memset(&op, 0, sizeof(op));
    op.started    = 1;
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)ct;
    op.params[0].tmpref.size   = ct_len;
    op.params[1].tmpref.buffer = pt;
    op.params[1].tmpref.size   = *pt_len;

    ret = invoke_asym(sess, TA_CMD_ASYMMETRIC_DECRYPT, &op);
    if (ret == TEEC_SUCCESS)
        *pt_len = op.params[1].tmpref.size;
    return ret;
}

/* -----------------------------------------------------------------------
 * Dynamic base64 helpers
 *
 * These call mbedtls_base64_* with a size-probe first pass so the output
 * buffer is always large enough, regardless of the blob size.
 * ----------------------------------------------------------------------- */

char *rsa_b64_encode(const unsigned char *buf, size_t len)
{
    size_t out_len = 0;
    unsigned char dummy;
    char *out;

    /* Probe: get the required encoded length */
    mbedtls_base64_encode(&dummy, 0, &out_len, buf, len);

    out = malloc(out_len + 1);
    if (!out)
        return NULL;

    if (mbedtls_base64_encode((unsigned char *)out, out_len + 1,
                              &out_len, buf, len) != 0) {
        free(out);
        return NULL;
    }
    out[out_len] = '\0';
    return out;
}

unsigned char *rsa_b64_decode(const char *str, size_t *out_len)
{
    size_t needed = 0;
    unsigned char *out;
    const unsigned char *src = (const unsigned char *)str;
    size_t src_len = strlen(str);

    /* Probe: pass NULL dst so mbedtls returns the required length */
    mbedtls_base64_decode(NULL, 0, &needed, src, src_len);
    if (needed == 0)
        needed = 1;

    out = malloc(needed);
    if (!out)
        return NULL;

    if (mbedtls_base64_decode(out, needed, out_len, src, src_len) != 0) {
        free(out);
        return NULL;
    }
    return out;
}
