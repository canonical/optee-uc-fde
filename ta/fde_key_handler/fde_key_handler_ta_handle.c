/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2025, Canonical Ltd.
 */

#include <assert.h>
#include <util.h>
#include <tee_internal_api.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <tee_internal_api_extensions.h>
#include <pta_system.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>

#include "fde_key_handler_ta_type.h"
#include "fde_key_handler_ta_handle.h"

#define IV_SIZE         16
#define NONCE_SIZE      32
#define TAG_SIZE        16
#define KEY_HANDLE_VERSION 'U'

/*
 * The GP TEE Internal Core API changed the type of the length parameters of
 * TEE_AEEncryptFinal()/TEE_AEDecryptFinal() (destLen, tagLen) from uint32_t to
 * size_t. Select a matching local length type so the TA builds against any
 * supported OP-TEE version:
 *   - OP-TEE <= 3.20 expects uint32_t.
 *   - OP-TEE >= 3.21 uses size_t by default; compatibility mode selects the
 *     legacy uint32_t (__GP11) variant.
 * Select size_t only when Core API 1.3.1 or newer is exposed without compat.
 */
#if defined(TEE_CORE_API_VERSION) && TEE_CORE_API_VERSION >= 0x01030100 && \
    defined(__OPTEE_CORE_API_COMPAT_1_1) && \
    !__OPTEE_CORE_API_COMPAT_1_1
typedef size_t tee_ae_len_t;
#else
typedef uint32_t tee_ae_len_t;
#endif

// Trusted Key Handle
struct key_handle {
    uint8_t version; // reserved to recognise the version
    uint8_t iv[IV_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t tag[TAG_SIZE];
};

/**
 * Derive TA unique key
 * use passed handle as extra data for key derivation
 *  key: buffer to created key
 *  key_size: size of derived key buffer
 *  handle: buffer with handle
 *  handle_size: size handle buffer
 */
static TEE_Result derive_ta_unique_key(uint8_t *key,
                                       uint16_t key_size,
                                       uint8_t *handle,
                                       uint32_t handle_size) {

  TEE_TASessionHandle sess = TEE_HANDLE_NULL;
  TEE_Param params[TEE_NUM_PARAMS] = { };
  TEE_Result res = TEE_ERROR_GENERIC;
  uint32_t ret_orig = 0;
  uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                         TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                         TEE_PARAM_TYPE_NONE,
                                         TEE_PARAM_TYPE_NONE);

  res = TEE_OpenTASession(&(const TEE_UUID)PTA_SYSTEM_UUID,
                          TEE_TIMEOUT_INFINITE,
                          0,
                          NULL,
                          &sess,
                          &ret_orig);
  if (res) {
    return res;
  }

  if (handle && handle_size) {
    params[0].memref.buffer = handle;
    params[0].memref.size = handle_size;
  }

  params[1].memref.buffer = key;
  params[1].memref.size = key_size;

  res = TEE_InvokeTACommand(sess,
                            TEE_TIMEOUT_INFINITE,
                            PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY,
                            param_types,
                            params,
                            &ret_orig);

  TEE_CloseTASession(sess);

  return res;
}

static TEE_Result do_key_encrypt( TEE_OperationHandle crypto_op,
                                  uint8_t *key, size_t key_sz,
                                  uint8_t *enc_key, size_t *enc_key_sz,
                                  struct key_handle *handle) {

    TEE_Result res = TEE_ERROR_GENERIC;
    tee_ae_len_t tag_len = TAG_SIZE;
    tee_ae_len_t enc_key_len = *enc_key_sz;

    res = TEE_AEInit(crypto_op, handle->iv, IV_SIZE, TAG_SIZE * 8, 0, 0);
    if (res) {
      EMSG("fde_key_handler: TA init failed: %#"PRIx32"\n", res);
      return res;
    }

    res = TEE_AEEncryptFinal(crypto_op, key, key_sz, enc_key,
                            &enc_key_len, handle->tag, &tag_len);
    *enc_key_sz = enc_key_len;

    if (res || tag_len != TAG_SIZE || *enc_key_sz != key_sz) {
      EMSG("fde_key_handler: key encrypt failed: [%"PRIu32", %"PRIu32"], [%"PRIu64", %"PRIu64"], %#"PRIx32"\n",
            (uint32_t)tag_len, (uint32_t)TAG_SIZE, (uint64_t)*enc_key_sz, (uint64_t)key_sz, res);
      res = res ? res: TEE_ERROR_SECURITY;
    }

    return res;
}

static TEE_Result do_key_decrypt( TEE_OperationHandle crypto_op,
                                  uint8_t *enc_key, size_t enc_key_sz,
                                  uint8_t *key, size_t *key_sz,
                                  struct key_handle *handle) {

    TEE_Result res = TEE_ERROR_GENERIC;
    uint8_t tag[TAG_SIZE] = { 0 };
    tee_ae_len_t key_len = *key_sz;

    res = TEE_AEInit(crypto_op, handle->iv, IV_SIZE, TAG_SIZE * 8, 0, 0);
    if (res) {
      EMSG("fde_key_handler: TA init failed: %#"PRIx32"\n", res);
      return res;
    }

    memcpy(tag, handle->tag, TAG_SIZE);
    res = TEE_AEDecryptFinal(crypto_op, enc_key, enc_key_sz, key,
           &key_len, tag, TAG_SIZE);
    *key_sz = key_len;

    if (res || enc_key_sz != *key_sz) {
      EMSG("fde_key_handler: key decrypt failed: [%"PRIx64", %"PRIx64"], %#"PRIx32"\n",
           (uint64_t)enc_key_sz, (uint64_t)*key_sz, res);
      res = res ? res: TEE_ERROR_SECURITY;
    }

    return res;
}

static TEE_Result do_key_crypto( TEE_OperationMode mode,
                                 uint8_t *in, size_t in_size,
                                 uint8_t *out, size_t *out_size,
                                 struct key_handle *handle) {

    TEE_Result res = TEE_ERROR_GENERIC;
    TEE_OperationHandle crypto_op = TEE_HANDLE_NULL;
    TEE_ObjectHandle hkey = TEE_HANDLE_NULL;
    uint8_t huk_key[TA_DERIVED_KEY_MAX_SIZE] = { };
    TEE_Attribute attr = { };

    res = TEE_AllocateOperation(&crypto_op, TEE_ALG_AES_GCM, mode,
              sizeof(huk_key) * 8);
    if (res)
      return res;

    res = derive_ta_unique_key(huk_key, sizeof(huk_key), handle->nonce, sizeof(handle->nonce));
    if (res) {
      EMSG("fde_key_handler: derive_unique_key failed: returned %#"PRIx32, res);
      goto out_op;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_AES, sizeof(huk_key) * 8,
              &hkey);
    if (res)
      goto out_op;

    attr.attributeID = TEE_ATTR_SECRET_VALUE;
    attr.content.ref.buffer = huk_key;
    attr.content.ref.length = sizeof(huk_key);

    res = TEE_PopulateTransientObject(hkey, &attr, 1);
    if (res) {
      EMSG("fde_key_handler: TEE_PopulateTransientObject failed: %#"PRIx32, res);
      goto out_key;
    }

    res = TEE_SetOperationKey(crypto_op, hkey);
    if (res) {
      EMSG("fde_key_handler: TEE_SetOperationKey failed: %#"PRIx32, res);
      goto out_key;
    }

    if (mode == TEE_MODE_ENCRYPT) {
      res = do_key_encrypt(crypto_op, in, in_size, out, out_size, handle);
    } else if (mode == TEE_MODE_DECRYPT) {
      res = do_key_decrypt(crypto_op, in, in_size, out, out_size, handle);
    } else {
      TEE_Panic(0);
    }

    out_key:
      TEE_FreeTransientObject(hkey);
    out_op:
      TEE_FreeOperation(crypto_op);
      memzero_explicit(huk_key, sizeof(huk_key));
    return res;
}

TEE_Result cmd_symmetric_key_crypto( TEE_OperationMode mode,
                       unsigned int paramTypes,
                       TEE_Param params[TEE_NUM_PARAMS]) {

    TEE_Result res = TEE_SUCCESS;
    uint8_t *in = NULL;
    size_t in_size = 0;
    uint8_t *out = NULL;
    size_t out_size = 0;
    struct key_handle * handle = NULL;
    uint8_t *handle_buf = NULL;
    uint32_t handle_buf_size = 0;
    uint8_t *rng_buf = NULL;

    DMSG("fde_key_handler: Handle key crypto");

    if (mode == TEE_MODE_ENCRYPT) {
      if (paramTypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                        TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;
    } else if (mode == TEE_MODE_DECRYPT) {
      if (paramTypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                        TEE_PARAM_TYPE_MEMREF_INPUT,
                                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                        TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;
    } else {
      return TEE_ERROR_BAD_PARAMETERS;
    }

    in = params[0].memref.buffer;
    in_size = params[0].memref.size;
    handle_buf = params[1].memref.buffer;
    handle_buf_size = params[1].memref.size;
    out = params[2].memref.buffer;
    out_size = params[2].memref.size;

    if ((!in && in_size) || in_size > MAX_BUF_SIZE) {
      return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((!out && out_size) || out_size > MAX_BUF_SIZE) {
      return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((!handle_buf && handle_buf_size) || handle_buf_size != sizeof(struct key_handle)) {
      return TEE_ERROR_BAD_PARAMETERS;
    }

    handle = (struct key_handle *)handle_buf;
    // generate random iv and handle for encryption operation
    if (mode == TEE_MODE_ENCRYPT) {
      // on some plartforms we can't call TEE_GenerateRandom twice in
      // single session, generate all randomness in one go.
      rng_buf = TEE_Malloc(IV_SIZE + NONCE_SIZE, TEE_MALLOC_FILL_ZERO);
      if (!rng_buf)
        return TEE_ERROR_OUT_OF_MEMORY;

      TEE_GenerateRandom(rng_buf, IV_SIZE + NONCE_SIZE);
      memcpy(handle->iv, rng_buf, IV_SIZE);
      memcpy(handle->nonce, rng_buf + IV_SIZE, NONCE_SIZE);
      memzero_explicit(rng_buf, IV_SIZE + NONCE_SIZE);
      TEE_Free(rng_buf);
      handle->version = KEY_HANDLE_VERSION;
    } else {
      if (handle->version != KEY_HANDLE_VERSION) {
        EMSG("fde_key_handler: bad handle version %#"PRIx8, handle->version);
        return TEE_ERROR_BAD_PARAMETERS;
      }
    }

    res = do_key_crypto(mode, in, in_size, out, &out_size, handle);
    if (res == TEE_SUCCESS) {
      if (out_size != in_size) {
        EMSG("fde_key_handler: output size mismatch %"PRIu64" != %"PRIu64,
             (uint64_t)out_size, (uint64_t)in_size);
        return TEE_ERROR_SECURITY;
      }
      params[2].memref.size = out_size;
      if (mode == TEE_MODE_ENCRYPT) {
        params[1].memref.size = sizeof(struct key_handle);
      }
    }
    return res;
}

TEE_Result generate_random( uint32_t types, TEE_Param params[TEE_NUM_PARAMS]) {
    uint8_t *rng_buf = NULL;

    DMSG("fde_key_handler: generate_random");

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                 TEE_PARAM_TYPE_NONE,
                                 TEE_PARAM_TYPE_NONE,
                                 TEE_PARAM_TYPE_NONE))
      return TEE_ERROR_BAD_PARAMETERS;

    if (!params[0].memref.buffer || !params[0].memref.size)
      return TEE_ERROR_BAD_PARAMETERS;

    rng_buf = TEE_Malloc(params[0].memref.size, TEE_MALLOC_FILL_ZERO);
    if (!rng_buf)
      return TEE_ERROR_OUT_OF_MEMORY;

    TEE_GenerateRandom(rng_buf, params[0].memref.size);
    memcpy(params[0].memref.buffer, rng_buf, params[0].memref.size);
    memzero_explicit(rng_buf, params[0].memref.size);

    TEE_Free(rng_buf);

    return TEE_SUCCESS;
}

TEE_Result get_ta_version( uint32_t types, TEE_Param params[TEE_NUM_PARAMS]) {
    DMSG("get_ta_version");
    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                 TEE_PARAM_TYPE_NONE,
                                 TEE_PARAM_TYPE_NONE,
                                 TEE_PARAM_TYPE_NONE))
      return TEE_ERROR_BAD_PARAMETERS;

    params[0].value.a = FDE_TA_VERSION_V1;
    return TEE_SUCCESS;
}

/* =========================================================================
 * Asynchronous Crypto implementation
 * ========================================================================= */

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

/*
 * hkdf_sha256_extract_expand
 *
 * Minimal HKDF (RFC 5869) implementation using GP MAC + Digest APIs.
 *
 *   ikm        : input keying material (the seed)
 *   ikm_len    : seed length in bytes
 *   info       : context / application string
 *   info_len   : length of info
 *   out        : output buffer
 *   out_len    : requested output length (must be ≤ 255 * 32 bytes)
 *
 * Returns TEE_SUCCESS or a TEE error.
 */
static TEE_Result hkdf_sha256(const uint8_t *ikm,  size_t ikm_len,
                               const uint8_t *info, size_t info_len,
                               uint8_t *out, size_t out_len) {
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_ObjectHandle    prk_key = TEE_HANDLE_NULL;
    TEE_Result          res;

    /* Fixed zero salt for extract step */
    static const uint8_t zero_salt[32] = { 0 };
    uint8_t  prk[32];          /* pseudorandom key from extract step         */
    size_t prk_len = sizeof(prk);

    TEE_ObjectHandle expand_key = TEE_HANDLE_NULL;
    TEE_Attribute    prk_attr;

    uint8_t  t_prev[32] = { 0 };
    size_t   t_prev_len = 0;
    size_t   produced   = 0;
    uint8_t  ctr        = 1;

    /* ---- Extract: PRK = HMAC-SHA256(salt=zeros, IKM=seed) --------------- */
    TEE_Attribute attr;
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
                         (void *)zero_salt, sizeof(zero_salt));

    res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256,
                                      sizeof(zero_salt) * 8, &prk_key);
    if (res != TEE_SUCCESS){
      return res;
    }

    res = TEE_PopulateTransientObject(prk_key, &attr, 1);
    if (res != TEE_SUCCESS){
      goto err_prk_key;
    }

    res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256,
                                 TEE_MODE_MAC, sizeof(zero_salt) * 8);
    if (res != TEE_SUCCESS) {
      goto err_prk_key;
    }

    res = TEE_SetOperationKey(op, prk_key);
    if (res != TEE_SUCCESS) {
      goto err_op;
    }

    TEE_MACInit(op, NULL, 0);
    TEE_MACUpdate(op, (void *)ikm, ikm_len);
    res = TEE_MACComputeFinal(op, NULL, 0, prk, &prk_len);
    if (res != TEE_SUCCESS) {
      goto err_op;
    }

    TEE_FreeOperation(op);  op = TEE_HANDLE_NULL;
    TEE_FreeTransientObject(prk_key); prk_key = TEE_HANDLE_NULL;

    /* ---- Expand: T(i) = HMAC-SHA256(PRK, T(i-1) || info || i) ---------- */
    TEE_InitRefAttribute(&prk_attr, TEE_ATTR_SECRET_VALUE, prk, prk_len);

    res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256,
                                      prk_len * 8, &expand_key);
    if (res != TEE_SUCCESS) {
      goto err_clean;
    }

    res = TEE_PopulateTransientObject(expand_key, &prk_attr, 1);
    if (res != TEE_SUCCESS) {
      TEE_FreeTransientObject(expand_key);
      goto err_clean;
    }

    while (produced < out_len) {
        size_t t_len = sizeof(t_prev);
        size_t copy;

        res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256,
                                     TEE_MODE_MAC, prk_len * 8);
        if (res != TEE_SUCCESS) {
          TEE_FreeTransientObject(expand_key);
          goto err_clean;
        }

        res = TEE_SetOperationKey(op, expand_key);
        if (res != TEE_SUCCESS) {
          TEE_FreeOperation(op);
          TEE_FreeTransientObject(expand_key); goto err_clean;
        }

        TEE_MACInit(op, NULL, 0);
        if (t_prev_len > 0) {
            TEE_MACUpdate(op, t_prev, t_prev_len);
        }
        if (info_len > 0) {
            TEE_MACUpdate(op, (void *)info, info_len);
        }
        TEE_MACUpdate(op, &ctr, 1);
        res = TEE_MACComputeFinal(op, NULL, 0, t_prev, &t_len);
        TEE_FreeOperation(op);  op = TEE_HANDLE_NULL;
        if (res != TEE_SUCCESS) {
          TEE_FreeTransientObject(expand_key);
          goto err_clean;
        }

        t_prev_len = t_len;
        copy = out_len - produced;
        if (copy > t_len) {
          copy = t_len;
        }
        TEE_MemMove(out + produced, t_prev, copy);
        produced += copy;
        ctr++;
    }

    TEE_FreeTransientObject(expand_key);
    TEE_MemFill(prk, 0, sizeof(prk));
    return TEE_SUCCESS;

err_op:
    if (op != TEE_HANDLE_NULL) {
      TEE_FreeOperation(op);
    }
err_prk_key:
    if (prk_key != TEE_HANDLE_NULL) {
      TEE_FreeTransientObject(prk_key);
    }
err_clean:
    TEE_MemFill(prk, 0, sizeof(prk));
    return res;
}

/* =========================================================================
 * Key derivation
 * ========================================================================= */

/*
 * build_kdf_info — assemble an HKDF info label as prefix || key_bits (BE32).
 *
 * The key size must be part of the label: HKDF-Expand output for a shorter
 * request is a prefix of the output for a longer one with the same info, so
 * without this, keys of different sizes derived from the same seed would
 * share their top bytes (e.g. the RSA-2048 prime candidate would equal the
 * high half of the RSA-4096 one, and compromise of one key would reveal
 * enough bits of the other to factor it).
 *
 * Returns the total label length; 'buf' must hold strlen(prefix) + 4 bytes.
 */
#define KDF_INFO_MAX_LEN 40

static size_t build_kdf_info(uint8_t *buf, size_t buf_sz,
                             const char *prefix, uint32_t key_bits)
{
    size_t plen = strlen(prefix);

    assert(plen + 4 <= buf_sz);
    TEE_MemMove(buf, prefix, plen);
    buf[plen + 0] = (uint8_t)(key_bits >> 24);
    buf[plen + 1] = (uint8_t)(key_bits >> 16);
    buf[plen + 2] = (uint8_t)(key_bits >> 8);
    buf[plen + 3] = (uint8_t)(key_bits);
    return plen + 4;
}

/*
 * bigint_alloc — allocate and initialise a TEE_BigInt for 'bits' bits.
 * Returns NULL on OOM.  Caller must call bigint_free() when done.
 */
static TEE_BigInt *bigint_alloc(uint32_t bits)
{
    uint32_t nw = TEE_BigIntSizeInU32(bits);
    TEE_BigInt *bi = TEE_Malloc(nw * sizeof(uint32_t), TEE_MALLOC_FILL_ZERO);
    if (bi)
        TEE_BigIntInit(bi, nw);
    return bi;
}

/*
 * bigint_free — zero-wipe and free a TEE_BigInt.
 * 'bits' must match what was passed to bigint_alloc().
 */
static void bigint_free(TEE_BigInt *bi, uint32_t bits)
{
    if (!bi)
        return;
    TEE_MemFill(bi, 0, TEE_BigIntSizeInU32(bits) * sizeof(uint32_t));
    TEE_Free(bi);
}

/*
 * derive_prime — find a probable prime of exactly 'bits' bits,
 * deterministically from (seed, label).
 *
 * Algorithm:
 *   1. Use HKDF-SHA256(seed, label) to produce an initial odd candidate.
 *   2. Force top 2 bits set — ensures bit-length is exactly 'bits', and that
 *      p×q spans the full 2×'bits' bit-width.
 *   3. Walk upward by +2 (staying odd) until TEE_BigIntIsProbablePrime passes.
 *
 * 'out' must be pre-allocated with at least (bits + 64) bit capacity to
 * absorb the upward walk without overflow.
 *
 * Average number of candidates before a prime is found ≈ bits×ln(2)/2.
 * RSA_PRIME_SEARCH_MAX is a safety cap; in practice it is never reached.
 */
#define RSA_PRIME_SEARCH_MAX 65536U

static TEE_Result derive_prime(const uint8_t *seed, size_t seed_len,
                               uint32_t bits,
                               const uint8_t *label, size_t label_len,
                               TEE_BigInt *out)
{
    TEE_Result  res;
    uint32_t    nbytes = bits / 8;
    uint8_t    *cand   = NULL;
    TEE_BigInt *two    = NULL;
    uint32_t    iter;

    cand = TEE_Malloc(nbytes, TEE_MALLOC_FILL_ZERO);
    if (!cand)
        return TEE_ERROR_OUT_OF_MEMORY;

    two = bigint_alloc(8);
    if (!two) {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto out;
    }
    TEE_BigIntConvertFromS32(two, 2);

    res = hkdf_sha256(seed, seed_len, label, label_len, cand, nbytes);
    if (res != TEE_SUCCESS)
        goto out;

    cand[0]         |= 0xC0; /* set top 2 bits → correct bit-length for p×q */
    cand[nbytes - 1] |= 0x01; /* set LSB → odd                               */

    res = TEE_BigIntConvertFromOctetString(out, cand, nbytes, 0);
    if (res != TEE_SUCCESS)
        goto out;

    for (iter = 0; iter < RSA_PRIME_SEARCH_MAX; iter++) {
        if (TEE_BigIntIsProbablePrime(out, 80)) {
            res = TEE_SUCCESS;
            goto out;
        }
        TEE_BigIntAdd(out, out, two);
    }

    EMSG("seed_crypto_ta: prime search exhausted after %u steps",
         RSA_PRIME_SEARCH_MAX);
    res = TEE_ERROR_GENERIC;

out:
    if (cand) {
        TEE_MemFill(cand, 0, nbytes);
        TEE_Free(cand);
    }
    bigint_free(two, 8);
    return res;
}

/*
 * derive_huk_bound_seed
 *
 * Mixes the caller-supplied seed with device-unique material that only this
 * TA on this specific device can access (the Hardware Unique Key, via
 * PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY).
 *
 * Result: bound_seed = KDF(HUK, TA_UUID, user_seed)
 *
 * Properties:
 *  - Same seed + same device  → same bound_seed  (reproducible on-device)
 *  - Same seed + other device → different bound_seed (device-binding)
 *  - Knowing only the user seed is not sufficient to reproduce the keypair
 *    on any device other than the originating one.
 *
 * The output buffer is always HUK_BOUND_SEED_LEN bytes.  The user seed is
 * passed as the "extra data" diversifier to the PTA so that different seeds
 * produce different bound material even on the same device.
 */
#define HUK_BOUND_SEED_LEN  32u

static TEE_Result derive_huk_bound_seed(const uint8_t *seed, size_t seed_len,
                                        uint8_t bound[HUK_BOUND_SEED_LEN])
{
    return derive_ta_unique_key(bound, HUK_BOUND_SEED_LEN,
                                (uint8_t *)seed, (uint32_t)seed_len);
}

/*
 * derive_rsa_keypair — fully deterministic, device-bound RSA key construction.
 *
 * The user seed is first bound to the device HUK via derive_huk_bound_seed(),
 * then all RSA parameters are derived from that bound seed using HKDF and
 * TEE BigInt arithmetic.  No platform RNG is used.
 *
 * Steps:
 *   0. bound_seed = KDF(HUK, TA_UUID, user_seed)
 *   1. Derive prime p  via HKDF(bound_seed, "seed_crypto_ta:rsa:p:v1") + prime search.
 *   2. Derive prime q  via HKDF(bound_seed, "seed_crypto_ta:rsa:q:v1") + prime search.
 *   3. n    = p · q
 *   4. e    = 65537
 *   5. φ(n) = (p−1) · (q−1)
 *   6. d    = e⁻¹ mod φ(n)
 *   7. dp   = d mod (p−1),  dq = d mod (q−1),  qInv = q⁻¹ mod p
 *   8. TEE_PopulateTransientObject with all 8 RSA attributes.
 */
static TEE_Result derive_rsa_keypair(session_ctx_t *ctx,
                                     const uint8_t *seed, size_t seed_len,
                                     uint32_t key_bits)
{
    TEE_Result       res;
    TEE_ObjectHandle kp = TEE_HANDLE_NULL;
    uint8_t          bound_seed[HUK_BOUND_SEED_LEN];

    uint32_t half_bits  = key_bits / 2;
    /* +64 bits of headroom so the +2 walk in derive_prime never overflows */
    uint32_t prime_bits = half_bits + 64;

    /* BigInts */
    TEE_BigInt *p    = NULL, *q   = NULL, *n   = NULL;
    TEE_BigInt *e    = NULL, *d   = NULL, *phi = NULL;
    TEE_BigInt *pm1  = NULL, *qm1 = NULL;
    TEE_BigInt *dp   = NULL, *dq  = NULL, *qInv = NULL;

    /* Byte-array exports */
    uint32_t n_bytes    = key_bits / 8;
    uint32_t half_bytes = half_bits / 8;
    uint8_t *n_buf = NULL, *e_buf  = NULL, *d_buf   = NULL;
    uint8_t *p_buf = NULL, *q_buf  = NULL;
    uint8_t *dp_buf = NULL, *dq_buf = NULL, *qInv_buf = NULL;
    size_t n_len, e_len, d_len, p_len, q_len, dp_len, dq_len, qInv_len;

    TEE_Attribute attrs[8];

    /* HKDF labels are domain-separated by key size, see build_kdf_info() */
    uint8_t p_info[KDF_INFO_MAX_LEN];
    uint8_t q_info[KDF_INFO_MAX_LEN];
    size_t  p_info_len = build_kdf_info(p_info, sizeof(p_info),
                                        "seed_crypto_ta:rsa:p:v1", key_bits);
    size_t  q_info_len = build_kdf_info(q_info, sizeof(q_info),
                                        "seed_crypto_ta:rsa:q:v1", key_bits);

    /* ------------------------------------------------------------------ */
    /* 0. Bind seed to device HUK                                          */
    /* ------------------------------------------------------------------ */
    res = derive_huk_bound_seed(seed, seed_len, bound_seed);
    if (res != TEE_SUCCESS) {
        EMSG("seed_crypto_ta: HUK binding failed: 0x%x", res);
        return res;
    }

    /* ------------------------------------------------------------------ */
    /* 1–2. Derive primes p and q from the HUK-bound seed                 */
    /* ------------------------------------------------------------------ */
    p = bigint_alloc(prime_bits);
    q = bigint_alloc(prime_bits);
    if (!p || !q) { res = TEE_ERROR_OUT_OF_MEMORY; goto cleanup; }

    res = derive_prime(bound_seed, sizeof(bound_seed), half_bits,
                       p_info, p_info_len, p);
    if (res != TEE_SUCCESS) goto cleanup;

    res = derive_prime(bound_seed, sizeof(bound_seed), half_bits,
                       q_info, q_info_len, q);
    if (res != TEE_SUCCESS) goto cleanup;

    if (TEE_BigIntCmp(p, q) == 0) {
        EMSG("seed_crypto_ta: p == q, degenerate seed");
        res = TEE_ERROR_BAD_PARAMETERS;
        goto cleanup;
    }

    /* ------------------------------------------------------------------ */
    /* 3. n = p · q                                                        */
    /* ------------------------------------------------------------------ */
    n = bigint_alloc(key_bits + 2);
    if (!n) { res = TEE_ERROR_OUT_OF_MEMORY; goto cleanup; }
    TEE_BigIntMul(n, p, q);

    /* ------------------------------------------------------------------ */
    /* 4. e = 65537                                                        */
    /* ------------------------------------------------------------------ */
    e = bigint_alloc(32);
    if (!e) { res = TEE_ERROR_OUT_OF_MEMORY; goto cleanup; }
    TEE_BigIntConvertFromS32(e, 65537);

    /* ------------------------------------------------------------------ */
    /* 5. φ(n) = (p − 1) · (q − 1)                                       */
    /* ------------------------------------------------------------------ */
    pm1 = bigint_alloc(prime_bits);
    qm1 = bigint_alloc(prime_bits);
    phi = bigint_alloc(key_bits + 4);
    if (!pm1 || !qm1 || !phi) { res = TEE_ERROR_OUT_OF_MEMORY; goto cleanup; }

    {
        TEE_BigInt *one = bigint_alloc(8);
        if (!one) { res = TEE_ERROR_OUT_OF_MEMORY; goto cleanup; }
        TEE_BigIntConvertFromS32(one, 1);
        TEE_BigIntSub(pm1, p, one);
        TEE_BigIntSub(qm1, q, one);
        bigint_free(one, 8);
    }
    TEE_BigIntMul(phi, pm1, qm1);

    /* ------------------------------------------------------------------ */
    /* 6. d = e⁻¹ mod φ(n)                                               */
    /* TEE_BigIntInvMod returns void and panics if gcd != 1; check first. */
    /* ------------------------------------------------------------------ */
    d = bigint_alloc(key_bits + 2);
    if (!d) { res = TEE_ERROR_OUT_OF_MEMORY; goto cleanup; }

    if (!TEE_BigIntRelativePrime(e, phi)) {
        EMSG("seed_crypto_ta: gcd(e, phi(n)) != 1 — seed produces "
             "a prime p or q divisible by e=65537; try a different seed");
        res = TEE_ERROR_BAD_PARAMETERS;
        goto cleanup;
    }
    TEE_BigIntInvMod(d, e, phi);

    /* ------------------------------------------------------------------ */
    /* 7. CRT parameters                                                   */
    /* ------------------------------------------------------------------ */
    dp   = bigint_alloc(prime_bits);
    dq   = bigint_alloc(prime_bits);
    qInv = bigint_alloc(prime_bits);
    if (!dp || !dq || !qInv) { res = TEE_ERROR_OUT_OF_MEMORY; goto cleanup; }

    TEE_BigIntMod(dp,  d, pm1);
    TEE_BigIntMod(dq,  d, qm1);

    /* p and q are distinct primes so gcd(q, p) == 1 is guaranteed */
    TEE_BigIntInvMod(qInv, q, p);

    /* ------------------------------------------------------------------ */
    /* 8. Export to byte arrays and populate transient key object          */
    /* ------------------------------------------------------------------ */
    n_buf    = TEE_Malloc(n_bytes,    TEE_MALLOC_FILL_ZERO);
    e_buf    = TEE_Malloc(4,          TEE_MALLOC_FILL_ZERO);
    d_buf    = TEE_Malloc(n_bytes,    TEE_MALLOC_FILL_ZERO);
    p_buf    = TEE_Malloc(half_bytes, TEE_MALLOC_FILL_ZERO);
    q_buf    = TEE_Malloc(half_bytes, TEE_MALLOC_FILL_ZERO);
    dp_buf   = TEE_Malloc(half_bytes, TEE_MALLOC_FILL_ZERO);
    dq_buf   = TEE_Malloc(half_bytes, TEE_MALLOC_FILL_ZERO);
    qInv_buf = TEE_Malloc(half_bytes, TEE_MALLOC_FILL_ZERO);
    if (!n_buf || !e_buf || !d_buf || !p_buf || !q_buf ||
        !dp_buf || !dq_buf || !qInv_buf) {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    n_len    = n_bytes;
    e_len    = 4;
    d_len    = n_bytes;
    p_len    = half_bytes;
    q_len    = half_bytes;
    dp_len   = half_bytes;
    dq_len   = half_bytes;
    qInv_len = half_bytes;

    res = TEE_BigIntConvertToOctetString(n_buf,    &n_len,    n);
    if (res != TEE_SUCCESS) goto cleanup;
    res = TEE_BigIntConvertToOctetString(e_buf,    &e_len,    e);
    if (res != TEE_SUCCESS) goto cleanup;
    res = TEE_BigIntConvertToOctetString(d_buf,    &d_len,    d);
    if (res != TEE_SUCCESS) goto cleanup;
    res = TEE_BigIntConvertToOctetString(p_buf,    &p_len,    p);
    if (res != TEE_SUCCESS) goto cleanup;
    res = TEE_BigIntConvertToOctetString(q_buf,    &q_len,    q);
    if (res != TEE_SUCCESS) goto cleanup;
    res = TEE_BigIntConvertToOctetString(dp_buf,   &dp_len,   dp);
    if (res != TEE_SUCCESS) goto cleanup;
    res = TEE_BigIntConvertToOctetString(dq_buf,   &dq_len,   dq);
    if (res != TEE_SUCCESS) goto cleanup;
    res = TEE_BigIntConvertToOctetString(qInv_buf, &qInv_len, qInv);
    if (res != TEE_SUCCESS) goto cleanup;

    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_bits, &kp);
    if (res != TEE_SUCCESS) goto cleanup;

    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS,          n_buf,    n_len);
    TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT,  e_buf,    e_len);
    TEE_InitRefAttribute(&attrs[2], TEE_ATTR_RSA_PRIVATE_EXPONENT, d_buf,    d_len);
    TEE_InitRefAttribute(&attrs[3], TEE_ATTR_RSA_PRIME1,           p_buf,    p_len);
    TEE_InitRefAttribute(&attrs[4], TEE_ATTR_RSA_PRIME2,           q_buf,    q_len);
    TEE_InitRefAttribute(&attrs[5], TEE_ATTR_RSA_EXPONENT1,        dp_buf,   dp_len);
    TEE_InitRefAttribute(&attrs[6], TEE_ATTR_RSA_EXPONENT2,        dq_buf,   dq_len);
    TEE_InitRefAttribute(&attrs[7], TEE_ATTR_RSA_COEFFICIENT,      qInv_buf, qInv_len);

    res = TEE_PopulateTransientObject(kp, attrs, 8);
    if (res != TEE_SUCCESS) {
        TEE_FreeTransientObject(kp);
        kp = TEE_HANDLE_NULL;
        goto cleanup;
    }

    if (ctx->key_pair != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(ctx->key_pair);

    ctx->key_pair  = kp;
    ctx->algo      = ALGO_RSA;
    ctx->key_bits  = key_bits;
    ctx->key_ready = true;
    res = TEE_SUCCESS;

cleanup:
    bigint_free(p,    prime_bits);
    bigint_free(q,    prime_bits);
    bigint_free(n,    key_bits + 2);
    bigint_free(e,    32);
    bigint_free(d,    key_bits + 2);
    bigint_free(pm1,  prime_bits);
    bigint_free(qm1,  prime_bits);
    bigint_free(phi,  key_bits + 4);
    bigint_free(dp,   prime_bits);
    bigint_free(dq,   prime_bits);
    bigint_free(qInv, prime_bits);

    if (n_buf)    { TEE_MemFill(n_buf,    0, n_bytes);    TEE_Free(n_buf); }
    if (e_buf)    { TEE_MemFill(e_buf,    0, 4);          TEE_Free(e_buf); }
    if (d_buf)    { TEE_MemFill(d_buf,    0, n_bytes);    TEE_Free(d_buf); }
    if (p_buf)    { TEE_MemFill(p_buf,    0, half_bytes); TEE_Free(p_buf); }
    if (q_buf)    { TEE_MemFill(q_buf,    0, half_bytes); TEE_Free(q_buf); }
    if (dp_buf)   { TEE_MemFill(dp_buf,   0, half_bytes); TEE_Free(dp_buf); }
    if (dq_buf)   { TEE_MemFill(dq_buf,   0, half_bytes); TEE_Free(dq_buf); }
    if (qInv_buf) { TEE_MemFill(qInv_buf, 0, half_bytes); TEE_Free(qInv_buf); }
    TEE_MemFill(bound_seed, 0, sizeof(bound_seed));

    return res;
}

/*
 * derive_ec_keypair
 *
 * The user seed is first bound to the device HUK via derive_huk_bound_seed(),
 * then the ECDSA private scalar is derived from that bound seed via HKDF.
 * Same seed + same device → same keypair; same seed + different device →
 * different keypair.
 *
 * DISABLED: OP-TEE requires TEE_ATTR_ECC_PUBLIC_VALUE_X/Y as mandatory
 * attributes when populating a TEE_TYPE_ECDSA_KEYPAIR and provides no API
 * to compute the public point from a private scalar, so the
 * TEE_PopulateTransientObject() call below panics.  Re-enable once the
 * public point is computed (EC scalar multiplication over the TEE BigInt
 * API or an equivalent construction).
 */
static TEE_Result __maybe_unused derive_ec_keypair(session_ctx_t *ctx,
                                    const uint8_t *seed, size_t seed_len,
                                    uint32_t key_bits) {
    TEE_Result res;
    TEE_ObjectHandle kp = TEE_HANDLE_NULL;
    uint8_t bound_seed[HUK_BOUND_SEED_LEN];

    /* Choose curve */
    uint32_t curve;
    /* HKDF label is domain-separated by key size, see build_kdf_info() */
    uint8_t ec_info[KDF_INFO_MAX_LEN];
    size_t  ec_info_len = build_kdf_info(ec_info, sizeof(ec_info),
                                         "seed_crypto_ta:ecdsa:v1", key_bits);
    uint8_t *priv;
    size_t scalar_bytes = key_bits / 8;
    TEE_Attribute attrs[2];
    switch (key_bits) {
        case 256: curve = TEE_ECC_CURVE_NIST_P256; break;
        case 384: curve = TEE_ECC_CURVE_NIST_P384; break;
        default:  return TEE_ERROR_BAD_PARAMETERS;
    }

    priv = TEE_Malloc(scalar_bytes, TEE_MALLOC_FILL_ZERO);
    if (!priv) {
      return TEE_ERROR_OUT_OF_MEMORY;
    }

    /* Bind seed to device HUK before deriving the private scalar */
    res = derive_huk_bound_seed(seed, seed_len, bound_seed);
    if (res != TEE_SUCCESS) {
        EMSG("seed_crypto_ta: HUK binding failed: 0x%x", res);
        TEE_Free(priv);
        return res;
    }

    res = hkdf_sha256(bound_seed, sizeof(bound_seed),
                      ec_info, ec_info_len,
                      priv, scalar_bytes);
    TEE_MemFill(bound_seed, 0, sizeof(bound_seed));
    if (res != TEE_SUCCESS) {
      TEE_Free(priv);
      return res;
    }

    /*
     * Ensure the scalar is non-zero.  This sets bit 8*(scalar_bytes-1) of
     * the big-endian scalar, i.e. fixes one bit of the keyspace; a proper
     * implementation should instead reduce the HKDF output into [1, n-1]
     * (n = curve order).  Scalars >= n are not rejected here either — both
     * to be addressed when this path is re-enabled.
     */
    priv[0] |= 0x01;

    res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, key_bits, &kp);
    if (res != TEE_SUCCESS) {
      TEE_Free(priv);
      return res;
    }

    TEE_InitValueAttribute(&attrs[0], TEE_ATTR_ECC_CURVE, curve, 0);
    TEE_InitRefAttribute(&attrs[1], TEE_ATTR_ECC_PRIVATE_VALUE,
                         priv, scalar_bytes);

    res = TEE_PopulateTransientObject(kp, attrs, 2);
    TEE_MemFill(priv, 0, scalar_bytes);
    TEE_Free(priv);

    if (res != TEE_SUCCESS) {
      TEE_FreeTransientObject(kp);
      return res;
    }

    if (ctx->key_pair != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(ctx->key_pair);
    }

    ctx->key_pair = kp;
    ctx->algo     = ALGO_ECDSA;
    ctx->key_bits = key_bits;
    ctx->key_ready = true;
    return TEE_SUCCESS;
}


/*
 * Minimal DER helpers
 */
static size_t der_write_len(uint8_t *buf, size_t val) {
    if (val < 0x80) {
      buf[0] = (uint8_t)val;
      return 1;
    }
    if (val < 0x100) {
      buf[0] = 0x81;
      buf[1] = (uint8_t)val;
      return 2;
    }
    buf[0] = 0x82;
    buf[1] = (uint8_t)(val >> 8);
    buf[2] = (uint8_t)(val);
    return 3;
}

static size_t der_tlv(uint8_t *dst, uint8_t tag, const uint8_t *val, size_t vlen) {
    size_t l;
    dst[0] = tag;
    l = der_write_len(dst + 1, vlen);
    TEE_MemMove(dst + 1 + l, val, vlen);
    return 1 + l + vlen;
}

/*
 * export_rsa_pubkey_der
 *
 * Builds a PKCS#1 RSAPublicKey DER blob (modulus + public exponent).
 */
static TEE_Result export_rsa_pubkey_der(TEE_ObjectHandle kp,
                                        void *buf, size_t *buf_len) {
    /* Get modulus size first */
    TEE_ObjectInfo info;
    uint8_t *mod;
    size_t mod_len;
    uint8_t *mod_tag_buf;
    uint8_t  exp_buf[4] = { 0x01, 0x00, 0x01 };  /* 65537 */
    TEE_Result res;
    uint8_t *tmp;
    size_t  mod_der_val_len;
    size_t off = 0;
    uint8_t *out;
    size_t needed;

    TEE_GetObjectInfo1(kp, &info);
    mod_len = (info.objectSize / 8);

    mod_tag_buf = TEE_Malloc(mod_len + 1, TEE_MALLOC_FILL_ZERO);
    if (!mod_tag_buf)
        return TEE_ERROR_OUT_OF_MEMORY;

    mod  = TEE_Malloc(mod_len + 4, TEE_MALLOC_FILL_ZERO);
    if (!mod)
        return TEE_ERROR_OUT_OF_MEMORY;

    res = TEE_GetObjectBufferAttribute(kp,
                         TEE_ATTR_RSA_MODULUS, mod, &mod_len);
    if (res != TEE_SUCCESS) {
      TEE_Free(mod);
      return res;
    }

    /* INTEGER (modulus) – prepend 0x00 if high bit set */
    tmp = TEE_Malloc(mod_len + 4 + 16, TEE_MALLOC_FILL_ZERO);
    if (!tmp) {
      TEE_Free(mod);
      return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (mod[0] & 0x80) {
        mod_tag_buf[0] = 0x00;
        TEE_MemMove(mod_tag_buf + 1, mod, mod_len);
        mod_der_val_len = mod_len + 1;
    } else {
        TEE_MemMove(mod_tag_buf, mod, mod_len);
        mod_der_val_len = mod_len;
    }

    off += der_tlv(tmp + off, 0x02, mod_tag_buf, mod_der_val_len);
    off += der_tlv(tmp + off, 0x02, exp_buf, 3);

    /* Wrap in outer SEQUENCE */
    out = buf;
    needed = 4 + off;
    if (*buf_len < needed) {
        TEE_Free(mod);
        TEE_Free(tmp);
        return TEE_ERROR_SHORT_BUFFER;
    }

    *buf_len = der_tlv(out, 0x30, tmp, off);

    TEE_Free(mod);
    TEE_Free(mod_tag_buf);
    TEE_Free(tmp);
    return TEE_SUCCESS;
}

/*
 * export_ec_pubkey_der
 *
 * Builds an uncompressed EC public key blob: 0x04 || X || Y
 */
static TEE_Result export_ec_pubkey_der(TEE_ObjectHandle kp,
                                       uint32_t key_bits,
                                       void *buf, size_t *buf_len) {
    size_t coord = key_bits / 8;
    size_t needed = 1 + 2 * coord;  /* 0x04 || X || Y */
    uint8_t *out = buf;
    size_t xlen = (uint32_t)coord, ylen = (uint32_t)coord;
    TEE_Result res;

    if (*buf_len < needed)
        return TEE_ERROR_SHORT_BUFFER;

    res = TEE_GetObjectBufferAttribute(kp, TEE_ATTR_ECC_PUBLIC_VALUE_X,
                                       out + 1, &xlen);
    if (res != TEE_SUCCESS) {
        return res;
    }
    res = TEE_GetObjectBufferAttribute(kp, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                                       out + 1 + coord, &ylen);
    if (res != TEE_SUCCESS) {
        return res;
    }

    out[0]  = 0x04;
    *buf_len = needed;
    return TEE_SUCCESS;
}

static TEE_Result get_pubkey_internal(session_ctx_t *ctx,
                                          void **buf_ptr, size_t *buf_len) {
    if (!ctx->key_ready)
        return TEE_ERROR_BAD_STATE;

    if (ctx->algo == ALGO_RSA)
        return export_rsa_pubkey_der(ctx->key_pair, *buf_ptr, buf_len);
    else
        return export_ec_pubkey_der(ctx->key_pair, ctx->key_bits,
                                    *buf_ptr, buf_len);
}

/* =========================================================================
 * Command handlers for asymmetric operations
 * ========================================================================= */

TEE_Result cmd_asymmetric_derive_keypair(session_ctx_t *ctx,
                                        uint32_t param_types,
                                        TEE_Param params[4]) {
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                   TEE_PARAM_TYPE_VALUE_INPUT,
                                   TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                   TEE_PARAM_TYPE_NONE);
    const uint8_t *seed     = params[0].memref.buffer;
    size_t         seed_len = params[0].memref.size;
    uint32_t       algo     = params[1].value.a;
    uint32_t       key_bits = params[1].value.b;
    TEE_Result res;

    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;


    if (seed_len < SEED_MIN_LEN || seed_len > SEED_MAX_LEN)
        return TEE_ERROR_BAD_PARAMETERS;

    switch (algo) {
        case ALGO_RSA:
            if (key_bits != 2048 && key_bits != 3072 && key_bits != 4096)
                return TEE_ERROR_BAD_PARAMETERS;
            res = derive_rsa_keypair(ctx, seed, seed_len, key_bits);
            break;
        case ALGO_ECDSA:
            /*
             * ECDSA derivation is disabled: derive_ec_keypair() cannot
             * populate the keypair object without the public point, which
             * OP-TEE does not compute from the private scalar.  See the
             * comment on derive_ec_keypair().
             */
            return TEE_ERROR_NOT_SUPPORTED;
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }

    if (res != TEE_SUCCESS)
        return res;

    /* Export public key DER into param[2] */
    /* GP doesn't have a single DER export; we export the raw EC point or
     * RSA modulus/exponent via TEE_GetObjectBufferAttribute and build a
     * minimal SubjectPublicKeyInfo ourselves. */
    return get_pubkey_internal(ctx, &params[2].memref.buffer,
                                   &params[2].memref.size);
}

TEE_Result cmd_asymmetric_get_pubkey(session_ctx_t *ctx,
                                 uint32_t param_types,
                                 TEE_Param params[4]) {
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);
    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;
    if (!ctx->key_ready)
        return TEE_ERROR_BAD_STATE;

    return get_pubkey_internal(ctx,
               &params[0].memref.buffer, &params[0].memref.size);
}

/* -------------------------------------------------------------------------
 * Sign
 * ------------------------------------------------------------------------- */

TEE_Result cmd_asymmetric_sign(session_ctx_t *ctx,
                           uint32_t param_types,
                           TEE_Param params[4])
{
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                   TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);

    const void *data     = params[0].memref.buffer;
    size_t      data_len = params[0].memref.size;
    void       *sig      = params[1].memref.buffer;
    size_t    sig_len  = (uint32_t)params[1].memref.size;

    /* Hash the message first */
    uint8_t  digest[32];
    size_t digest_len = sizeof(digest);
    uint32_t sign_alg;
    uint32_t op_key_bits;
    TEE_ObjectInfo oi;
    TEE_Result res;
    TEE_OperationHandle sign_op;
    TEE_OperationHandle hash_op;

    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;
    if (!ctx->key_ready)
        return TEE_ERROR_BAD_STATE;

    hash_op = TEE_HANDLE_NULL;
    res = TEE_AllocateOperation(&hash_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS)
        return res;

    digest_len = sizeof(digest);
    res = TEE_DigestDoFinal(hash_op, data, data_len, digest, &digest_len);
    TEE_FreeOperation(hash_op);
    if (res != TEE_SUCCESS)
        return res;

    /* Select signing algorithm */
    TEE_GetObjectInfo1(ctx->key_pair, &oi);
    op_key_bits = oi.objectSize;

    if (ctx->algo == ALGO_RSA)
        sign_alg = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256;
    else if (ctx->key_bits == 256)
        sign_alg = TEE_ALG_ECDSA_P256;
    else
        sign_alg = TEE_ALG_ECDSA_P384;

    sign_op = TEE_HANDLE_NULL;
    res = TEE_AllocateOperation(&sign_op, sign_alg,
                                 TEE_MODE_SIGN, op_key_bits);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_SetOperationKey(sign_op, ctx->key_pair);
    if (res != TEE_SUCCESS) {
        TEE_FreeOperation(sign_op);
        return res;
    }

    res = TEE_AsymmetricSignDigest(sign_op, NULL, 0,
                                   digest, digest_len,
                                   sig, &sig_len);
    TEE_FreeOperation(sign_op);
    if (res != TEE_SUCCESS)
        return res;

    params[1].memref.size = sig_len;
    return TEE_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Decrypt (RSA-OAEP only)
 * ------------------------------------------------------------------------- */

TEE_Result cmd_asymmetric_decrypt(session_ctx_t *ctx,
                              uint32_t param_types,
                              TEE_Param params[4])
{
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                   TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);

    TEE_ObjectInfo oi;
    TEE_OperationHandle op;
    TEE_Result res;
    size_t out_len;

    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;
    if (!ctx->key_ready)
        return TEE_ERROR_BAD_STATE;
    if (ctx->algo != ALGO_RSA)
        return TEE_ERROR_NOT_SUPPORTED;

    TEE_GetObjectInfo1(ctx->key_pair, &oi);

    op = TEE_HANDLE_NULL;
    res = TEE_AllocateOperation(&op, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256,
                                            TEE_MODE_DECRYPT, oi.objectSize);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_SetOperationKey(op, ctx->key_pair);
    if (res != TEE_SUCCESS) {
        TEE_FreeOperation(op);
        return res;
    }

    out_len = (uint32_t)params[1].memref.size;
    res = TEE_AsymmetricDecrypt(op, NULL, 0,
                                params[0].memref.buffer, params[0].memref.size,
                                params[1].memref.buffer, &out_len);
    TEE_FreeOperation(op);
    if (res != TEE_SUCCESS)
        return res;

    params[1].memref.size = out_len;
    return TEE_SUCCESS;
}
