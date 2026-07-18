/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2025, Canonical Ltd.
 */

#ifndef RSA_KEY_MANAGER_CA_H_
#define RSA_KEY_MANAGER_CA_H_

#include <stddef.h>
#include <stdint.h>
#include <tee_client_api.h>

/*
 * RSA_MAX_BUF_SIZE covers the largest asymmetric crypto blob we expect:
 *   RSA-4096 PKCS#1 DER public key  ~526 bytes
 *   RSA-4096 signature               512 bytes
 *   RSA-4096 ciphertext              512 bytes
 */
#define RSA_MAX_BUF_SIZE 1024

/*
 * Session handle that keeps a TEEC context and session open across multiple
 * TA invocations.  Required because the TA stores the derived keypair in
 * per-session state: TA_CMD_ASYMMETRIC_DERIVE_KEYPAIR must be called first,
 * and subsequent commands reuse the same session.
 */
typedef struct {
    TEEC_Context context;
    TEEC_Session session;
} rsa_session_t;

/* Open / close a TEE session to the fde_key_handler TA */
TEEC_Result rsa_open_session(rsa_session_t *sess);
void        rsa_close_session(rsa_session_t *sess);

/*
 * rsa_derive_keypair - TA_CMD_ASYMMETRIC_DERIVE_KEYPAIR
 *   Derives a keypair from @seed inside the TA and returns the public key
 *   in @pubkey_buf / *@pubkey_len (PKCS#1 RSAPublicKey DER for RSA, an
 *   uncompressed point 0x04 || X || Y for ECDSA).
 *   Must be called once per session before any of the operations below.
 */
TEEC_Result rsa_derive_keypair(rsa_session_t *sess,
                               const unsigned char *seed, size_t seed_len,
                               uint32_t algo, uint32_t key_bits,
                               unsigned char *pubkey_buf, size_t *pubkey_len);

/*
 * rsa_get_pubkey - TA_CMD_ASYMMETRIC_GET_PUBKEY
 *   Return the public key for the already-derived keypair, in the same
 *   encoding as rsa_derive_keypair().
 */
TEEC_Result rsa_get_pubkey(rsa_session_t *sess,
                           unsigned char *pubkey_buf, size_t *pubkey_len);

/*
 * rsa_sign - TA_CMD_ASYMMETRIC_SIGN
 *   Sign @data_len bytes from @data with the derived private key.
 *   Signature is written to @sig_buf; *@sig_len is updated with actual length.
 */
TEEC_Result rsa_sign(rsa_session_t *sess,
                     const unsigned char *data, size_t data_len,
                     unsigned char *sig_buf, size_t *sig_len);

/*
 * rsa_decrypt - TA_CMD_ASYMMETRIC_DECRYPT
 *   RSA-OAEP decrypt @ct_len bytes from @ct with the derived private key.
 *   Plaintext is written to @pt; *@pt_len updated with actual length.
 */
TEEC_Result rsa_decrypt(rsa_session_t *sess,
                        const unsigned char *ct, size_t ct_len,
                        unsigned char *pt, size_t *pt_len);

/*
 * Dynamic base64 helpers — caller must free() the returned pointer.
 * rsa_b64_encode: binary -> NUL-terminated base64 string
 * rsa_b64_decode: base64 string -> binary; *out_len set to decoded length
 */
char          *rsa_b64_encode(const unsigned char *buf, size_t len);
unsigned char *rsa_b64_decode(const char *str, size_t *out_len);

#endif /* RSA_KEY_MANAGER_CA_H_ */
