/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2025, Canonical Ltd.
 */

#ifndef FDE_KEY_HANDLER_TA_TYPE_H_
#define FDE_KEY_HANDLER_TA_TYPE_H_

// fd1b2a86-3668-11eb-adc1-0242ac120002
#define FDE_KEY_HANDLER_UUID_ID {0xfd1b2a86, 0x3668, 0x11eb, \
    { \
        0xad, 0xc1, 0x02, 0x42, 0xac, 0x12, 0x00, 0x02 \
    } \
}

#define MAX_BUF_SIZE    512
#define HANDLE_SIZE     65  // (version)(1), IV(16), NONCE(32), TAG(16)

/* TA version allowing tracking of future functionality changes */
#define FDE_TA_VERSION_V1   0x00010001

/* Define the command index in this TA */

/*
 * TA_CMD_KEY_ENCRYPT have 3 parameters
 * Encrypts passed key with derived key
 * Key handle is randomply generated at key derivation
 * - TEE_PARAM_TYPE_MEMREF_INPUT
 *    params[0].memref.buffer: plain key buffer
 *    params[0].memref.size: lenght of the buffer
 * - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *    params[1].memref.buffer: returned key handle
 *    params[1].memref.size: lenght of the buffer
 * - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *    params[2].memref.buffer: returned encrypted key
 *    params[2].memref.size: lenght of the buffer
 */
#define TA_CMD_KEY_ENCRYPT            1U

/*
 * TA_CMD_KEY_DECRYPT have 3 parameters
 * - TEE_PARAM_TYPE_MEMREF_INPUT
 *    params[0].memref.buffer:  encrypted key buffer
 *    params[0].memref.size: lenght of the string
 * - TEE_PARAM_TYPE_MEMREF_INPUT
 *    params[1].memref.buffer: key handle
 *    params[1].memref.size: lenght of the buffer
 * - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *    params[2].memref.buffer: returned decrypted key buffer
 *    params[2].memref.size: lenght of the buffer
 */
#define TA_CMD_KEY_DECRYPT            2U

/*
 * TA_CMD_LOCK have no parameter
 * Locks TA interface for future use till next reboot
 */
#define TA_CMD_LOCK                   3U

/*
 * TA_CMD_GET_LOCK get TA lock status
 * Gets TA interface lock state
 * - TEE_PARAM_TYPE_VALUE_OUTPUT
 *    params[0].value.a: lock status (0-unlocked, 1-locked)
 */
#define TA_CMD_GET_LOCK               4U

/*
 * TA_CMD_GEN_RANDOM generate random data
 * Generates rand data of given length
 * - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *    params[0].memref.buffer: buffer to be filled with random data
 *    params[0].memref.size: lenght of the buffer
 */
#define TA_CMD_GEN_RANDOM             5U

/*
 * TA_CMD_VERSION return TA version
 * Return the version of TA
 * - TEE_PARAM_TYPE_MEMREF_OUTPUT
 *    params[0].value.a: TA version as int
 */
#define TA_CMD_TA_VERSION                6U

/* -----------------------------------------------------------------------
 * Commands for Seed-Derived Asymmetric Crypto TA functionality
 * ----------------------------------------------------------------------- */

/*
 * TA_CMD_AS_DERIVE_KEYPAIR
 *   Derives a persistent key pair from the provided seed.
 *   Must be called before any crypto command.
 *
 *   param[0] (memref-input)  : seed bytes (8 – 64 bytes)
 *   param[1] (value-input)   : a = key algorithm (ALGO_*)
 *                              b = key size in bits (KEY_SIZE_*)
 *   param[2] (memref-output) : public key DER blob (caller-allocated)
 *   param[3] (unused)
 */
#define TA_CMD_ASYMMETRIC_DERIVE_KEYPAIR      101U

/*
 * TA_CMD_AS_SIGN
 *   Sign data with the derived private key (ECDSA / Ed25519 / RSA-PSS).
 *
 *   param[0] (memref-input)  : data to sign (≤ 8 KiB)
 *   param[1] (memref-output) : signature blob
 *   param[2] (unused)
 *   param[3] (unused)
 */
#define TA_CMD_ASYMMETRIC_SIGN                102U

/*
 * TA_CMD_AS_DECRYPT
 *   Decrypt data with the derived private key (RSA-OAEP only).
 *
 *   param[0] (memref-input)  : ciphertext
 *   param[1] (memref-output) : plaintext
 *   param[2] (unused)
 *   param[3] (unused)
 */
#define TA_CMD_ASYMMETRIC_DECRYPT             103U

/*
 * TA_CMD_AS_GET_PUBKEY
 *   Return DER-encoded public key for the currently derived key pair.
 *
 *   param[0] (memref-output) : public key DER blob
 *   param[1] (unused)
 *   param[2] (unused)
 *   param[3] (unused)
 */
#define TA_CMD_ASYMMETRIC_GET_PUBKEY          104U

/* -----------------------------------------------------------------------
 * Algorithm selectors (param[1].a for CMD_DERIVE_KEYPAIR)
 * ----------------------------------------------------------------------- */
#define ALGO_RSA                0x00000001   /* RSA-PSS sign + OAEP enc  */
#define ALGO_ECDSA              0x00000002   /* ECDSA on NIST P-256/384  */

/* Key sizes (param[1].b for CMD_DERIVE_KEYPAIR) */
#define KEY_SIZE_RSA_2048       2048
#define KEY_SIZE_RSA_3072       3072
#define KEY_SIZE_RSA_4096       4096
#define KEY_SIZE_EC_256         256
#define KEY_SIZE_EC_384         384

/* -----------------------------------------------------------------------
 * Return codes (TA-private; GP error codes used on the CA side)
 * ----------------------------------------------------------------------- */
#define SEED_CRYPTO_ERR_NO_KEY          0xF0000001  /* cmd before derive  */
#define SEED_CRYPTO_ERR_BAD_ALGO        0xF0000002
#define SEED_CRYPTO_ERR_BAD_SEED        0xF0000003
#define SEED_CRYPTO_ERR_BUF_TOO_SMALL   0xF0000004

/* Convenience */
#define SEED_MIN_LEN    8
#define SEED_MAX_LEN    64

/* Upper bound for asymmetric command inputs (data to sign, ciphertext) */
#define ASYM_MAX_INPUT_SIZE   (8 * 1024)
/* Upper bound for asymmetric command outputs (pubkey, signature, plaintext) */
#define ASYM_MAX_OUTPUT_SIZE  (8 * 1024)


/* Define the debug flag */
#define DEBUG
#define DLOG    MSG_RAW
//#define DLOG    ta_debug

#define UNUSED(x) (void)(x)

#endif
