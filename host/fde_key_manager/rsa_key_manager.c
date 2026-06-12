/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2025, Canonical Ltd.
 */

/*
 * rsa-key-manager — CA-side client for the fde_key_handler TA asymmetric
 * crypto commands.
 *
 * Usage:
 *   rsa-key-manager --action <action> --seed <b64> \
 *                   --algo <rsa|ecdsa> --key-size <N> [action-options]
 *
 * Actions:
 *   get-pubkey
 *       Derives a keypair from the seed and prints the DER-encoded public key
 *       (base64) to stdout.
 *
 *   sign   --data <b64-data>
 *       Signs the data (base64) with the derived private key.
 *       Prints the base64-encoded signature to stdout.
 *
 *   decrypt --ciphertext <b64-ciphertext>
 *       RSA-OAEP decrypts the ciphertext (base64) with the derived private key.
 *       Prints the base64-encoded plaintext to stdout.
 *
 * All binary inputs and outputs are base64-encoded.
 * The seed must decode to 8–64 bytes (SEED_MIN_LEN / SEED_MAX_LEN).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>

#include "fde_key_handler_ta_type.h"
#include "rsa_key_manager_ca.h"

/*
 * Decode a lowercase or uppercase hex string into a freshly malloc'd buffer.
 * Returns NULL on bad input.  *out_len is set to the number of decoded bytes.
 */
static unsigned char *hex_decode(const char *str, size_t *out_len)
{
    size_t hex_len = strlen(str);
    /* sha256sum appends a trailing space+filename; accept bare hex too */
    if (hex_len % 2 != 0) {
        fprintf(stderr, "error: hex seed has odd number of characters\n");
        return NULL;
    }
    size_t bin_len = hex_len / 2;
    unsigned char *buf = malloc(bin_len);
    if (!buf)
        return NULL;
    for (size_t i = 0; i < bin_len; i++) {
        unsigned int byte;
        if (sscanf(str + i * 2, "%02x", &byte) != 1) {
            fprintf(stderr, "error: invalid hex character at position %zu\n",
                    i * 2);
            free(buf);
            return NULL;
        }
        buf[i] = (unsigned char)byte;
    }
    *out_len = bin_len;
    return buf;
}

static void print_help(const char *prog)
{
    printf(
        "Usage: %s --action <action> (--seed <b64> | --seed-hex <hex>)\n"
        "          --algo <rsa|ecdsa> --key-size <N> [action-options]\n"
        "\n"
        "Actions:\n"
        "  get-pubkey\n"
        "      Derive keypair and print DER public key (base64) to stdout.\n"
        "\n"
        "  sign --data <b64-data>\n"
        "      Sign data with the derived private key.\n"
        "      Prints base64-encoded signature to stdout.\n"
        "\n"
        "  decrypt --ciphertext <b64-ciphertext>\n"
        "      RSA-OAEP decrypt ciphertext (base64).\n"
        "      Prints base64-encoded plaintext to stdout.\n"
        "\n"
        "Common options:\n"
        "  --algo rsa|ecdsa\n"
        "  --key-size 2048|3072|4096   (RSA)  or  256|384  (ECDSA)\n"
        "  --seed <base64>             Seed bytes, base64-encoded\n"
        "  --seed-hex <hex>            Seed bytes, hex-encoded (e.g. sha256sum output)\n"
        "  Decoded seed must be %d-%d bytes. Exactly one of --seed / --seed-hex required.\n",
        prog, SEED_MIN_LEN, SEED_MAX_LEN);
}

/* Return the value of the argument that follows @flag, or NULL. */
static const char *arg_get(int argc, char *argv[], const char *flag)
{
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], flag) == 0)
            return argv[i + 1];
    }
    return NULL;
}

static uint32_t parse_algo(const char *str)
{
    if (strcmp(str, "rsa")   == 0) return ALGO_RSA;
    if (strcmp(str, "ecdsa") == 0) return ALGO_ECDSA;
    return 0;
}

static uint32_t parse_key_size(const char *str)
{
    int n = atoi(str);
    switch (n) {
    case 2048: return KEY_SIZE_RSA_2048;
    case 3072: return KEY_SIZE_RSA_3072;
    case 4096: return KEY_SIZE_RSA_4096;
    case  256: return KEY_SIZE_EC_256;
    case  384: return KEY_SIZE_EC_384;
    default:   return 0;
    }
}

int main(int argc, char *argv[])
{
    int ret = EXIT_SUCCESS;
    TEEC_Result tret;

    /* ---- Parse common arguments ---- */
    const char *action    = arg_get(argc, argv, "--action");
    const char *seed_b64  = arg_get(argc, argv, "--seed");
    const char *seed_hex  = arg_get(argc, argv, "--seed-hex");
    const char *algo_str  = arg_get(argc, argv, "--algo");
    const char *ksize_str = arg_get(argc, argv, "--key-size");

    if (!action || (!seed_b64 && !seed_hex) || !algo_str || !ksize_str) {
        fprintf(stderr,
                "error: --action, --seed or --seed-hex, --algo and --key-size are required\n\n");
        print_help(argv[0]);
        return EXIT_FAILURE;
    }
    if (seed_b64 && seed_hex) {
        fprintf(stderr, "error: --seed and --seed-hex are mutually exclusive\n");
        return EXIT_FAILURE;
    }

    uint32_t algo     = parse_algo(algo_str);
    uint32_t key_bits = parse_key_size(ksize_str);

    if (!algo) {
        fprintf(stderr, "error: unknown algo '%s' (use rsa or ecdsa)\n",
                algo_str);
        return EXIT_FAILURE;
    }
    if (!key_bits) {
        fprintf(stderr, "error: unsupported key-size '%s'\n", ksize_str);
        return EXIT_FAILURE;
    }

    /* ---- Decode seed ---- */
    size_t seed_len = 0;
    unsigned char *seed = seed_hex ? hex_decode(seed_hex, &seed_len)
                                   : rsa_b64_decode(seed_b64, &seed_len);
    if (!seed) {
        fprintf(stderr, "error: failed to decode --%s\n",
                seed_hex ? "seed-hex" : "seed");
        return EXIT_FAILURE;
    }
    if (seed_len < SEED_MIN_LEN || seed_len > SEED_MAX_LEN) {
        fprintf(stderr,
                "error: seed must be %d-%d bytes after decoding (got %zu)\n",
                SEED_MIN_LEN, SEED_MAX_LEN, seed_len);
        free(seed);
        return EXIT_FAILURE;
    }

    /* ---- Open TEE session ---- */
    rsa_session_t sess;
    if (rsa_open_session(&sess) != TEEC_SUCCESS) {
        free(seed);
        return EXIT_FAILURE;
    }

    /* ---- Derive keypair (required before any crypto operation) ---- */
    unsigned char pubkey_buf[RSA_MAX_BUF_SIZE];
    size_t pubkey_len = sizeof(pubkey_buf);
    unsigned char sig_buf[RSA_MAX_BUF_SIZE];
    unsigned char pt_buf[RSA_MAX_BUF_SIZE];

    tret = rsa_derive_keypair(&sess, seed, seed_len, algo, key_bits,
                              pubkey_buf, &pubkey_len);
    explicit_bzero(seed, seed_len);
    free(seed);
    if (tret != TEEC_SUCCESS) {
        fprintf(stderr, "error: key derivation failed (0x%x)\n", tret);
        rsa_close_session(&sess);
        return EXIT_FAILURE;
    }

    /* ---- Dispatch action ---- */

    if (strcmp(action, "get-pubkey") == 0) {
        /*
         * Use TA_CMD_ASYMMETRIC_GET_PUBKEY explicitly rather than the key
         * already returned by derive, to exercise that specific TA command.
         */
        unsigned char key_buf[RSA_MAX_BUF_SIZE];
        size_t key_len = sizeof(key_buf);

        tret = rsa_get_pubkey(&sess, key_buf, &key_len);
        if (tret != TEEC_SUCCESS) {
            fprintf(stderr, "error: get-pubkey failed (0x%x)\n", tret);
            ret = EXIT_FAILURE;
            goto done;
        }

        char *encoded = rsa_b64_encode(key_buf, key_len);
        if (!encoded) {
            fprintf(stderr, "error: base64 encode failed\n");
            ret = EXIT_FAILURE;
        } else {
            printf("%s\n", encoded);
            free(encoded);
        }

    } else if (strcmp(action, "sign") == 0) {
        const char *data_b64 = arg_get(argc, argv, "--data");
        if (!data_b64) {
            fprintf(stderr, "error: --data required for sign\n");
            ret = EXIT_FAILURE;
            goto done;
        }

        size_t data_len = 0;
        unsigned char *data = rsa_b64_decode(data_b64, &data_len);
        if (!data) {
            fprintf(stderr, "error: failed to base64-decode --data\n");
            ret = EXIT_FAILURE;
            goto done;
        }

        size_t sig_len = sizeof(sig_buf);

        tret = rsa_sign(&sess, data, data_len, sig_buf, &sig_len);
        free(data);
        if (tret != TEEC_SUCCESS) {
            fprintf(stderr, "error: sign failed (0x%x)\n", tret);
            ret = EXIT_FAILURE;
            goto done;
        }

        char *encoded = rsa_b64_encode(sig_buf, sig_len);
        if (!encoded) {
            fprintf(stderr, "error: base64 encode failed\n");
            ret = EXIT_FAILURE;
        } else {
            printf("%s\n", encoded);
            free(encoded);
        }

    } else if (strcmp(action, "decrypt") == 0) {
        const char *ct_b64 = arg_get(argc, argv, "--ciphertext");
        if (!ct_b64) {
            fprintf(stderr, "error: --ciphertext required for decrypt\n");
            ret = EXIT_FAILURE;
            goto done;
        }

        size_t ct_len = 0;
        unsigned char *ct = rsa_b64_decode(ct_b64, &ct_len);
        if (!ct) {
            fprintf(stderr, "error: failed to base64-decode --ciphertext\n");
            ret = EXIT_FAILURE;
            goto done;
        }

        size_t pt_len = sizeof(pt_buf);

        tret = rsa_decrypt(&sess, ct, ct_len, pt_buf, &pt_len);
        free(ct);
        if (tret != TEEC_SUCCESS) {
            fprintf(stderr, "error: decrypt failed (0x%x)\n", tret);
            ret = EXIT_FAILURE;
            goto done;
        }

        char *encoded = rsa_b64_encode(pt_buf, pt_len);
        if (!encoded) {
            fprintf(stderr, "error: base64 encode failed\n");
            ret = EXIT_FAILURE;
        } else {
            printf("%s\n", encoded);
            free(encoded);
        }

    } else {
        fprintf(stderr, "error: unknown action '%s'\n", action);
        print_help(argv[0]);
        ret = EXIT_FAILURE;
    }

done:
    explicit_bzero(sig_buf, sizeof(sig_buf));
    explicit_bzero(pt_buf,  sizeof(pt_buf));
    rsa_close_session(&sess);
    return ret;
}
