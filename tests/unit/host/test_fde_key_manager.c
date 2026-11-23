/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 *
 * Tests for fde_key_manager.c: the fde-setup and fde-reveal-key hooks, and the
 * test commands of fde-key-manager.
 *
 * Hook requests are read from stdin, or from a fake snapctl when the
 * fde-setup hook runs as a snap hook. Results and command output go to
 * stdout, which every test captures, or to the fake snapctl.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cmocka.h>

#include <json-c/json.h>

#include <tee_client_api.h>

#include "fde_key_handler_ta_type.h"
#include "fde_key_manager.h"
#include "fde_key_manager_ca.h"

#include "fake_ta.h"

/* "key!", and the same key sealed by the fake TA with its handle */
#define KEY "a2V5IQ=="
#define SEALED_KEY "lJqG3g=="
#define HANDLE                                                                 \
	"oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS" \
	"09TV1tfY2drb3N3e3+A="

/* The fake TA's random data, of 16 and HANDLE_SIZE bytes */
#define RANDOM_16 "AAECAwQFBgcICQoLDA0ODw=="
#define RANDOM_65                                                              \
	"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEy" \
	"MzQ1Njc4OTo7PD0+P0A="
/* RANDOM_65 sealed by the fake TA */
#define SEALED_RANDOM_65                                                       \
	"//79/Pv6+fj39vX08/Lx8O/u7ezr6uno5+bl5OPi4eDf3t3c29rZ2NfW1dTT0tHQz87N" \
	"zMvKycjHxsXEw8LBwL8="

#define REVEAL_REQUEST                                              \
	"{\"op\": \"reveal\", \"sealed-key\": \"" SEALED_KEY "\", " \
	"\"handle\": \"" HANDLE "\"}"
#define SETUP_REQUEST                                        \
	"{\"op\": \"initial-setup\", \"key\": \"" KEY "\", " \
	"\"key-name\": \"test\"}"
#define SETUP_REQUEST_WITHOUT_OP \
	"{\"key\": \"" KEY "\", \"key-name\": \"test\"}"

/* stdout */

static int saved_stdout = -1;
static FILE *captured;

static void capture_stdout(void)
{
	fflush(stdout);
	captured = tmpfile();
	assert_non_null(captured);
	saved_stdout = dup(STDOUT_FILENO);
	assert_int_not_equal(saved_stdout, -1);
	assert_int_not_equal(dup2(fileno(captured), STDOUT_FILENO), -1);
}

/* Stop capturing stdout, and return what was written to it */
static const char *output(void)
{
	static char buf[4096];
	size_t len = 0;

	if (saved_stdout == -1) {
		return "";
	}
	fflush(stdout);
	dup2(saved_stdout, STDOUT_FILENO);
	close(saved_stdout);
	saved_stdout = -1;

	rewind(captured);
	len = fread(buf, 1, sizeof(buf) - 1, captured);
	buf[len] = '\0';
	fclose(captured);
	return buf;
}

static void assert_output_starts_with(const char *prefix)
{
	const char *out = output();

	if (strncmp(out, prefix, strlen(prefix)) != 0) {
		fail_msg("output \"%s\" doesn't start with \"%s\"", out,
			 prefix);
	}
}

/* Check that json is an object, with the string field set to value */
static void assert_json_field(const char *json, const char *field,
			      const char *value)
{
	struct json_object *obj = json_tokener_parse(json);
	struct json_object *field_obj = NULL;

	assert_non_null(obj);
	assert_true(json_object_object_get_ex(obj, field, &field_obj));
	assert_string_equal(json_object_get_string(field_obj), value);
	json_object_put(obj);
}

/* stdin */

static void set_stdin(const char *data)
{
	FILE *f = tmpfile();

	assert_non_null(f);
	assert_int_not_equal(fputs(data, f), EOF);
	rewind(f);
	assert_int_not_equal(dup2(fileno(f), STDIN_FILENO), -1);
	fclose(f);
}

/* Run as the named hook, the way snapd runs it */
static int run_hook(const char *name)
{
	char path[64];
	char *argv[] = { path, NULL };

	snprintf(path, sizeof(path), "/usr/bin/%s", name);
	return fde_key_manager_main(1, argv);
}

/*
 * Run a hook request from stdin, with the result on stdout, as the hooks do
 * in the initramfs.
 */
static int run_request(const char *request)
{
	set_stdin(request);
	return run_hook("fde-reveal-key");
}

/*
 * A fake snapctl, first in PATH. fde-setup-request prints the request file,
 * fde-setup-result saves its input to the result file, and both exit with the
 * status in the status file.
 */

static char snapctl_dir[] = "/tmp/test_fde_key_manager-XXXXXX";

static const char snapctl_script[] =
	"#!/bin/sh\n"
	"dir=$(dirname \"$0\")\n"
	"case \"$1\" in\n"
	"fde-setup-request) cat \"$dir/request\" ;;\n"
	"fde-setup-result) cat > \"$dir/result\" ;;\n"
	"*) exit 1 ;;\n"
	"esac\n"
	"exit \"$(cat \"$dir/status\")\"\n";

static const char *snapctl_path(const char *name)
{
	static char path[256];

	snprintf(path, sizeof(path), "%s/%s", snapctl_dir, name);
	return path;
}

static int write_snapctl_file(const char *name, const char *data)
{
	FILE *f = fopen(snapctl_path(name), "w");

	if (!f) {
		return -1;
	}
	fputs(data, f);
	return fclose(f);
}

static const char *read_snapctl_file(const char *name)
{
	static char buf[4096];
	FILE *f = fopen(snapctl_path(name), "r");
	size_t len = 0;

	assert_non_null(f);
	len = fread(buf, 1, sizeof(buf) - 1, f);
	buf[len] = '\0';
	fclose(f);
	return buf;
}

static int create_snapctl(void **state)
{
	const char *path = getenv("PATH");
	char new_path[4096];

	(void)state;
	if (!mkdtemp(snapctl_dir) ||
	    write_snapctl_file("snapctl", snapctl_script) ||
	    chmod(snapctl_path("snapctl"), 0755)) {
		return -1;
	}
	snprintf(new_path, sizeof(new_path), "%s:%s", snapctl_dir,
		 path ? path : "/usr/bin:/bin");
	return setenv("PATH", new_path, 1);
}

static int remove_snapctl(void **state)
{
	(void)state;
	unlink(snapctl_path("snapctl"));
	unlink(snapctl_path("status"));
	unlink(snapctl_path("request"));
	unlink(snapctl_path("result"));
	return rmdir(snapctl_dir);
}

/* The fde-setup hook only uses snapctl outside of the initramfs */
static void skip_in_initramfs(void)
{
	if (access("/etc/initrd-release", F_OK) == 0) {
		skip();
	}
}

/* Every test captures stdout, and starts with a successful snapctl */
static int setup(void **state)
{
	(void)state;
	unlink(snapctl_path("request"));
	unlink(snapctl_path("result"));
	assert_int_equal(write_snapctl_file("status", "0"), 0);
	capture_stdout();
	return 0;
}

static int teardown(void **state)
{
	(void)state;
	output();
	return 0;
}

/* Hook requests */

static void test_reveal(void **state)
{
	(void)state;
	expect_ta_command(TA_CMD_KEY_DECRYPT, fake_ta_decrypt, 0, TEEC_SUCCESS);

	assert_int_equal(run_request(REVEAL_REQUEST), EXIT_SUCCESS);
	assert_json_field(output(), "key", KEY);
}

static void test_reveal_ta_fails(void **state)
{
	(void)state;
	expect_ta_command(TA_CMD_KEY_DECRYPT, fake_ta_decrypt, 0,
			  TEEC_ERROR_GENERIC);

	assert_int_equal(run_request(REVEAL_REQUEST), EXIT_FAILURE);
	assert_string_equal(output(), "");
}

static void test_reveal_bad_request(void **state)
{
	static const char *const requests[] = {
		"{\"op\": \"reveal\", \"handle\": \"" HANDLE "\"}",
		"{\"op\": \"reveal\", \"sealed-key\": 1, "
		"\"handle\": \"" HANDLE "\"}",
		"{\"op\": \"reveal\", \"sealed-key\": \"!\", "
		"\"handle\": \"" HANDLE "\"}",
		"{\"op\": \"reveal\", \"sealed-key\": \"" SEALED_KEY "\"}",
		"{\"op\": \"reveal\", \"sealed-key\": \"" SEALED_KEY "\", "
		"\"handle\": 1}",
		"{\"op\": \"reveal\", \"sealed-key\": \"" SEALED_KEY "\", "
		"\"handle\": \"!\"}",
	};

	(void)state;
	for (size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); i++) {
		assert_int_equal(run_request(requests[i]), EXIT_FAILURE);
	}
	assert_string_equal(output(), "");
}

static void test_setup(void **state)
{
	const char *out = NULL;

	(void)state;
	expect_ta_command(TA_CMD_KEY_ENCRYPT, fake_ta_encrypt, 0, TEEC_SUCCESS);

	assert_int_equal(run_request(SETUP_REQUEST), EXIT_SUCCESS);
	out = output();
	assert_json_field(out, "sealed-key", SEALED_KEY);
	assert_json_field(out, "handle", HANDLE);
}

static void test_setup_ta_fails(void **state)
{
	(void)state;
	expect_ta_command(TA_CMD_KEY_ENCRYPT, fake_ta_encrypt, 0,
			  TEEC_ERROR_GENERIC);

	assert_int_equal(run_request(SETUP_REQUEST), EXIT_FAILURE);
	assert_string_equal(output(), "");
}

static void test_setup_bad_request(void **state)
{
	static const char *const requests[] = {
		"{\"op\": \"initial-setup\", \"key-name\": \"test\"}",
		"{\"op\": \"initial-setup\", \"key\": 1, "
		"\"key-name\": \"test\"}",
		"{\"op\": \"initial-setup\", \"key\": \"!\", "
		"\"key-name\": \"test\"}",
		"{\"op\": \"initial-setup\", \"key\": \"" KEY "\"}",
		"{\"op\": \"initial-setup\", \"key\": \"" KEY "\", "
		"\"key-name\": 1}",
	};

	(void)state;
	for (size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); i++) {
		assert_int_equal(run_request(requests[i]), EXIT_FAILURE);
	}
	assert_string_equal(output(), "");
}

static void test_lock(void **state)
{
	(void)state;
	expect_ta_command(TA_CMD_LOCK, fake_ta_lock, 0, TEEC_SUCCESS);
	assert_int_equal(run_request("{\"op\": \"lock\"}"), EXIT_SUCCESS);

	expect_ta_command(TA_CMD_LOCK, fake_ta_lock, 0, TEEC_ERROR_GENERIC);
	assert_int_equal(run_request("{\"op\": \"lock\"}"), EXIT_FAILURE);
	assert_string_equal(output(), "");
}

static void test_features(void **state)
{
	(void)state;
	assert_int_equal(run_request("{\"op\": \"features\"}"), EXIT_SUCCESS);
	assert_string_equal(output(), "{\"features\":[]}\n");
}

static void test_bad_request(void **state)
{
	(void)state;
	assert_int_equal(run_request(""), EXIT_FAILURE);
	assert_int_equal(run_request("{\"op\": "), EXIT_FAILURE);
	assert_int_equal(run_request("{\"op\": \"unknown\"}"), EXIT_FAILURE);
	assert_string_equal(output(), "");
}

/* No TA command is expected, so the fake fails the test if it's called */
static void test_missing_op(void **state)
{
	(void)state;
	assert_int_equal(run_request("{}"), EXIT_FAILURE);
	assert_int_equal(run_request(SETUP_REQUEST_WITHOUT_OP), EXIT_FAILURE);
	assert_string_equal(output(), "");
}

static void test_null_op(void **state)
{
	(void)state;
	assert_int_equal(run_request("{\"op\": null}"), EXIT_FAILURE);
	assert_string_equal(output(), "");
}

/* Without arguments, the binary must be run as one of the hooks */
static void test_unknown_hook(void **state)
{
	(void)state;
	assert_int_equal(run_hook("fde-key-manager"), EXIT_FAILURE);
	assert_output_starts_with("This binary should be invoked only under "
				  "specific context\n");
}

static void test_read_request(void **state)
{
	char *request = NULL;

	(void)state;
	set_stdin(REVEAL_REQUEST);
	request = get_initrd_fde_request();
	assert_non_null(request);
	assert_string_equal(request, REVEAL_REQUEST);
	free(request);
}

/* Requests are cut off at 10 KiB, leaving room for the NUL */
static void test_read_long_request(void **state)
{
	char data[12 * 1024];
	char *request = NULL;

	(void)state;
	memset(data, 'a', sizeof(data) - 1);
	data[sizeof(data) - 1] = '\0';
	set_stdin(data);
	request = get_initrd_fde_request();
	assert_non_null(request);
	assert_uint_equal(strlen(request), 10 * 1024 - 1);
	free(request);
}

/* The fde-setup hook, through snapctl */

static void test_setup_snapctl(void **state)
{
	const char *result = NULL;

	(void)state;
	skip_in_initramfs();
	assert_int_equal(write_snapctl_file("request", SETUP_REQUEST), 0);
	expect_ta_command(TA_CMD_KEY_ENCRYPT, fake_ta_encrypt, 0, TEEC_SUCCESS);

	assert_int_equal(run_hook("fde-setup"), EXIT_SUCCESS);
	result = read_snapctl_file("result");
	assert_json_field(result, "sealed-key", SEALED_KEY);
	assert_json_field(result, "handle", HANDLE);
	assert_string_equal(output(), "");
}

static void test_features_snapctl(void **state)
{
	(void)state;
	skip_in_initramfs();
	assert_int_equal(
		write_snapctl_file("request", "{\"op\": \"features\"}"), 0);

	assert_int_equal(run_hook("fde-setup"), EXIT_SUCCESS);
	assert_string_equal(read_snapctl_file("result"), "{\"features\":[]}");
	assert_string_equal(output(), "");
}

static void test_snapctl_fails(void **state)
{
	(void)state;
	skip_in_initramfs();
	assert_int_equal(
		write_snapctl_file("request", "{\"op\": \"features\"}"), 0);
	assert_int_equal(write_snapctl_file("status", "1"), 0);

	assert_int_equal(run_hook("fde-setup"), EXIT_FAILURE);
}

/* The test commands */

static int command(const char *arg, const char *value)
{
	char name[] = "fde-key-manager";
	char *argv[] = { name, (char *)arg, (char *)value, NULL };

	return fde_key_manager_main(value ? 3 : 2, argv);
}

static void expect_selftest(TEEC_Result random, TEEC_Result encrypt,
			    TEEC_Result decrypt)
{
	expect_ta_command(TA_CMD_GEN_RANDOM, fake_ta_random, 0, random);
	if (random != TEEC_SUCCESS) {
		return;
	}
	expect_ta_command(TA_CMD_KEY_ENCRYPT, fake_ta_encrypt, 0, encrypt);
	if (encrypt != TEEC_SUCCESS) {
		return;
	}
	expect_ta_command(TA_CMD_KEY_DECRYPT, fake_ta_decrypt, 0, decrypt);
}

static void test_selftest(void **state)
{
	(void)state;
	expect_selftest(TEEC_SUCCESS, TEEC_SUCCESS, TEEC_SUCCESS);

	assert_int_equal(encrypt_decrypt_selftest(), EXIT_SUCCESS);
	assert_string_equal(output(), "Key: " RANDOM_65 "\n"
				      "Sealed Key: " SEALED_RANDOM_65 "\n"
				      "Unsealed Key: " RANDOM_65 "\n");
}

static void test_selftest_fails(void **state)
{
	(void)state;
	expect_selftest(TEEC_ERROR_GENERIC, TEEC_SUCCESS, TEEC_SUCCESS);
	assert_int_equal(encrypt_decrypt_selftest(), EXIT_FAILURE);

	expect_selftest(TEEC_SUCCESS, TEEC_ERROR_GENERIC, TEEC_SUCCESS);
	assert_int_equal(encrypt_decrypt_selftest(), EXIT_FAILURE);

	expect_selftest(TEEC_SUCCESS, TEEC_SUCCESS, TEEC_ERROR_GENERIC);
	assert_int_equal(encrypt_decrypt_selftest(), EXIT_FAILURE);
}

/* A TA that unseals the wrong key, by flipping a bit of the right one */
static int fake_ta_decrypt_wrong_key(CMockaValueData value,
				     CMockaValueData data)
{
	TEEC_Operation *op = value.ptr;

	if (!fake_ta_decrypt(value, data)) {
		return 0;
	}
	tmpref_buffer(op, 2)[0] ^= 1;
	return 1;
}

static void test_selftest_wrong_key(void **state)
{
	(void)state;
	expect_ta_command(TA_CMD_GEN_RANDOM, fake_ta_random, 0, TEEC_SUCCESS);
	expect_ta_command(TA_CMD_KEY_ENCRYPT, fake_ta_encrypt, 0, TEEC_SUCCESS);
	expect_ta_command(TA_CMD_KEY_DECRYPT, fake_ta_decrypt_wrong_key, 0,
			  TEEC_SUCCESS);

	assert_int_equal(encrypt_decrypt_selftest(), EXIT_FAILURE);
}

static void test_selftest_command(void **state)
{
	(void)state;
	expect_selftest(TEEC_SUCCESS, TEEC_SUCCESS, TEEC_SUCCESS);
	assert_int_equal(command("--encrypt-decrypt-selftest", NULL),
			 EXIT_SUCCESS);

	expect_selftest(TEEC_SUCCESS, TEEC_SUCCESS, TEEC_ERROR_GENERIC);
	assert_int_equal(command("--encrypt-decrypt-selftest", NULL),
			 EXIT_FAILURE);
	assert_non_null(strstr(
		output(), "Failed to pass encrypt and decrypt selftest\n"));
}

static void test_lock_status_command(void **state)
{
	(void)state;
	expect_ta_command(TA_CMD_GET_LOCK, fake_ta_value, 0, TEEC_SUCCESS);
	assert_int_equal(command("--ta-lock-status", NULL), EXIT_SUCCESS);
	expect_ta_command(TA_CMD_GET_LOCK, fake_ta_value, 1, TEEC_SUCCESS);
	assert_int_equal(command("--ta-lock-status", NULL), EXIT_SUCCESS);
	expect_ta_command(TA_CMD_GET_LOCK, fake_ta_value, 0,
			  TEEC_ERROR_GENERIC);
	assert_int_equal(command("--ta-lock-status", NULL), EXIT_FAILURE);

	assert_string_equal(output(), "Lock status: UNLOCKED\n"
				      "Lock status: LOCKED\n"
				      "TA operation fail, ret 0xffff0000\n");
}

static void test_lock_ta_command(void **state)
{
	(void)state;
	expect_ta_command(TA_CMD_LOCK, fake_ta_lock, 0, TEEC_SUCCESS);
	assert_int_equal(command("--lock-ta", NULL), EXIT_SUCCESS);
	expect_ta_command(TA_CMD_LOCK, fake_ta_lock, 0, TEEC_ERROR_GENERIC);
	assert_int_equal(command("--lock-ta", NULL), EXIT_FAILURE);

	assert_string_equal(output(), "TA is now locked\n"
				      "TA operation fail, ret 0xffff0000\n");
}

static void test_generate_random_command(void **state)
{
	(void)state;
	expect_ta_command(TA_CMD_GEN_RANDOM, fake_ta_random, 0, TEEC_SUCCESS);
	assert_int_equal(command("--generate-random", NULL), EXIT_SUCCESS);
	expect_ta_command(TA_CMD_GEN_RANDOM, fake_ta_random, 0, TEEC_SUCCESS);
	assert_int_equal(command("--generate-random", "16"), EXIT_SUCCESS);
	expect_ta_command(TA_CMD_GEN_RANDOM, fake_ta_random, 0,
			  TEEC_ERROR_GENERIC);
	assert_int_equal(command("--generate-random", "16"), EXIT_FAILURE);

	assert_string_equal(output(), RANDOM_65 "\n" RANDOM_16 "\n");
}

/* No TA command is expected, so the fake fails the test if it's called */
static void test_generate_random_bad_size(void **state)
{
	(void)state;
	assert_int_equal(command("--generate-random", "abc"), EXIT_FAILURE);
	assert_int_equal(command("--generate-random", "-1"), EXIT_FAILURE);
	assert_int_equal(command("--generate-random", "0"), EXIT_FAILURE);
	assert_int_equal(command("--generate-random", "12x"), EXIT_FAILURE);
	assert_int_equal(command("--generate-random", ""), EXIT_FAILURE);

	assert_string_equal(output(), "error: invalid buffer size (abc).\n"
				      "error: invalid buffer size (-1).\n"
				      "error: invalid buffer size (0).\n"
				      "error: invalid buffer size (12x).\n"
				      "error: invalid buffer size ().\n");
}

static void test_get_ta_version_command(void **state)
{
	(void)state;
	expect_ta_command(TA_CMD_TA_VERSION, fake_ta_value, FDE_TA_VERSION_V1,
			  TEEC_SUCCESS);
	assert_int_equal(command("--get-ta-version", NULL), EXIT_SUCCESS);
	expect_ta_command(TA_CMD_TA_VERSION, fake_ta_value, FDE_TA_VERSION_V1,
			  TEEC_ERROR_GENERIC);
	assert_int_equal(command("--get-ta-version", NULL), EXIT_FAILURE);

	assert_string_equal(output(),
			    "TA version: 0x10001\n"
			    "Failed to get TA version, ret 0xffff0000\n");
}

static void test_help_command(void **state)
{
	(void)state;
	assert_int_equal(command("--help", NULL), EXIT_SUCCESS);
	assert_output_starts_with("This binary should be invoked only under "
				  "specific context\n");
}

static void test_unknown_command(void **state)
{
	(void)state;
	assert_int_equal(command("--unknown", NULL), EXIT_FAILURE);
	assert_output_starts_with("error: NOT supported option(--unknown).\n");
}

#define TEST(test) cmocka_unit_test_setup_teardown(test, setup, teardown)

int main(void)
{
	const struct CMUnitTest tests[] = {
		TEST(test_reveal),
		TEST(test_reveal_ta_fails),
		TEST(test_reveal_bad_request),
		TEST(test_setup),
		TEST(test_setup_ta_fails),
		TEST(test_setup_bad_request),
		TEST(test_lock),
		TEST(test_features),
		TEST(test_bad_request),
		TEST(test_missing_op),
		TEST(test_null_op),
		TEST(test_unknown_hook),
		TEST(test_read_request),
		TEST(test_read_long_request),
		TEST(test_setup_snapctl),
		TEST(test_features_snapctl),
		TEST(test_snapctl_fails),
		TEST(test_selftest),
		TEST(test_selftest_fails),
		TEST(test_selftest_wrong_key),
		TEST(test_selftest_command),
		TEST(test_lock_status_command),
		TEST(test_lock_ta_command),
		TEST(test_generate_random_command),
		TEST(test_generate_random_bad_size),
		TEST(test_get_ta_version_command),
		TEST(test_help_command),
		TEST(test_unknown_command),
	};

	return cmocka_run_group_tests(tests, create_snapctl, remove_snapctl);
}
