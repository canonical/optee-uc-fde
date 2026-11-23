/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2026, Canonical Ltd.
 */

#ifndef FDE_KEY_MANAGER_H_
#define FDE_KEY_MANAGER_H_

#include <stddef.h>

struct json_object;

// snapctl fde-setup-request and fde-setup-result
extern char *get_snap_hook_fde_setup_request(void);
extern int set_snap_hook_fde_setup_request_result(const char *result,
						  size_t len);
// pass a hook result to stdout, or to snapctl when running as a snap hook
extern int set_result(const char *result, size_t len);
// read a hook request from stdin
extern char *get_initrd_fde_request(void);

extern int handle_operation_reveal(struct json_object *request_json);
extern int handle_operation_lock(void);
extern int handle_operation_setup(struct json_object *request_json);
extern int handle_operation_feature(void);
extern int handle_fde_operation(char *request_str);
extern int encrypt_decrypt_selftest(void);

// the hooks and test commands, called by main()
extern int fde_key_manager_main(int argc, char *argv[]);
#endif // FDE_KEY_MANAGER_H_
