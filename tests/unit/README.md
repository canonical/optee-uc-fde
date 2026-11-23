# Unit tests

Unit tests for the TA and host code, written with
[cmocka](https://cmocka.org) 2.0. They run natively on the build machine
against the mock OP-TEE APIs in `tests/mocks`, so they need neither OP-TEE nor
QEMU. Run them with:

```sh
make unit-test
```

This needs `libcmocka-dev` and `libjson-c-dev`.

## Adding tests

Each test file tests one source file, and is built into its own binary:

| Test file, in `tests/unit` | Tests                           | Mocks                      |
|----------------------------|---------------------------------|----------------------------|
| `ta/test_<name>.c`         | `ta/fde_key_handler/<name>.c`   | `tests/mocks/optee-os`     |
| `host/test_<name>.c`       | `host/fde_key_manager/<name>.c` | `tests/mocks/optee-client` |

Only that source file is linked into the test, so anything else it calls must
be faked in the test file. See `tests/mocks/README.md` for how to control the
OP-TEE fakes.

A test file is a normal cmocka program:

```c
#include <cmocka.h>

#include <tee_internal_api.h>

#include "fde_key_handler_ta_handle.h"

static void test_something(void **state)
{
	(void)state;
	...
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_something),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
```
