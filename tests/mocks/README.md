# Mock OP-TEE headers and libraries

Minimal stand-ins for the OP-TEE APIs used by this repository, so the code can
be checked and unit tested natively without the OP-TEE TA dev kit or
optee_client:

- `optee-os/`: the TA side (GP TEE Internal Core API and OP-TEE extensions),
  used by `ta/`.
- `optee-client/`: the normal world side (GP TEE Client API), used by `host/`.

The headers only declare what the code uses, with the types, signatures and
values of OP-TEE 4.x. When the code starts using something new from OP-TEE,
add it here as well, copying its definition from the real header, and add a
fake for any new function.

`make tidy` uses the headers to run clang-tidy. `make mocks` builds the fakes
into `out/mocks/libmock-optee-os.a` and `out/mocks/libmock-optee-client.a`,
which need [cmocka](https://cmocka.org) 2.0 (`libcmocka-dev` in Ubuntu 26.04).

## Fakes

The fakes are controlled with cmocka from each test:

- Inputs are checked with `check_expected_*()`, so every call needs an
  expectation such as `expect_uint_value()` or `expect_memory()`, or
  `expect_any()` when the test doesn't care about a parameter. cmocka 2.0
  deprecates the untyped `expect_value()`: compare pointers with
  `expect_uint_value()` and a `uintptr_t` cast. To look at or fill in a
  `params` array, use `expect_check_data()` with a check function.
- Return values come from `will_return_uint()`.
- Outputs (handles, buffers and their lengths) come from
  `will_set_parameter_ptr()` and `will_set_parameter_uint()`, under the
  output parameter's name. They are only read when the call succeeds.
- `TEE_Panic()` fails the test, unless the test expects it with
  `expect_assert_failure()`.

Memory handling and tracing are real, not faked:

- `TEE_Malloc()` and `TEE_Free()` use cmocka's `test_calloc()` and
  `test_free()`, so cmocka fails tests that leak memory.
- `memzero_explicit()` really clears the buffer.
- `EMSG()`, `DMSG()` and `MSG_RAW()` discard their messages.

The TEE Client API context and session are allocated by the code under test,
so their fakes don't check them. `TEEC_FinalizeContext()` and
`TEEC_CloseSession()` take part in `expect_function_call()` instead.

For example, a test where the TA allocates an AES-GCM operation:

```c
static int op;

expect_uint_value(TEE_AllocateOperation, algorithm, TEE_ALG_AES_GCM);
expect_uint_value(TEE_AllocateOperation, mode, TEE_MODE_ENCRYPT);
expect_uint_value(TEE_AllocateOperation, maxKeySize, 256);
will_return_uint(TEE_AllocateOperation, TEE_SUCCESS);
will_set_parameter_ptr(TEE_AllocateOperation, operation, &op);

/* ... and checks it's freed again */
expect_uint_value(TEE_FreeOperation, operation, (uintptr_t)&op);
```
