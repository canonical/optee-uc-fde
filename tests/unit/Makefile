# Builds and runs the unit tests in tests/unit with cmocka and the mock
# OP-TEE libraries from tests/mocks. They are built with the native compiler
# and run on the build machine. See README.md for how tests are organised.

out-dir := $(abspath $(O))
ifeq ($(out-dir),)
$(error invalid output directory (O=$(O)))
endif

CC		?= cc
PKG_CONFIG	?= pkg-config

root := $(abspath ../..)
tests-dir := $(out-dir)/unit-tests
mocks-dir := $(out-dir)/mocks

CFLAGS += -std=gnu11 -Wall -Wextra -g
CFLAGS += $(shell $(PKG_CONFIG) --cflags cmocka)
LDLIBS += $(shell $(PKG_CONFIG) --libs cmocka)

# Fail tests on memory errors, leaks and undefined behaviour. cmocka only
# checks the TA's TEE_Malloc() memory, these also check the host code.
SANITIZE ?= -fsanitize=address,undefined -fno-sanitize-recover=all
CFLAGS += $(SANITIZE)

ta-cflags := -I$(root)/ta/fde_key_handler \
	     -I$(root)/ta/fde_key_handler/include \
	     -I$(root)/tests/mocks/optee-os
# Only expanded when a host test is built
host-cflags = -I$(root)/host/fde_key_manager \
	      -I$(root)/ta/fde_key_handler/include \
	      -I$(root)/tests/mocks/optee-client \
	      $(shell $(PKG_CONFIG) --cflags json-c)
host-ldlibs = $(shell $(PKG_CONFIG) --libs json-c)
# Linked into every host test, so host tests only fake the TEE Client API
host-helpers := $(root)/host/fde_key_manager/base64.c \
		$(root)/host/fde_key_manager/fde_key_manager_ca.c

ta-tests := $(patsubst %.c,$(tests-dir)/%,$(wildcard ta/test_*.c))
host-tests := $(patsubst %.c,$(tests-dir)/%,$(wildcard host/test_*.c))
tests := $(strip $(ta-tests) $(host-tests))

.PHONY: all
all: run

.PHONY: build
build: $(tests)

# Run every test, then fail if any of them failed
.PHONY: run
run: build
ifeq ($(tests),)
	@echo '  No unit tests found'
else
	$(q)failed=0; \
	for t in $(tests); do \
		echo "  RUN     $${t#$(tests-dir)/}"; \
		"$$t" || failed=1; \
	done; \
	exit $$failed
endif

# test_<name>.c tests <name>.c, linked with the mocks. $^ lists each file
# once, even when the tested file is also one of the host helpers. Tests are
# rebuilt when a header shared by the tests in their directory changes.
$(tests-dir)/ta/test_%: ta/test_%.c $(root)/ta/fde_key_handler/%.c \
			$(mocks-dir)/libmock-optee-os.a $(wildcard ta/*.h)
	$(q)mkdir -p $(dir $@)
	@echo '  CC      $<'
	$(q)$(CC) $(CFLAGS) $(ta-cflags) -o $@ $(filter-out %.h,$^) $(LDLIBS)

$(tests-dir)/host/test_%: host/test_%.c $(root)/host/fde_key_manager/%.c \
			  $(host-helpers) $(mocks-dir)/libmock-optee-client.a \
			  $(wildcard host/*.h)
	$(q)mkdir -p $(dir $@)
	@echo '  CC      $<'
	$(q)$(CC) $(CFLAGS) $(host-cflags) -o $@ $(filter-out %.h,$^) \
		$(LDLIBS) $(host-ldlibs)

.PHONY: clean
clean:
	@echo '  CLEAN $(tests-dir)'
	$(q)rm -rf $(tests-dir)
