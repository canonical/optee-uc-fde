# Builds the mock OP-TEE libraries in tests/mocks for unit tests. They are
# built with the native compiler, as unit tests run on the build machine.

out-dir := $(abspath $(O))
ifeq ($(out-dir),)
$(error invalid output directory (O=$(O)))
endif

CC		?= cc
AR		?= ar
PKG_CONFIG	?= pkg-config

CFLAGS += -std=gnu11 -Wall -Wextra
CFLAGS += $(shell $(PKG_CONFIG) --cflags cmocka)

mocks-dir := $(out-dir)/mocks

os-objs := $(patsubst %.c,$(mocks-dir)/%.o,$(wildcard optee-os/*.c))
client-objs := $(patsubst %.c,$(mocks-dir)/%.o,$(wildcard optee-client/*.c))

.PHONY: all
all: $(mocks-dir)/libmock-optee-os.a $(mocks-dir)/libmock-optee-client.a

$(mocks-dir)/libmock-optee-os.a: $(os-objs)
$(mocks-dir)/libmock-optee-client.a: $(client-objs)

$(mocks-dir)/%.a:
	@echo '  AR      $@'
	$(q)rm -f $@
	$(q)$(AR) rcs $@ $^

# Each mock's headers are next to its sources
$(mocks-dir)/%.o: %.c
	$(q)mkdir -p $(dir $@)
	@echo '  CC      $<'
	$(q)$(CC) $(CFLAGS) -I$(dir $<) -c $< -o $@

.PHONY: clean
clean:
	@echo '  CLEAN $(mocks-dir)'
	$(q)rm -rf $(mocks-dir)
