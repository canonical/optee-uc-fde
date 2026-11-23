ifeq ($O,)
out-dir := $(CURDIR)/out
else
out-dir := $(abspath $(O))
ifeq ($(out-dir),)
$(error invalid output directory (O=$(O)))
endif
endif

-include $(TA_DEV_KIT_DIR)/host_include/conf.mk

ifneq ($V,1)
	q := @
	echo := @echo
else
	q :=
	echo := @:
endif
# export 'q', used by sub-makefiles.
export q

# If _HOST or _TA specific compilers are not specified, then use CROSS_COMPILE
CROSS_COMPILE_HOST ?= $(CROSS_COMPILE)
CROSS_COMPILE_TA ?= $(CROSS_COMPILE)

.PHONY: all
all: ta fde-reveal-key fde-setup fde-key-manager

.PHONY: fde-reveal-key
fde-reveal-key:
	$(q)$(MAKE) -C host/fde_key_manager CROSS_COMPILE="$(CROSS_COMPILE_HOST)" \
			     --no-builtin-variables \
			     O=$(out-dir) \
			     $@

.PHONY: fde-setup
fde-setup:
	$(q)$(MAKE) -C host/fde_key_manager CROSS_COMPILE="$(CROSS_COMPILE_HOST)" \
			     --no-builtin-variables \
			     O=$(out-dir) \
			     $@

.PHONY: fde-key-manager
fde-key-manager:
	$(q)$(MAKE) -C host/fde_key_manager CROSS_COMPILE="$(CROSS_COMPILE_HOST)" \
			     --no-builtin-variables \
			     O=$(out-dir) \
			     $@

.PHONY: ta
ta:
	$(q)$(MAKE) -C ta CROSS_COMPILE="$(CROSS_COMPILE_TA)" \
			  O=$(out-dir) \
			  $@

# Mock OP-TEE libraries for unit tests, built natively
.PHONY: mocks
mocks:
	$(q)$(MAKE) -C tests/mocks O=$(out-dir)

# Unit tests, see tests/unit/README.md
.PHONY: unit-test
unit-test: mocks
	$(q)$(MAKE) -C tests/unit O=$(out-dir)

.PHONY: clean
clean:
	${q}if [ -d $(out-dir)/fde_key_manager ]; then $(MAKE) -C host/fde_key_manager O=$(out-dir) $@; fi
	${q}if [ -d $(out-dir)/ta ]; then $(MAKE) -C ta O=$(out-dir) $@; fi
	${q}if [ -d $(out-dir)/mocks ]; then $(MAKE) -C tests/mocks O=$(out-dir) $@; fi
	${q}if [ -d $(out-dir)/unit-tests ]; then $(MAKE) -C tests/unit O=$(out-dir) $@; fi

# Formatting and static analysis, see .clang-format and .clang-tidy.
# base64.[ch] are imported from mbedtls and keep their upstream style.
CLANG_FORMAT ?= clang-format
CLANG_TIDY ?= clang-tidy
# Extra clang-tidy options, e.g. TIDY_FLAGS=--warnings-as-errors='*'
TIDY_FLAGS ?=

FORMAT_SRCS := $(filter-out %/base64.c %/base64.h, \
		 $(wildcard host/*/*.[ch] ta/*/*.[ch] ta/*/include/*.h \
			    tests/mocks/*/*.[ch] tests/unit/*/*.[ch]))

# clang-tidy uses the mock OP-TEE headers in tests/mocks, so it needs neither
# the OP-TEE SDKs nor a build. The host code also needs libjson-c-dev.
TIDY_HOST_SRCS := $(filter-out %/base64.c,$(wildcard host/*/*.c))
TIDY_TA_SRCS := $(wildcard ta/*/*.c)
TIDY_CFLAGS := -std=gnu11 -Ita/fde_key_handler/include

.PHONY: format
format:
	$(echo) '  FORMAT  $(FORMAT_SRCS)'
	$(q)$(CLANG_FORMAT) -i $(FORMAT_SRCS)

.PHONY: check-format
check-format:
	$(echo) '  CHECK   $(FORMAT_SRCS)'
	$(q)$(CLANG_FORMAT) --dry-run --Werror $(FORMAT_SRCS)

.PHONY: tidy
tidy:
	$(echo) '  TIDY    $(TIDY_HOST_SRCS)'
	$(q)$(CLANG_TIDY) --quiet $(TIDY_FLAGS) $(TIDY_HOST_SRCS) -- \
		$(TIDY_CFLAGS) -Itests/mocks/optee-client
	$(echo) '  TIDY    $(TIDY_TA_SRCS)'
	$(q)$(CLANG_TIDY) --quiet $(TIDY_FLAGS) $(TIDY_TA_SRCS) -- \
		$(TIDY_CFLAGS) -Itests/mocks/optee-os

.PHONY: lint
lint: check-format tidy

install:
	$(echo) '  INSTALL ${DESTDIR}/lib/optee_armtz'
	$(q)if [ -d $(out-dir)/ta ]; then mkdir -p ${DESTDIR}/lib/optee_armtz; find $(out-dir)/ta -name \*.ta -exec cp -a {} ${DESTDIR}/lib/optee_armtz \; ;fi
	$(echo) '  INSTALL ${DESTDIR}/usr/bin'
	$(q)mkdir -p ${DESTDIR}/usr/bin
	$(q)if [ -e $(out-dir)/fde_key_manager/fde-key-manager ]; then cp -a $(out-dir)/fde_key_manager/fde-key-manager ${DESTDIR}/usr/bin; fi
	$(q)if [ -e $(out-dir)/fde_key_manager/fde-reveal-key ]; then cp -a $(out-dir)/fde_key_manager/fde-reveal-key ${DESTDIR}/usr/bin; fi
	$(q)if [ -e $(out-dir)/fde_key_manager/fde-setup ]; then cp -a $(out-dir)/fde_key_manager/fde-setup ${DESTDIR}/usr/bin; fi
