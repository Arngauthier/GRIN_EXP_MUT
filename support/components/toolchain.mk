# Toolchains
# ==========

$(call option,COREUTILS_VERSION,8.29,Version of coreutils to build)

$(call option,LIBC_CONFIGS,default gc-o0 gc-o1 gc-o2 gc-o3,Name of the configurations of the libc to compile)
$(call option,LIBC_DEFAULT_CONFIG,default,Name of the default configuration to use for the libc)
$(eval LIBC_CONFIG_DEFAULT_FLAGS ?= -ggdb3)
$(eval LIBC_CONFIG_GC_O0_FLAGS ?= -ggdb3 -Wl$$(COMMA)--gc-sections -ffunction-sections -O0)
$(eval LIBC_CONFIG_GC_O1_FLAGS ?= -ggdb3 -Wl$$(COMMA)--gc-sections -ffunction-sections -O1)
$(eval LIBC_CONFIG_GC_O2_FLAGS ?= -ggdb3 -Wl$$(COMMA)--gc-sections -ffunction-sections -O2)
$(eval LIBC_CONFIG_GC_O3_FLAGS ?= -ggdb3 -Wl$$(COMMA)--gc-sections -ffunction-sections -O3)
$(foreach LIBC_CONFIG,$(LIBC_CONFIGS),$(call option,LIBC_CONFIG_$(call target-to-prefix,$(LIBC_CONFIG))_FLAGS,$(LIBC_CONFIG_$(call target-to-prefix,$(LIBC_CONFIG))_FLAGS),Compile flags for $(LIBC_CONFIG)))

# $(1): target prefix for toolchain
define prepare-for-toolchain
$(strip
$(eval TOOLCHAIN := $(1))
$(eval TMP := $(call target-to-prefix,$(1)))
$(eval TRIPLE := $($(TMP)_TRIPLE))
$(eval LINUX_ARCH_NAME := $($(TMP)_LINUX_ARCH_NAME))
$(eval UCLIBC_ARCH_NAME := $($(TMP)_UCLIBC_ARCH_NAME))
$(eval BINUTILS_VERSION := $($(TMP)_BINUTILS_VERSION))
$(eval MUSL_VERSION := $($(TMP)_MUSL_VERSION))
$(eval UCLIBC_VERSION := $($(TMP)_UCLIBC_VERSION))
$(eval LINUX_VERSION := $($(TMP)_LINUX_VERSION))
$(eval GCC_VERSION := $($(TMP)_GCC_VERSION))
$(eval EXTRA_GCC_CONFIGURE_OPTIONS := $($(TMP)_EXTRA_GCC_CONFIGURE_OPTIONS))
$(eval MUSL_CFLAGS := $($(TMP)_MUSL_CFLAGS))
$(eval DYNAMIC := $($(TMP)_DYNAMIC))
)
endef

include support/components/toolchains-dependencies.mk

include support/components/toolchains-list.mk
