# $(1): patch patch
# $(2): directory to patch from
define patch-if-exists
	if test -e "$(1)"; then cd "$(2)" && patch -p1 < "$(1)"; fi
endef

# binutils
# ========

$(eval BINUTILS_ARCHIVE=binutils-$(BINUTILS_VERSION).tar.bz2)
$(eval BINUTILS_PATH := $(INSTALL_PATH)/usr/x86_64-pc-linux-gnu/$(TRIPLE)/binutils-bin/$(BINUTILS_VERSION))
$(eval NEW_GCC_PATH := $(INSTALL_PATH)/usr/x86_64-pc-linux-gnu/$(TRIPLE)/gcc-bin/$(GCC_VERSION)/)
$(eval NEW_GCC := $(NEW_GCC_PATH)/$(TRIPLE)-gcc)
$(eval TOOLCHAIN_TARGET_PREFIX := toolchain/$(TOOLCHAIN)/)
$(eval TOOLCHAIN_VAR_PREFIX := TOOLCHAIN/$(call target-to-prefix,$(TOOLCHAIN))/)
$(eval BIN_PATH += usr/x86_64-pc-linux-gnu/$(TRIPLE)/binutils-bin/$(BINUTILS_VERSION))
$(eval BIN_PATH += usr/x86_64-pc-linux-gnu/$(TRIPLE)/gcc-bin/$(GCC_VERSION))

# Forward declarations for dependencies
$(eval $(TOOLCHAIN_VAR_PREFIX)GCC_STAGE1_INSTALL_TARGET_FILE := $(call install-target-file,$(TOOLCHAIN_TARGET_PREFIX)gcc-stage1))

# TODO: $(1) is unused
# $(1): remote-relative path of the repository to clone
# $(2): clone destination path
define do-clone-$(TOOLCHAIN_TARGET_PREFIX)binutils
$(call download-tar,$(2),https://ftp.gnu.org/gnu/binutils,$(BINUTILS_ARCHIVE))
endef

# $(1): source path
# $(2): build path
define do-configure-$(TOOLCHAIN_TARGET_PREFIX)binutils
	mkdir -p "$(2)"

	cd "$(2)" && "$(1)/configure" \
	    --build=x86_64-pc-linux-gnu \
	    --host=x86_64-pc-linux-gnu \
	    --target=$(TRIPLE) \
	    --with-sysroot=$(INSTALL_PATH)/usr/$(TRIPLE) \
	    --prefix=$(INSTALL_PATH)/usr \
	    --datadir=$(INSTALL_PATH)/usr/share/binutils-data/$(TRIPLE)/$(BINUTILS_VERSION) \
	    --infodir=$(INSTALL_PATH)/usr/share/binutils-data/$(TRIPLE)/$(BINUTILS_VERSION)/info \
	    --mandir=$(INSTALL_PATH)/usr/share/binutils-data/$(TRIPLE)/$(BINUTILS_VERSION)/man \
	    --bindir=$(INSTALL_PATH)/usr/x86_64-pc-linux-gnu/$(TRIPLE)/binutils-bin/$(BINUTILS_VERSION) \
	    --libdir=$(INSTALL_PATH)/usr/lib64/binutils/$(TRIPLE)/$(BINUTILS_VERSION) \
	    --libexecdir=$(INSTALL_PATH)/usr/lib64/binutils/$(TRIPLE)/$(BINUTILS_VERSION) \
	    --includedir=$(INSTALL_PATH)/usr/lib64/binutils/$(TRIPLE)/$(BINUTILS_VERSION)/include \
	    --without-included-gettext \
	    --with-zlib \
	    --enable-poison-system-directories \
	    --enable-secureplt \
	    --enable-obsolete \
	    --disable-shared \
	    --enable-threads \
	    --enable-install-libiberty \
	    --disable-werror \
	    --disable-static \
	    --disable-gdb \
	    --disable-libdecnumber \
	    --disable-readline \
	    --disable-sim \
	    --without-stage1-ldflags \
	    CFLAGS="-w -ggdb3 -O2" CXXFLAGS="-w -ggdb3 -O2"
endef

$(eval \
  $(call strip-call,simple-autotools-component, \
    $(TOOLCHAIN_TARGET_PREFIX)binutils))

# Linux headers
# =============

define do-build-$(TOOLCHAIN_TARGET_PREFIX)linux-headers
	make -C $(1) ARCH=$(LINUX_ARCH_NAME) INSTALL_HDR_PATH="$$$$DESTDIR$(INSTALL_PATH)/usr/$(TRIPLE)/usr" headers_install
endef

define do-install-$(TOOLCHAIN_TARGET_PREFIX)linux-headers
	make -C $(1) ARCH=$(LINUX_ARCH_NAME) INSTALL_HDR_PATH="$$$$DESTDIR$(INSTALL_PATH)/usr/$(TRIPLE)/usr" headers_install
endef

# $(1): source path
# $(2): build path
define do-configure-$(TOOLCHAIN_TARGET_PREFIX)linux-headers
	mkdir -p "$(2)"

$(call download-tar,$(2),https://cdn.kernel.org/pub/linux/kernel/v4.x,linux-$(LINUX_VERSION).tar.xz)

endef

$(eval \
  $(call strip-call,component-base, \
    $(TOOLCHAIN_VAR_PREFIX)LINUX_HEADERS, \
    $(TOOLCHAIN_TARGET_PREFIX)linux-headers, \
    $(TOOLCHAIN_TARGET_PREFIX)linux-headers))

$(eval \
  $(call strip-call,simple-component-build, \
     $(TOOLCHAIN_TARGET_PREFIX)linux-headers, \
     , \
     Makefile))

# GCC
# ===

# TODO: $(1) is unused
# $(1): remote-relative path of the repository to clone
# $(2): clone destination path
define do-clone-$(TOOLCHAIN_TARGET_PREFIX)gcc
$(call download-tar,$(2),https://ftp.gnu.org/gnu/gcc/gcc-$(GCC_VERSION),gcc-$(GCC_VERSION).tar.gz)

$(call patch-if-exists,$(PATCH_PATH)/gcc-$(GCC_VERSION)-cfns-fix-mismatch-in-gnu_inline-attributes.patch,$(2))
$(call patch-if-exists,$(PATCH_PATH)/gcc-$(GCC_VERSION)-cpp-musl-support.patch,$(2))
endef

# $(1): source path
# $(2): build path
# $(3): extra configure options
define do-configure-$(TOOLCHAIN_TARGET_PREFIX)gcc
	mkdir -p "$(2)"

	cd "$(2)" && "$(1)/configure" \
	        --host=x86_64-pc-linux-gnu \
	        --build=x86_64-pc-linux-gnu \
	        --target=$(TRIPLE) \
	        --prefix=$(INSTALL_PATH)/usr \
	        --bindir=$(INSTALL_PATH)/usr/x86_64-pc-linux-gnu/$(TRIPLE)/gcc-bin/$(GCC_VERSION) \
	        --includedir=$(INSTALL_PATH)/usr/lib/gcc/$(TRIPLE)/$(GCC_VERSION)/include \
	        --datadir=$(INSTALL_PATH)/usr/share/gcc-data/$(TRIPLE)/$(GCC_VERSION) \
	        --mandir=$(INSTALL_PATH)/usr/share/gcc-data/$(TRIPLE)/$(GCC_VERSION)/man \
	        --infodir=$(INSTALL_PATH)/usr/share/gcc-data/$(TRIPLE)/$(GCC_VERSION)/info \
	        --with-gxx-include-dir=$(INSTALL_PATH)/usr/lib/gcc/$(TRIPLE)/$(GCC_VERSION)/include/g++-v4 \
	        --with-sysroot=$(INSTALL_PATH)/usr/$(TRIPLE) \
	        --enable-obsolete \
	        --enable-secureplt \
	        --disable-werror \
	        --with-system-zlib \
	        --enable-nls \
	        --without-included-gettext \
	        --enable-checking=release \
	        --enable-libstdcxx-time \
	        --enable-poison-system-directories \
	        --disable-shared \
	        --disable-libatomic \
	        --disable-bootstrap \
	        --disable-multilib \
	        --disable-altivec \
	        --disable-fixed-point \
	        --disable-libgcj \
	        --disable-libgomp \
	        --disable-libmudflap \
	        --disable-libssp \
	        --disable-libcilkrts \
	        --disable-vtable-verify \
	        --disable-libvtv \
	        --disable-libquadmath \
	        --enable-lto \
	        --disable-libsanitizer \
	        --with-mpfr="$(INSTALL_PATH)" \
	        --with-mpc="$(INSTALL_PATH)" \
	        --with-gmp="$(INSTALL_PATH)" \
	        $(EXTRA_GCC_CONFIGURE_OPTIONS) \
	        $(3) \
	        CFLAGS="-w -ggdb3 -O2" CXXFLAGS="-w -ggdb3 -O2"
endef

define do-configure-$(TOOLCHAIN_TARGET_PREFIX)gcc-stage1
$(call do-configure-$(TOOLCHAIN_TARGET_PREFIX)gcc,$(1),$(2),--enable-languages=c)
endef

define do-configure-$(TOOLCHAIN_TARGET_PREFIX)gcc-stage2
$(call do-configure-$(TOOLCHAIN_TARGET_PREFIX)gcc,$(1),$(2),--enable-languages=c$(COMMA)c++)
endef

$(eval \
  $(call strip-call,autotools-component-source, \
    $(TOOLCHAIN_TARGET_PREFIX)gcc, \
    -stage2))

ifdef MUSL_VERSION

# musl
# ====

# headers
# -------

# $(1): source path
# $(2): build path
define do-configure-$(TOOLCHAIN_TARGET_PREFIX)musl-common
	mkdir -p "$(2)"

$(call download-tar,$(2),http://www.musl-libc.org/releases/,musl-$(MUSL_VERSION).tar.gz)

$(call patch-if-exists,$(PATCH_PATH)/musl-$(MUSL_VERSION)-printf-floating-point-rounding.patch,$(2))

endef

# Recent versions of musl have changed the path of the generated file alltypes.h
# and we want take it into account without checking explicitly for specific musl
define do-build-$(TOOLCHAIN_TARGET_PREFIX)musl-headers
	make -C $(1) include/bits/alltypes.h || make -C $(1) obj/include/bits/alltypes.h
endef

define do-install-$(TOOLCHAIN_TARGET_PREFIX)musl-headers
	make -C $(1) include/bits/alltypes.h || make -C $(1) obj/include/bits/alltypes.h
	make -C $(1) install-headers
endef

# $(1): source path
# $(2): build path
define do-configure-$(TOOLCHAIN_TARGET_PREFIX)musl-headers
$(call do-configure-$(TOOLCHAIN_TARGET_PREFIX)musl-common,$(1),$(2))
	cd "$(2)" && CC=true "$(2)/configure" \
	        --target=$(TRIPLE) \
	        --prefix="$(INSTALL_PATH)/usr/$(TRIPLE)/usr" \
	        --syslibdir="$(INSTALL_PATH)/usr/$(TRIPLE)/lib" \
	        --disable-gcc-wrapper
endef

# $(1): source path
# $(2): build path
# $(3): extra flags variable name
define do-configure-$(TOOLCHAIN_TARGET_PREFIX)musl
$(call do-configure-$(TOOLCHAIN_TARGET_PREFIX)musl-common,$(1),$(2))
	source $(PWD)/environment; \
	cd "$(2)" && CC="$(NEW_GCC)" \
	CFLAGS="$(MUSL_CFLAGS) $($(3))" \
	"$(2)/configure" \
	        --target=$(TRIPLE) \
	        --prefix="$(INSTALL_PATH)/usr/$(TRIPLE)/usr" \
	        --syslibdir="$(INSTALL_PATH)/usr/$(TRIPLE)/lib" \
	        --disable-gcc-wrapper
endef

define do-build-$(TOOLCHAIN_TARGET_PREFIX)musl
	source $(PWD)/environment; \
	make -C $(1)
endef

define do-install-$(TOOLCHAIN_TARGET_PREFIX)musl
	source $(PWD)/environment; \
	make -C $(1); \
	make -C $(1) install
endef

# $(1): build suffix
# $(2): extra flags variable name
define $(TOOLCHAIN_TARGET_PREFIX)musl-template

define do-configure-$(TOOLCHAIN_TARGET_PREFIX)musl$(1)
$$(call do-configure-$(TOOLCHAIN_TARGET_PREFIX)musl,$$(1),$$(2),$(2))
endef

define do-build-$(TOOLCHAIN_TARGET_PREFIX)musl$(1)
$$(call do-build-$(TOOLCHAIN_TARGET_PREFIX)musl,$$(1),$$(2),$(2))
endef

define do-install-$(TOOLCHAIN_TARGET_PREFIX)musl$(1)
$$(call do-install-$(TOOLCHAIN_TARGET_PREFIX)musl,$$(1),$$(2),$(2))
endef

$$(eval \
  $$(call strip-call,simple-component-build, \
    $(TOOLCHAIN_TARGET_PREFIX)musl, \
    $(1), \
    config.log, \
    $($(TOOLCHAIN_VAR_PREFIX)GCC_STAGE1_INSTALL_TARGET_FILE) environment, \
    -headers))

$(TOOLCHAIN_VAR_PREFIX)LIBC$(call target-to-prefix,$(1))_INSTALL_TARGET_FILE := $$($(TOOLCHAIN_VAR_PREFIX)MUSL$(call target-to-prefix,$(1))_INSTALL_TARGET_FILE)
$(TOOLCHAIN_TARGET_PREFIX)libc$(1): $(TOOLCHAIN_TARGET_PREFIX)musl$(1)

endef

$(eval \
  $(call strip-call,component-base, \
    $(TOOLCHAIN_VAR_PREFIX)MUSL, \
    $(TOOLCHAIN_TARGET_PREFIX)musl, \
    $(TOOLCHAIN_TARGET_PREFIX)musl-$(LIBC_DEFAULT_CONFIG)))

# -headers
#$(eval $(call component-base,$(TOOLCHAIN_VAR_PREFIX)MUSL_HEADERS,$(TOOLCHAIN_TARGET_PREFIX)musl-headers,$(TOOLCHAIN_TARGET_PREFIX)musl-headers))
$(eval \
  $(call strip-call,simple-component-build, \
    $(TOOLCHAIN_TARGET_PREFIX)musl, \
    -headers, \
    config.log))

$(TOOLCHAIN_VAR_PREFIX)LIBC_HEADERS_INSTALL_TARGET_FILE := $($(TOOLCHAIN_VAR_PREFIX)MUSL_HEADERS_INSTALL_TARGET_FILE)
$(TOOLCHAIN_TARGET_PREFIX)libc-headers: $(TOOLCHAIN_TARGET_PREFIX)musl-headers

# Actual builds
$(foreach LIBC_CONFIG,$(LIBC_CONFIGS),$(eval $(call $(TOOLCHAIN_TARGET_PREFIX)musl-template,-$(LIBC_CONFIG),LIBC_CONFIG_$(call target-to-prefix,$(LIBC_CONFIG))_FLAGS)))

$(TOOLCHAIN_VAR_PREFIX)LIBC_INSTALL_TARGET_FILE := $($(TOOLCHAIN_VAR_PREFIX)MUSL_INSTALL_TARGET_FILE)
$(TOOLCHAIN_TARGET_PREFIX)libc: $(TOOLCHAIN_TARGET_PREFIX)musl
clean-$(TOOLCHAIN_TARGET_PREFIX)libc: clean-$(TOOLCHAIN_TARGET_PREFIX)musl
configure-$(TOOLCHAIN_TARGET_PREFIX)libc: configure-$(TOOLCHAIN_TARGET_PREFIX)musl
build-$(TOOLCHAIN_TARGET_PREFIX)libc: build-$(TOOLCHAIN_TARGET_PREFIX)musl
install-$(TOOLCHAIN_TARGET_PREFIX)libc: install-$(TOOLCHAIN_TARGET_PREFIX)musl
test-$(TOOLCHAIN_TARGET_PREFIX)libc: test-$(TOOLCHAIN_TARGET_PREFIX)musl

endif

# Create GCC builds
$(eval \
  $(call strip-call,autotools-component-build, \
    $(TOOLCHAIN_TARGET_PREFIX)gcc, \
    -stage1, \
    $($(TOOLCHAIN_VAR_PREFIX)LIBC_HEADERS_INSTALL_TARGET_FILE) \
      $($(TOOLCHAIN_VAR_PREFIX)LINUX_HEADERS_INSTALL_TARGET_FILE) \
      $($(TOOLCHAIN_VAR_PREFIX)BINUTILS_INSTALL_TARGET_FILE)))

$(eval \
  $(call strip-call,autotools-component-build, \
    $(TOOLCHAIN_TARGET_PREFIX)gcc, \
    -stage2, \
    , \
    -stage1, \
    $($(TOOLCHAIN_VAR_PREFIX)LIBC_INSTALL_TARGET_FILE) \
      $($(TOOLCHAIN_VAR_PREFIX)LINUX_HEADERS_INSTALL_TARGET_FILE) \
      $($(TOOLCHAIN_VAR_PREFIX)BINUTILS_INSTALL_TARGET_FILE)))

# toolchain
# =========

.PHONY: toolchain/$(TOOLCHAIN) clean-toolchain/$(TOOLCHAIN) configure-toolchain/$(TOOLCHAIN) build-toolchain/$(TOOLCHAIN) install-toolchain/$(TOOLCHAIN) test-toolchain/$(TOOLCHAIN)
toolchain/$(TOOLCHAIN): $(TOOLCHAIN_TARGET_PREFIX)gcc
clean-toolchain/$(TOOLCHAIN): clean-$(TOOLCHAIN_TARGET_PREFIX)gcc clean-$(TOOLCHAIN_TARGET_PREFIX)binutils clean-$(TOOLCHAIN_TARGET_PREFIX)linux-headers clean-$(TOOLCHAIN_TARGET_PREFIX)coreutils clean-$(TOOLCHAIN_TARGET_PREFIX)libc
configure-toolchain/$(TOOLCHAIN): configure-$(TOOLCHAIN_TARGET_PREFIX)gcc
build-toolchain/$(TOOLCHAIN): build-$(TOOLCHAIN_TARGET_PREFIX)gcc
install-toolchain/$(TOOLCHAIN): install-$(TOOLCHAIN_TARGET_PREFIX)gcc
test-toolchain/$(TOOLCHAIN): test-$(TOOLCHAIN_TARGET_PREFIX)gcc

.PHONY: toolchain clean-toolchain configure-toolchain build-toolchain install-toolchain test-toolchain
toolchain: toolchain/$(TOOLCHAIN)
clean-toolchain: clean-toolchain/$(TOOLCHAIN)
configure-toolchain: configure-toolchain/$(TOOLCHAIN)
build-toolchain: build-toolchain/$(TOOLCHAIN)
install-toolchain: install-toolchain/$(TOOLCHAIN)
test-toolchain: test-toolchain/$(TOOLCHAIN)


$(eval TOOLCHAIN_INSTALL_TARGET_FILE += $(if $(filter all,$(DEFAULT_TOOLCHAINS))$(filter $(TOOLCHAIN),$(DEFAULT_TOOLCHAINS)),$($(TOOLCHAIN_VAR_PREFIX)GCC_STAGE2_INSTALL_TARGET_FILE),))