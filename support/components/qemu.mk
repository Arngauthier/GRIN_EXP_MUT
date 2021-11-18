# QEMU
# ====

# $(1): source path
# $(2): build path
# $(3): extra configure flags
define do-configure-qemu-common
	   mkdir -p "$(2)"
	   cd "$(2)"; \
	export LLVM_CONFIG="$(INSTALL_PATH)/bin/llvm-config"; \
	   "$(1)/configure" \
	       --prefix="$(INSTALL_PATH)" \
	       --target-list=" \
	           x86_64-libtinycode \
	           x86_64-linux-user \
	           " \
	       --disable-werror \
	       --enable-llvm-helpers \
	       --disable-kvm \
	       --without-pixman \
	       --disable-tools \
	       --disable-system \
	       --python=$(shell which python2) \
	       $(3)
endef

define do-configure-qemu-debug
$(call do-configure-qemu-common,$(1),$(2),--enable-debug --extra-cflags="-ggdb -O0")
endef

define do-configure-qemu-release
$(call do-configure-qemu-common,$(1),$(2),--extra-cflags="-ggdb")
endef

$(eval \
  $(call strip-call,autotools-component-source, \
    qemu, \
    -debug))

$(eval \
  $(call strip-call,autotools-component-build, \
    qemu, \
    -debug, \
    $(LLVM_INSTALL_TARGET_FILE)))

$(eval \
  $(call strip-call,autotools-component-build, \
    qemu, \
    -release, \
    $(LLVM_INSTALL_TARGET_FILE)))
