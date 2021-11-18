# grin
# ======

# $(1): source path
# $(2): build path
define do-configure-grin
	mkdir -p "$(2)"
	source $(PWD)/environment; \
	cd "$(2)"; \
	cmake "$(1)" \
	      -DCMAKE_CXX_LINK_FLAGS="-static-libgcc -static-libstdc++" \
	      -DCMAKE_C_LINK_FLAGS="-static-libgcc" \
	      -DCMAKE_INSTALL_PREFIX="$(INSTALL_PATH)" \
	      -DCMAKE_BUILD_TYPE="Debug" \
	      -DQEMU_INSTALL_PATH="$(INSTALL_PATH)" \
	      -DLLVM_DIR="$(INSTALL_PATH)/share/llvm/cmake" \
	      -DC_COMPILER_x86_64="$(INSTALL_PATH)/usr/x86_64-pc-linux-gnu/x86_64-gentoo-linux-musl/gcc-bin/4.9.3/x86_64-gentoo-linux-musl-gcc" \
	      -DC_COMPILER_mips="$(INSTALL_PATH)/usr/x86_64-pc-linux-gnu/mips-unknown-linux-musl/gcc-bin/5.3.0/mips-unknown-linux-musl-gcc" \
	      -DC_COMPILER_mipsel="$(INSTALL_PATH)/usr/x86_64-pc-linux-gnu/mipsel-unknown-linux-musl/gcc-bin/5.3.0/mipsel-unknown-linux-musl-gcc" \
	      -DC_COMPILER_i386="$(INSTALL_PATH)/usr/x86_64-pc-linux-gnu/i386-gentoo-linux-musl/gcc-bin/4.9.3/i386-gentoo-linux-musl-gcc" \
	      -DC_COMPILER_arm="$(INSTALL_PATH)/usr/x86_64-pc-linux-gnu/armv7a-hardfloat-linux-uclibceabi/gcc-bin/4.9.3/armv7a-hardfloat-linux-uclibceabi-gcc" \
	      -DC_COMPILER_s390x="$(INSTALL_PATH)/usr/x86_64-pc-linux-gnu/s390x-ibm-linux-musl/gcc-bin/7.3.0/s390x-ibm-linux-musl-gcc" \
	      -DBOOST_ROOT="$(INSTALL_PATH)" \
	      -DBoost_NO_SYSTEM_PATHS=On
endef


$(eval \
  $(call strip-call,simple-cmake-component, \
    grin, \
    , \
    , \
    $(LLVM_INSTALL_TARGET_FILE) \
      $(QEMU_INSTALL_TARGET_FILE) \
      $(BOOST_INSTALL_TARGET_FILE) \
      environment \
      $(TOOLCHAIN_INSTALL_TARGET_FILE)))
