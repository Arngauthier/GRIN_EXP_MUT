# LLVM
# ====

# $(1): source path
# $(2): build path
# $(3): CMAKE_BUILD_TYPE
define do-configure-llvm
	mkdir -p "$(2)"

	cd "$(2)"; \
	cmake "$(1)" \
	      -DCMAKE_BUILD_TYPE=$(3) \
	      -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc -static-libstdc++" \
	      -DCMAKE_SHARED_LINKER_FLAGS="-static-libgcc -static-libstdc++" \
	      -DLLVM_TARGETS_TO_BUILD="X86" \
	      -DCMAKE_INSTALL_PREFIX="$(INSTALL_PATH)" \
	      -DBUILD_SHARED_LIBS=ON \
	      -DLLVM_ENABLE_DUMP=ON \
	      -Wno-dev
endef

define do-configure-llvm-debug
$(call do-configure-llvm,$(1),$(2),Debug)
endef

define do-configure-llvm-release
$(call do-configure-llvm,$(1),$(2),RelWithDebInfo)
endef

CLANG_SOURCE_PATH := $(SOURCE_PATH)/llvm/tools/clang
CLANG_SOURCE_TARGET_FILE := $(CLANG_SOURCE_PATH)/CMakeLists.txt
.PHONY: clone-clang
clone-clang: $(CLANG_SOURCE_TARGET_FILE)
$(CLANG_SOURCE_TARGET_FILE):
	$(call clone,clang,$(CLANG_SOURCE_PATH))
	$(call touch,$(CLANG_SOURCE_TARGET_FILE))

$(eval \
  $(call strip-call, \
    multi-build-cmake-component, \
    llvm, \
    release, \
    $(CLANG_SOURCE_TARGET_FILE), \
    , \
    , \
    release, \
    debug))
