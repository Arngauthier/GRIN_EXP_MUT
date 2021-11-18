# grin-c
# =======

# $(1): source path
# $(2): build path
define do-configure-grin-c
	mkdir -p "$(2)"
	source $(PWD)/environment; \
	cd "$(2)"; \
	cmake "$(1)" \
	      -DCMAKE_CXX_LINK_FLAGS="-static-libgcc -static-libstdc++" \
	      -DCMAKE_INSTALL_PREFIX="$(INSTALL_PATH)" \
	      -DCMAKE_BUILD_TYPE="Debug" \
	      -DLLVM_DIR="$(INSTALL_PATH)/share/llvm/cmake"
endef

$(eval \
  $(call strip-call,simple-cmake-component, \
    grin-c, \
    , \
    , \
    $(REVAMB_INSTALL_TARGET_FILE) \
      environment))
