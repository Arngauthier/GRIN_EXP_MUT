# llvmcpy
# =======

define do-build-llvmcpy
	cd "$(2)" && python3 setup.py build --build-base "$(1)"
endef

define do-install-llvmcpy
	export PYTHONPATH="$$$$DESTDIR$(INSTALL_PATH)/lib/python"; \
	mkdir -p "$$$$PYTHONPATH"; \
	cd "$(2)" && python3 setup.py build --build-base $(1) install --home "$$$$DESTDIR$(INSTALL_PATH)"
endef

# $(1): source path
# $(2): build path
define do-configure-llvmcpy
	mkdir -p "$(2)"
endef

$(eval $(call simple-component-source,llvmcpy))
$(eval $(call simple-component-build,llvmcpy,,,$(LLVM_INSTALL_TARGET_FILE)))
