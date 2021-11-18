# Is this a blatant abuse of Makefiles?
# Only time will say.

.SUFFIXES:
MAKEFLAGS += -r
COMMA := ,
SPACE :=
SPACE +=
LPAR := (
RPAR := )
SHELL := /bin/bash -e

include support/seq.mk

# TODO:
#
# * Time, get peak memory consumption and size targets

# Make sure all is the default build target, we will define it at the end
.PHONY: help
help:

# Include infrastructure files
# ============================

include support/option.mk

define strip-call
$(call $(strip $(1)),$(strip $(2)),$(strip $(3)),$(strip $(4)),$(strip $(5)),$(strip $(6)),$(strip $(7)),$(strip $(8)),$(strip $(9)),$(strip $(10)),$(strip $(11)),$(strip $(12)),$(strip $(13)),$(strip $(14)),$(strip $(15)))
endef

$(call strip-call,option, \
  DEFAULT_TOOLCHAINS, \
  all, \
  List of toolchains to build along with grin)



include support/component.mk

# Global configuration
# ====================

$(eval BIN_PATH := bin)

$(call patch-if-exists,$(PATCH_PATH)/boost-1.63.0-ignore-Wparentheses-warnings.patch,$(2))


# environment
# ===========

define print-prepend-path
	echo 'export PATH="$$INSTALL_PATH/$(1)$${PATH:+:$${PATH}}"' >> environment

endef

environment: Makefile
	echo 'INSTALL_PATH="$(INSTALL_PATH)"' > environment
	echo >> environment
	$(foreach path,$(BIN_PATH),$(call print-prepend-path,$(path)))
	echo >> environment
	echo 'export LD_LIBRARY_PATH="$$INSTALL_PATH/lib$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}"' >> environment
	echo >> environment
	echo 'export PYTHONPATH="$$INSTALL_PATH/lib/python$${PYTHONPATH:+:$${PYTHONPATH}}"' >> environment
	echo >> environment
	echo 'export QML2_IMPORT_PATH="$$INSTALL_PATH/lib/qt5/qml"' >> environment
	echo >> environment
	echo 'unset INSTALL_PATH' >> environment


# Components
# ==========

include support/components/llvm.mk
include support/components/qemu.mk
include support/components/toolchain.mk
include support/components/boost.mk
include support/components/grin.mk
include support/components/llvmcpy.mk
include support/components/grin-c.mk

# Default targets
# ===============

$(call option,ALL,$(TOOLCHAIN_INSTALL_TARGET_FILE) install-grin,Default targets to build)
all: $(ALL)

.PHONY: clean
clean: clean-build
	rm -rf $(SOURCE_ARCHIVE_PATH)

.PHONY: clean-build
clean-build:
	rm -rf $(BUILD_PATH)/
	rm -rf $(INSTALL_PATH)/
	rm -rf $(INSTALLED_TARGETS_PATH)/
	rm -f environment

.PHONY: help
help:
	@echo 'Welcome to the orchestra build system.'
	@echo
	@echo 'orchestra enables you to clone and download all the repositories necessary for rev.ng (such as our version of QEMU and LLVM, but also the core project itself, grin).'
	@echo 'Moreover, orchestra will also configure, build and install them for you.'
	@echo 'By default, the build will take place in the `build/` directory and the files will be installed in the `root/` directory, so no root permissions are required.'
	@echo
	@echo 'The repositories, by default, will be cloned from the same git namespace as the current one (but you can change this, run `make help-variables` and check out the `REMOTES` and `REMOTES_BASE_URL` options).'
	@echo
	@echo 'By default orchestra will build all the available toolchains and all the other components required by rev.ng. To do this, run:'
	@echo
	@echo '    make all'
	@echo
	@echo 'If you are interested only in working (and running tests) exclusively for a single architecture (e.g., MIPS), instead of running `make all`, run:'
	@echo
	@echo '    make toolchain/mips grin'
	@echo
	@echo 'To ensure everything is working properly, run:'
	@echo
	@echo '    make test-grin'
	@echo
	@echo 'For further information on the components that can be built and further customization options, run:'
	@echo
	@echo '    make help-variables'
	@echo '    make help-components'
	@echo

$(call strip-call,option, \
  EXCLUDE_CREATE_BINARY_ARCHIVE_COMPONENTS, \
  , \
  Components to exclude in from CREATE_BINARY_ARCHIVE_COMPONENTS)

$(call strip-call,option, \
  CREATE_BINARY_ARCHIVE_COMPONENTS, \
  $(filter-out $(EXCLUDE_CREATE_BINARY_ARCHIVE_COMPONENTS),$(foreach COMPONENT,$(COMPONENTS),$($(COMPONENT)_TARGET_NAME))), \
  Components to include in create-binary-archive)
