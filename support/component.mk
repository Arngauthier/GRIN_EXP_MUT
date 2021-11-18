define platform-name
$(subst $(SPACE),-,$(subst _,-,$(call lc,$(shell uname -ms))))
endef

# $(1): string
define lc
$(subst A,a,$(subst B,b,$(subst C,c,$(subst D,d,$(subst E,e,$(subst F,f,$(subst G,g,$(subst H,h,$(subst I,i,$(subst J,j,$(subst K,k,$(subst L,l,$(subst M,m,$(subst N,n,$(subst O,o,$(subst P,p,$(subst Q,q,$(subst R,r,$(subst S,s,$(subst T,t,$(subst U,u,$(subst V,v,$(subst W,w,$(subst X,x,$(subst Y,y,$(subst Z,z,$(1)))))))))))))))))))))))))))
endef

# $(1): string
define uc
$(subst a,A,$(subst b,B,$(subst c,C,$(subst d,D,$(subst e,E,$(subst f,F,$(subst g,G,$(subst h,H,$(subst i,I,$(subst j,J,$(subst k,K,$(subst l,L,$(subst m,M,$(subst n,N,$(subst o,O,$(subst p,P,$(subst q,Q,$(subst r,R,$(subst s,S,$(subst t,T,$(subst u,U,$(subst v,V,$(subst w,W,$(subst x,X,$(subst y,Y,$(subst z,Z,$(1)))))))))))))))))))))))))))
endef

$(call option,JOBS,$(shell nproc || echo 1),Number of concurrent jobs)
$(call option,SOURCE_PATH,$(PWD),Path for sources)
$(call option,BUILD_PATH,$(PWD)/build,Path for build directories)
$(call option,INSTALL_PATH,$(PWD)/root,Path for installing components)
$(call option,PLATFORM_NAME,$(call platform-name),Name of the platform used to archive binaries)
$(call option,BINARY_ARCHIVE_PATH,$(PWD)/binary-archives,Path for storing and fetching binary archives)
$(call option,SOURCE_ARCHIVE_PATH,$(PWD)/source-archives,Path for caching source archives)
$(call option,PATCH_PATH,$(PWD)/patches,Path containing patches for components)
$(call option,TEMP_INSTALL_PATH,$(PWD)/temp-install,Path for installing components before creating a binary archive)
$(call option,INSTALLED_TARGETS_PATH,$(PWD)/installed-targets,Path for the file to indicate that a certain build/component has been installed)
$(call option,REMOTES_BASE_URL,$(foreach REMOTE,$(REMOTES),$(dir $(shell git config --get remote.$(REMOTE).url))),Space-separated list of repository base URLs to try, one after the other, while cloning sources)
$(call option,BRANCHES,$(shell git name-rev --name-only HEAD | grep -v master) develop master,Space-separated list of git refs such as branches to try to checkout after the sources have been cloned)
$(call option,FORCE_BINARIES,no,Force building all the request binary packages even if they are already available)
$(call option,BUILD_MISSING_BINARIES,no,If a required binary archive is not available build it from source)
$(call option,CLONE_ATTEMPTS,3,Attempts to clone a remote before giving up)
$(call option,CLONE_ATTEMPTS_PAUSE,10,Seconds to wait before an attempt to clone a remote and the next one)
$(eval CLONE_ATTEMPTS_LOOP := $(SEQ$(CLONE_ATTEMPTS)))

# $(shell echo $(1) | tr a-z- A-Z_)
define target-to-prefix
$(subst -,_,$(call uc,$(1)))
endef

# $(1): build target name
# $(2): default build target name
# $(3): component target name
define print-component-build
	@echo '  '$($(1)_TARGET_NAME)$(if $($(1)_CONFIGURE_DEPS),' [configure deps: '$(subst |,[order only:],$(subst $(PWD)/,,$($(1)_CONFIGURE_DEPS)))']',)$(if $($(1)_INSTALL_DEPS),' [install deps: '$(subst |,[order only:],$(subst $(PWD)/,,$($(1)_INSTALL_DEPS)))']',)$(if $(filter $(2),$(1)),' [default]',)$(if $($(1)_PROVIDES),' [provides $(3)$($(1)_PROVIDES)]',)

endef

define print-component
	@echo 'Component '$($(1)_TARGET_NAME)
	$(eval TMP := $(call target-to-prefix,$($(1)_DEFAULT_BUILD)))
	$(foreach BUILD,$($(1)_BUILDS),$(call print-component-build,$(BUILD),$(TMP),$($(1)_TARGET_NAME)))
	@echo

endef

.PHONY: help-components
help-components:
	$(foreach COMPONENT,$(COMPONENTS),$(call print-component,$(COMPONENT)))

# $(1): file to touch
define touch
	mkdir -p $(dir $(1)) && touch $(1);
endef

define string-to-suffix
$(subst /,-,$(1))
endef

# $(1): target name
define binary-archive-directory
$(BINARY_ARCHIVE_PATH)/$(PLATFORM_NAME)/$(1)
endef

# $(1): source name prefix
# $(2): hash
# $(3): branch
define declare-binary-archive-name
	$(eval TMP_PARTS :=$(subst /,$(SPACE),$($(1)_TARGET_NAME))) \
	DEFINED_BY="$(foreach INDEX,$(SEQ$(words $(TMP_PARTS))),$(wildcard support/components/$(subst $(SPACE),/,$(wordlist 1,$(INDEX),$(TMP_PARTS))).mk))"; \
	ARCHIVE_NAME=$(if $(2),$(2),$(if $($(1)_CLONE_PATH),$$$$(git -C '$($(1)_SOURCE_PATH)' rev-parse HEAD),none))_$$$$(git log -1 --pretty=format:"%H" $$$$DEFINED_BY).tar.gz; \
	BRANCH_NAME=$(if $(3),$$$$(echo "$(3)" | tr '/' '-'),$(if $($(1)_CLONE_PATH),$$$$(git -C '$($(1)_SOURCE_PATH)' rev-parse --abbrev-ref HEAD | tr '/' '-'),none))_$$$$(git rev-parse --abbrev-ref HEAD | tr '/' '-').tar.gz;
endef

# $(1): build name prefix
# $(2): source name prefix
define declare-binary-archive-path
	if test -n "$($(2)_CLONE_PATH)"; then \
	  TEMP=$$$$(mktemp) || exit; \
	  trap "rm -f -- '$$$$TEMP'" EXIT; \
	  for REMOTE in $(REMOTES_BASE_URL); do \
	    $(call strip-call,retry,$(CLONE_ATTEMPTS_LOOP),$(CLONE_ATTEMPTS_PAUSE),git ls-remote -h --refs $$$${REMOTE}$($(2)_CLONE_PATH) > "$$$$TEMP") || true; \
	    if test -s "$$$$TEMP"; then \
	      for BRANCH in $(BRANCHES); do \
	        RES=$$$$( (grep 'refs/heads/'"$$$$BRANCH"'$$$$' "$$$$TEMP" || true) | (grep -o '^[a-z0-9]*' || true) ); \
	        if test -n "$$$$RES"; then \
	          rm -f -- "$$$$TEMP"; \
	          trap - EXIT; \
$(call declare-binary-archive-name,$(2),$$$${RES},$$$${BRANCH}) \
	          HASH_FILE="$(call strip-call,binary-archive-directory,$($(1)_TARGET_NAME))/$$$$ARCHIVE_NAME"; \
	          BRANCH_FILE="$(call strip-call,binary-archive-directory,$($(1)_TARGET_NAME))/$$$$BRANCH_NAME"; \
	        fi; \
	      done; \
	    fi; \
	  done; \
	else \
	  RES=none; \
	  BRANCH=none; \
$(call declare-binary-archive-name,$(2),$$$${RES},$$$${BRANCH}) \
	  HASH_FILE="$(call strip-call,binary-archive-directory,$($(1)_TARGET_NAME))/$$$$ARCHIVE_NAME"; \
	  BRANCH_FILE="$(call strip-call,binary-archive-directory,$($(1)_TARGET_NAME))/$$$$BRANCH_NAME"; \
	fi;
endef

# $(1): the message
define log-info
echo -e "\e[31m[INFO] $(1)\e[0m";
endef

# $(1): the message
define log-error
echo -e "\e[31m[ERROR] $(1)\e[0m";
endef

# $(1): build name prefix
# $(2): source name prefix
define create-binary-archive
	$(eval TMP_ARCHIVE_DIRECTORY := $(call binary-archive-directory,$($(1)_TARGET_NAME)))
$(call declare-binary-archive-path,$(1),$(2)) \
	if $(if $(filter-out no,$(FORCE_BINARIES)),true,test ! -e "$$$$HASH_FILE"); then \
	  $(call log-info,No binary archive available for $($(1)_TARGET_NAME)$(COMMA) building from source) \
	  rm -rf "$(TEMP_INSTALL_PATH)"; \
	  mkdir -p "$(TEMP_INSTALL_PATH)"; \
	  make $($(1)_INSTALL_TARGET_FILE) BUILD_MISSING_BINARIES=yes; \
	  make install-$($(1)_TARGET_NAME) "DESTDIR=$(TEMP_INSTALL_PATH)"; \
	  mkdir -p "$(TMP_ARCHIVE_DIRECTORY)"; \
	  touch "$(TMP_ARCHIVE_DIRECTORY)/$$$$ARCHIVE_NAME"; \
	  cd "$(TEMP_INSTALL_PATH)/$(INSTALL_PATH)"; \
	  tar caf "$(TMP_ARCHIVE_DIRECTORY)//$$$$ARCHIVE_NAME" --owner=0 --group=0 "."; \
	  cd -; \
	  rm -rf "$(TEMP_INSTALL_PATH)"; \
	else \
	  $(call log-info,We already have an archive for $($(1)_TARGET_NAME)) \
	fi; \
	rm -f "$(TMP_ARCHIVE_DIRECTORY)/$$$$BRANCH_NAME"; \
	ln -f -s "$$$$ARCHIVE_NAME" "$(TMP_ARCHIVE_DIRECTORY)/$$$$BRANCH_NAME";
endef

# $(1): build name prefix
# $(2): source name prefix
define git-add-binary-archive
	$(eval TMP_ARCHIVE_DIRECTORY := $(call binary-archive-directory,$($(1)_TARGET_NAME)))
$(call declare-binary-archive-path,$(1),$(2)) \
	if test -e "$$$$HASH_FILE"; then \
	  git -C '$(BINARY_ARCHIVE_PATH)' add "$$$$HASH_FILE"; \
	fi; \
	if test -e "$$$$BRANCH_FILE"; then \
	  git -C '$(BINARY_ARCHIVE_PATH)' add "$$$$BRANCH_FILE"; \
	fi
endef

# $(1): build path
# $(2): extra arguments (in particular, build target)
# We unset MAKEFLAGS to make sure we don't pass to submake weird flags
define make
	MAKEFLAGS= make -C "$(1)" -j$(JOBS) $(2)
endef

# $(1) attempts before giving up
# $(2) sleep time between attempts
# $(3) command to retry
define retry
$(LPAR)$(foreach I,$(1),$(3)$(RPAR) || $(LPAR)sleep $(2) && ) false $(RPAR)
endef

# TODO: Detect if a clone fails due to a missing repository or connection issues.
#       Looking for the "Connection refused" string in the output seems to be the most reliable approach.
# TODO: Clone and create a remote the same name as the source one.

# $(1): remote path of the repository to clone
# $(2): clone destination path
define clone-remote
	$(call retry,$(CLONE_ATTEMPTS_LOOP),$(CLONE_ATTEMPTS_PAUSE),GIT_LFS_SKIP_SMUDGE=1 git clone $(1) $(2)); \
	git -C $(2) branch -m orchestra-temporary; \
	$(foreach BRANCH,$(BRANCHES),git -C $(2) checkout -b $(BRANCH) origin/$(BRANCH) || ) true
endef

# $(1): remote-relative path of the repository to clone
# $(2): clone destination path
define clone
	$(call log-info,Cloning $(1) into $(2)) \
	$(foreach REMOTE_BASE_URL,$(REMOTES_BASE_URL),$(call clone-remote,$(REMOTE_BASE_URL)$(1),$(2)) || ) false
endef

# $(1): destination
# $(2): path
# $(3): file name
define download-tar
	$(call log-info,Downloading $(3) from $(2))
	mkdir -p $(1)
	mkdir -p $(SOURCE_ARCHIVE_PATH)
	trap "rm -f -- '$(SOURCE_ARCHIVE_PATH)/$(3)'" EXIT; \
	test -e "$(SOURCE_ARCHIVE_PATH)/$(3)" || $(call retry,$(CLONE_ATTEMPTS_LOOP),$(CLONE_ATTEMPTS_PAUSE),curl -L "$(2)/$(3)" > "$(SOURCE_ARCHIVE_PATH)/$(3)"); \
	trap - EXIT;
	$(call log-info,Extracting $(3) into $(1))
	cd "$(1)" && tar xaf "$(SOURCE_ARCHIVE_PATH)/$(3)" --strip-components=1
endef

# git -C "$(BINARY_ARCHIVE_PATH)" lfs pull -I "$$(1)";

# $(1): archive path
define fetch-binary-and-extract
	RELATIVE_PATH="$$$$(realpath --relative-to=$(PWD) $(1))"; \
	if test -n "$$$$(git -C $(BINARY_ARCHIVE_PATH) ls-files $(1))"; then \
	  $(call log-info,Fetching $$$$RELATIVE_PATH) \
	  cd $(BINARY_ARCHIVE_PATH); \
	  python $(PWD)/support/git-lfs  --only "`readlink -f $(1)`"; \
	fi; \
	$(call log-info,Extracting $$$$RELATIVE_PATH) \
	mkdir -p "$(INSTALL_PATH)"; \
	cd "$(INSTALL_PATH)"; \
	tar xaf "$(1)";
endef

# $(1): component prefix
# $(2): build prefix
define touch-install-files
$(eval TMP := $($(1)$(call target-to-prefix,$($(2)_PROVIDES))_INSTALL_TARGET_FILE))
ifneq (,$(TMP))
	TEMP_FILE=$$$$(mktemp); rm $$$$TEMP_FILE; if test -e $(TMP); then mv $(TMP) $$$$TEMP_FILE; fi; \
	rm -f $($(1)_INSTALL_TARGET_FILE)*; \
	if test -e $$$$TEMP_FILE; then mv $$$$TEMP_FILE $(TMP); else $(call touch,$(TMP)) fi;
else
	rm -f $($(1)_INSTALL_TARGET_FILE)*;
endif
$(call touch,$($(1)_INSTALL_TARGET_FILE))
$(call touch,$($(2)_INSTALL_TARGET_FILE))
endef

# Functions to build components
# =============================

#$(1)-HAS-BEEN-INSTALLED
# $(1): target name
define install-target-file
$(INSTALLED_TARGETS_PATH)/$(1)
endef

define component-source
$(call component-base,$(1),$(2),$(6))
$(call component-clone,$(1),$(3),$(4),$(5))
endef

# component-base creates the minimal set of variables and targets required to
# obtain a working component.
define component-base

#
# Rules for $(2) (component-base)
#

$(eval COMPONENTS += $(1))

# Name for targets related to this component
$(eval $(1)_TARGET_NAME := $(2))

# Default clone path, used to get the commit/branch for the component
$(eval $(1)_CLONE_PATH := )

$(eval $(1)_INSTALL_TARGET_FILE := $(call install-target-file,$($(1)_TARGET_NAME)))

# Build to install by default
$(call option,$(1)_DEFAULT_BUILD,$(3),Default build to install for $(2))

.PHONY: clean-$($(1)_TARGET_NAME)

$(if $(filter-out $($(1)_TARGET_NAME),$($(1)_DEFAULT_BUILD)),
.PHONY: install-$($(1)_TARGET_NAME)
install-$($(1)_TARGET_NAME): install-$($(1)_DEFAULT_BUILD)
$($(1)_INSTALL_TARGET_FILE): $(call install-target-file,$($(1)_DEFAULT_BUILD))

.PHONY: test-$($(1)_TARGET_NAME)
test-$($(1)_TARGET_NAME): test-$($(1)_DEFAULT_BUILD)

.PHONY: create-binary-archive-$($(1)_TARGET_NAME)
create-binary-archive-$($(1)_TARGET_NAME): create-binary-archive-$($(1)_DEFAULT_BUILD)

.PHONY: $($(1)_TARGET_NAME)
$($(1)_TARGET_NAME): $($(1)_INSTALL_TARGET_FILE)
,)


endef

# component-clone creates the variables and the targets required to perform a
# clone.
define component-clone

#
# Rules for $(1) (component-clone)
#

# Clone path, relative to the origin
$(eval $(if $(do-clone-$($(1)_TARGET_NAME)),,$(1)_CLONE_PATH := $(2)))

# Check out path, relative to $(SOURCE_PATH)
$(eval $(1)_SOURCE_PATH := $(SOURCE_PATH)/$(3))

# File to depend on for check out, relative to $(PREFIX)_SOURCE_PATH
$(eval $(1)_SOURCE_TARGET_FILE := $($(1)_SOURCE_PATH)/$(4))

$($(1)_SOURCE_TARGET_FILE):
$(if $(do-clone-$($(1)_TARGET_NAME)),
$(call do-clone-$($(1)_TARGET_NAME),$($(1)_TARGET_NAME),$($(1)_SOURCE_PATH)),
$(call clone,$($(1)_TARGET_NAME),$($(1)_SOURCE_PATH)))
$(call touch,$($(1)_SOURCE_TARGET_FILE))

.PHONY: clone-$($(1)_TARGET_NAME)
clone-$($(1)_TARGET_NAME): $($(1)_SOURCE_TARGET_FILE)

endef

# $(1): build prefix
# $(2): build target
# $(3): relative build path
# $(4): file to depend upon for configure
# $(5): configure-time dependencies
# $(6): component prefix
# $(7): build suffix of the another build of the same component provided by this build
# $(8): install-time dependencies
define component-build

#
# Rules for $(2) (component-build)
#

# $(6) is the PREFIX of the corresponding source

$(eval $(6)_BUILDS += $(1))

$(eval $(1)_TARGET_NAME := $(2))

# Build path, relative to $(BUILD_PATH)
$(eval $(1)_BUILD_PATH := $(BUILD_PATH)/$(3))

# File to depend on for configure, relative to $(PREFIX)_BUILD_PATH
$(eval $(1)_CONFIGURE_TARGET_FILE := $($(1)_BUILD_PATH)/$(4))

# File to depend on for configure, relative to $(PREFIX)_BUILD_PATH
$(eval $(1)_INSTALL_TARGET_FILE := $(call install-target-file,$($(1)_TARGET_NAME)))

# List of targets the configure stage should depend on
$(eval $(1)_CONFIGURE_DEPS := $(5))

# The name of another build that has to be considered installed when this build
# is installed
$(eval $(1)_PROVIDES := $(7))

# Install-time dependencies
$(eval $(1)_INSTALL_DEPS := $(8))

# configure- target
.PHONY: configure-$($(1)_TARGET_NAME)
configure-$($(1)_TARGET_NAME) $($(1)_CONFIGURE_TARGET_FILE): $($(6)_SOURCE_TARGET_FILE) $($(1)_CONFIGURE_DEPS) $($(1)_INSTALL_DEPS)
	$(call log-info,Configuring $($(1)_TARGET_NAME))
	mkdir -p $(BUILD_PATH)
$(call do-configure-$($(1)_TARGET_NAME),$($(6)_SOURCE_PATH),$($(1)_BUILD_PATH))
$(call touch,$($(1)_CONFIGURE_TARGET_FILE))

# build- target
.PHONY: build-$($(1)_TARGET_NAME)
build-$($(1)_TARGET_NAME): $($(1)_CONFIGURE_TARGET_FILE)
	$(call log-info,Building $($(1)_TARGET_NAME))
$(if $(do-build-$($(1)_TARGET_NAME)),
$(call do-build-$($(1)_TARGET_NAME),$($(1)_BUILD_PATH),$($(6)_SOURCE_PATH)),
$(call make,$($(1)_BUILD_PATH),))

# test- target
.PHONY: test-$($(1)_TARGET_NAME)
test-$($(1)_TARGET_NAME): build-$($(1)_TARGET_NAME)
	$(call log-info,Testing $($(1)_TARGET_NAME))
$(if $(do-test-$($(1)_TARGET_NAME)),
$(call do-test-$($(1)_TARGET_NAME),$($(1)_BUILD_PATH)),)

# install- target
.PHONY: install-$($(1)_TARGET_NAME)

ifeq ($($(6)_TARGET_NAME),$(filter $($(6)_TARGET_NAME),$(BINARY_COMPONENTS)))
install-$($(1)_TARGET_NAME): $($(1)_CONFIGURE_TARGET_FILE)
else
install-$($(1)_TARGET_NAME) $($(1)_INSTALL_TARGET_FILE): $($(1)_CONFIGURE_TARGET_FILE)
endif
	$(call log-info,Installing $($(1)_TARGET_NAME))
	mkdir -p "$$$$DESTDIR$(INSTALL_PATH)/include"
	mkdir -p "$$$$DESTDIR$(INSTALL_PATH)/lib"
	mkdir -p "$$$$DESTDIR$(INSTALL_PATH)/bin"
	mkdir -p "$$$$DESTDIR$(INSTALL_PATH)/libexec"
$(if $(do-install-$($(1)_TARGET_NAME)),
$(call do-install-$($(1)_TARGET_NAME),$($(1)_BUILD_PATH),$($(6)_SOURCE_PATH)),
$(call make,$($(1)_BUILD_PATH),)
$(call make,$($(1)_BUILD_PATH),install))
$(call touch-install-files,$(6),$(1))

# clean- target
.PHONY: clean-$($(1)_TARGET_NAME)
clean-$($(1)_TARGET_NAME):
	$(call log-info,Cleaning $($(1)_TARGET_NAME))
	rm -rf $($(1)_BUILD_PATH)

# Add the clean- target for the current build to the component clean- target
ifneq ($($(6)_TARGET_NAME),$($(1)_TARGET_NAME))
clean-$($(6)_TARGET_NAME): clean-$($(1)_TARGET_NAME)
endif

.PHONY: $($(1)_TARGET_NAME)
$($(1)_TARGET_NAME): $($(1)_INSTALL_TARGET_FILE)

.PHONY: create-binary-archive-$($(1)_TARGET_NAME)
create-binary-archive-$($(1)_TARGET_NAME): $(BINARY_ARCHIVE_PATH)/README.md
$(call create-binary-archive,$(1),$(6))

.PHONY: git-add-binary-archive-$($(1)_TARGET_NAME)
git-add-binary-archive-$($(1)_TARGET_NAME): $(BINARY_ARCHIVE_PATH)/README.md
$(call git-add-binary-archive,$(1),$(6))

# fetch- target
#
# 1. Find the branch
# 2. Get the commit
# 3. Check for the commit file
# 4. Check for the branch file
ifeq ($($(6)_TARGET_NAME),$(filter $($(6)_TARGET_NAME),$(BINARY_COMPONENTS)))
fetch-$($(1)_TARGET_NAME) $($(1)_INSTALL_TARGET_FILE): $(BINARY_ARCHIVE_PATH)/README.md $($(1)_INSTALL_DEPS)
else
fetch-$($(1)_TARGET_NAME): $(BINARY_ARCHIVE_PATH)/README.md $($(1)_INSTALL_DEPS)
endif
$(call declare-binary-archive-path,$(1),$(6)) \
	if test -e "$$$$HASH_FILE"; then \
	  $(call strip-call,fetch-binary-and-extract,$$$$HASH_FILE) \
	elif $(if $(filter-out no,$(BUILD_MISSING_BINARIES)),true,false); then \
	  make install-$($(1)_TARGET_NAME); \
	else \
	  $(call log-error,Couldn't find the archive for branch $$$$BRANCH) \
	  exit 1; \
	fi; \
$(call touch-install-files,$(6),$(1))
endef

# $(1): target name
# $(2): file to depend on for check out, relative to $(PREFIX)_SOURCE_PATH
# $(3): default variant
define simple-component-source
$(call component-source,$(call target-to-prefix,$(1)),$(1),$(1),$(1),$(2),$(1)$(3))
endef

# $(1): source target name
# $(2): build name suffix
# $(3): file to depend on for configure, relative to $(PREFIX)_BUILD_PATH
# $(4): list of targets the configure stage should depend on at configure-time
# $(5): build suffix of the another build of the same component provided by this build
# $(6): install-time dependencies
define simple-component-build
$(call strip-call,component-build, \
  $(call strip-call,target-to-prefix,$(1)$(2)), \
  $(1)$(2), \
  $(1)$(2), \
  $(3), \
  $(4), \
  $(call strip-call,target-to-prefix,$(1)), \
  $(5), \
  $(6))
endef

# CMake-based components
# ----------------------

# $(1): target name
# $(2): default build
define cmake-component-source
$(call simple-component-source,$(1),CMakeLists.txt,$(2))
endef

# $(1): target name
# $(2): build name
# $(3): configure-time dependencies
# $(4): provided build
# $(5): install-time dependencies
define cmake-component-build
$(call strip-call,simple-component-build, \
  $(1), \
  $(2), \
  CMakeCache.txt, \
  $(3), \
  $(4), \
  $(5))
endef

# $(1): target name
# $(2): configure-time dependencies
# $(3): provided build
# $(4): install-time dependencies
define simple-cmake-component
$(call cmake-component-source,$(1),)
$(call strip-call,cmake-component-build, \
  $(1), \
  , \
  $(2), \
  $(3), \
  $(4))
endef

# $(1): target name
# $(2): default build
# $(3): configure-time dependencies
# $(4): provided build
# $(5): install-time dependencies
# $(6), $(7), $(8), $(9), $(10): name of build targets
define multi-build-cmake-component
$(call cmake-component-source,$(1),-$(2))
$(foreach i,6 7 8 9 10,$(if $($(i)),$(call cmake-component-build,$(1),-$($(i)),$(3),$(4),$(5))))
endef

# autotools-based components
# --------------------------

# 1: target name
# 2: default build
define autotools-component-source
$(call simple-component-source,$(1),configure,$(2))
endef

# $(1): target name
# $(2): build name
# $(3): configure-time dependencies
# $(4): provided build
# $(5): install-time dependencies
define autotools-component-build
$(call strip-call,simple-component-build, \
  $(1), \
  $(2), \
  config.log, \
  $(3), \
  $(4), \
  $(5))
endef

# $(1): target name
# $(2): configure-time dependencies
# $(3): provided build
# $(4): install-time dependencies
define simple-autotools-component
$(call autotools-component-source,$(1),)
$(call strip-call,autotools-component-build, \
  $(1), \
  , \
  $(2), \
  $(3), \
  $(4))
endef

# Binaries
$(BINARY_ARCHIVE_PATH)/README.md:
	test -n $(BINARY_ARCHIVE_PATH)
	test ! -e $(BINARY_ARCHIVE_PATH)
	$(call clone,binary-archives,$(BINARY_ARCHIVE_PATH))
	while test -e $(BINARY_ARCHIVE_PATH)/REDIRECT; do \
	  NEW_REMOTE=$$(cat $(BINARY_ARCHIVE_PATH)/REDIRECT); \
	  rm -rf $(BINARY_ARCHIVE_PATH); \
	  $(call clone-remote,$$NEW_REMOTE,$(BINARY_ARCHIVE_PATH)); \
	done
