# Boost
# =====

define do-build-boost
	cd $(1) && ./b2 --ignore-site-config
endef

define do-install-boost
	cd $(1) && ./b2 --prefix="$$$$DESTDIR$(INSTALL_PATH)" --ignore-site-config install
endef

# $(1): source path
# $(2): build path
define do-configure-boost
	mkdir -p "$(2)"

$(call download-tar,$(2),https://sourceforge.net/projects/boost/files/boost/1.63.0,boost_1_63_0.tar.bz2)

$(call patch-if-exists,$(PATCH_PATH)/boost-1.63.0-ignore-Wparentheses-warnings.patch,$(2))

	cd $(2) && ./bootstrap.sh --prefix="$(INSTALL_PATH)" --with-libraries=test
endef

$(eval $(call component-base,BOOST,boost,boost))
$(eval \
  $(call strip-call,simple-component-build, \
    boost))
