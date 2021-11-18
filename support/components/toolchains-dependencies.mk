# mpfr
# ====

# $(1): source path
# $(2): build path
define do-configure-mpfr
	mkdir -p "$(2)"

$(call download-tar,$(2),https://www.mpfr.org/mpfr-current/,mpfr-4.0.2.tar.xz)

	cd $(2) && ./configure \
	  --prefix="$(INSTALL_PATH)" \
	  --enable-shared=no
endef

$(eval \
  $(call strip-call,component-base, \
    MPFR, \
    mpfr, \
	mpfr))

$(eval \
  $(call strip-call,autotools-component-build, \
    mpfr))

# gmp
# ===

# $(1): source path
# $(2): build path
define do-configure-gmp
	mkdir -p "$(2)"

$(call download-tar,$(2),https://gmplib.org/download/gmp/,gmp-6.1.2.tar.xz)

	cd $(2) && ./configure \
	  --prefix="$(INSTALL_PATH)" \
	  --enable-shared=no
endef

$(eval \
  $(call strip-call,component-base, \
    GMP, \
    gmp, \
	gmp))

$(eval \
  $(call strip-call,autotools-component-build, \
    gmp))

# mpc
# ===

# $(1): source path
# $(2): build path
define do-configure-mpc
	mkdir -p "$(2)"

$(call download-tar,$(2),https://ftp.gnu.org/gnu/mpc/,mpc-1.1.0.tar.gz)

	cd $(2) && ./configure \
	  --prefix="$(INSTALL_PATH)" \
	  --with-mpfr="$(INSTALL_PATH)" \
	  --with-mpc="$(INSTALL_PATH)" \
	  --enable-shared=no
endef

$(eval \
  $(call strip-call,component-base, \
    MPC, \
    mpc, \
	mpc))

$(eval \
  $(call strip-call,autotools-component-build, \
    mpc, \
    , \
    $(MPFR_INSTALL_TARGET_FILE) $(GMP_INSTALL_TARGET_FILE)))
