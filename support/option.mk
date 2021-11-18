define print-option
	@echo $(1)
	@echo '  '$(if $($(1)_DESCRIPTION),Description: $($(1)_DESCRIPTION),No description provided)
	@echo '  'Default value: $($(1)_DEFAULT)
	@echo '  'Actual value: $($(1))
	@echo

endef

.PHONY: help-variables
help-variables:
	$(foreach OPTION,$(OPTIONS),$(call print-option,$(OPTION)))

# Defines a variable associated with a description and that can be overriden
# externally
#
# $(1): variable name
# $(2): default value
# $(3): description
define option
$(strip
$(eval OPTIONS += $(1))
$(eval $(1) ?= $(2))
$(eval $(1)_DESCRIPTION := $(3))
$(eval $(1)_DEFAULT := $(2))
)
endef
