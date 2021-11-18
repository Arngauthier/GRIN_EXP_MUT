# Helper macro to create a new library containing analyses to be employed in
# grin-opt
macro(grin_add_analyses_library NAME)
  add_library("${NAME}" SHARED ${ARGN})
  target_include_directories("${NAME}" INTERFACE $<INSTALL_INTERFACE:include/>)
  set_target_properties("${NAME}" PROPERTIES INSTALL_RPATH "\$ORIGIN/../../:\$ORIGIN/")
  install(TARGETS "${NAME}" EXPORT grin LIBRARY DESTINATION lib/grin/analyses)
endmacro()
