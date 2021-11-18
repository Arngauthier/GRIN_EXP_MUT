#
# This file is distributed under the MIT License. See LICENSE.md for details.
#

add_library(grinFunctionCallIdentification
  STATIC
  FunctionCallIdentification.cpp)
target_link_libraries(grinFunctionCallIdentification
  grinSupport)
install(TARGETS grinFunctionCallIdentification
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
