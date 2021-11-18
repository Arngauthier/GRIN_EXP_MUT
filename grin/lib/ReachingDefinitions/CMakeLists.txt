#
# This file is distributed under the MIT License. See LICENSE.md for details.
#

add_library(grinReachingDefinitions
  STATIC
  ReachingDefinitionsPass.cpp)
target_link_libraries(grinReachingDefinitions
  grinFunctionCallIdentification
  grinStackAnalysis
  grinSupport)
install(TARGETS grinReachingDefinitions
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
