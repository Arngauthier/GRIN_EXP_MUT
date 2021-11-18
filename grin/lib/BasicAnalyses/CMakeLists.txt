#
# This file is distributed under the MIT License. See LICENSE.md for details.
#

grin_add_analyses_library_internal(grinBasicAnalyses
  GeneratedCodeBasicInfo.cpp)

target_link_libraries(grinBasicAnalyses
  grinSupport)
