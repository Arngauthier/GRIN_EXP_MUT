#
# This file is distributed under the MIT License. See LICENSE.md for details.
#

grin_add_analyses_library_internal(grinFunctionIsolation
  IsolateFunctions.cpp)

target_link_libraries(grinFunctionIsolation
  grinStackAnalysis
  grinSupport)
