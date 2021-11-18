#
# This file is distributed under the MIT License. See LICENSE.md for details.
#

grin_add_analyses_library_internal(grinDump
  CollectCFG.cpp
  CollectNoreturn.cpp)

target_link_libraries(grinDump
  grinSupport)
