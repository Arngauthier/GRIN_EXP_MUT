#
# This file is distributed under the MIT License. See LICENSE.md for details.
#

add_library(grinSupport SHARED
  Assert.cpp
  CommandLine.cpp
  Debug.cpp
  DebugHelper.cpp
  ExampleAnalysis.cpp
  IRHelpers.cpp
  Statistics.cpp)

target_include_directories(grinSupport
  INTERFACE $<INSTALL_INTERFACE:include/>)

install(TARGETS grinSupport
  EXPORT grin
  LIBRARY DESTINATION lib)
