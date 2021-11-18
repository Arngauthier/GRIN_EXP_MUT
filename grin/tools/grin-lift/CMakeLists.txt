#
# This file is distributed under the MIT License. See LICENSE.md for details.
#

add_executable(grin-lift
  BinaryFile.cpp
  CPUStateAccessAnalysisPass.cpp
  CodeGenerator.cpp
  ExternalJumpsHandler.cpp
  InstructionTranslator.cpp
  JumpTargetManager.cpp
  Main.cpp
  NoReturnAnalysis.cpp
  OSRA.cpp
  PTCDump.cpp
  SET.cpp
  SimplifyComparisonsPass.cpp
  VariableManager.cpp)

target_link_libraries(grin-lift
  dl
  m
  grinBasicAnalyses
  grinReachingDefinitions
  grinSupport
  ${LLVM_LIBRARIES})

add_custom_command(TARGET grin-lift POST_BUILD VERBATIM
  COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:grin-lift>" "${CMAKE_BINARY_DIR}/")

install(TARGETS grin-lift
  RUNTIME DESTINATION bin)
