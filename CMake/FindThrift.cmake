# - Find Thrift (a cross platform RPC lib/tool)
# This module defines
#  THRIFT_VERSION, version string of ant if found
#  THRIFT_INCLUDE_DIR, where to find THRIFT headers
#  THRIFT_CONTRIB_DIR, where contrib thrift files (e.g. fb303.thrift) are installed
#  THRIFT_LIBS, THRIFT libraries
#  THRIFT_FOUND, If false, do not try to use ant

if(APPLE AND NOT DEFINED $ENV{THRIFT_HOME})
  execute_process(COMMAND brew --prefix OUTPUT_VARIABLE BREW_PREFIX OUTPUT_STRIP_TRAILING_WHITESPACE)
  set(ENV{THRIFT_HOME} ${BREW_PREFIX})
endif()

# Prefer the thrift version supplied in THRIFT_HOME
if(NOT DEFINED THRIFT_FOUND)
  find_program(THRIFT_COMPILER thrift
    $ENV{THRIFT_HOME}/bin
    /usr/local/bin
    /usr/bin
    NO_DEFAULT_PATH
  )

  if (THRIFT_COMPILER)
    set(THRIFT_FOUND TRUE)
    exec_program(${THRIFT_COMPILER}
      ARGS -version OUTPUT_VARIABLE THRIFT_VERSION RETURN_VALUE THRIFT_RETURN)
  else()
    message(FATAL_ERROR "Thrift compiler NOT found.")
  endif()

  mark_as_advanced(THRIFT_COMPILER)
endif()

if (NOT "${THRIFT_VERSION}" STREQUAL "Thrift version 0.9.3")
  WARNING_LOG("[Ref #1830] Cannot use thrift versions <0.9.3 (found ${THRIFT_VERSION})")
  message(FATAL_ERROR "[Ref #1830] Need thrift version 0.9.3")
endif()
