# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

# Set the build type
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type (default RelWithDebInfo)" FORCE)
endif()

# Always generate the compile_commands.json file
set(CMAKE_EXPORT_COMPILE_COMMANDS true)

# Show verbose compilation messages when building Debug binaries
if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  set(CMAKE_VERBOSE_MAKEFILE true)
endif()

# This is the destination for the remotely imported Python modules, used when
# setting up the PYTHONPATH folder
set(PYTHON_PATH "${CMAKE_BINARY_DIR}/python_path")

# TODO(alessandro): Add missing defines: PLATFORM_FREEBSD
if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  set(PLATFORM_POSIX 1)
  set(PLATFORM_LINUX 1)

elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
  set(PLATFORM_POSIX 1)
  set(PLATFORM_MACOS 1)
elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
  set(PLATFORM_WINDOWS 1)
else()
  message(FATAL_ERROR "Unrecognized platform")
endif()

# Use ccache when available
if(DEFINED PLATFORM_POSIX)
  find_program(ccache_command ccache)

  if(NOT "${ccache_command}" STREQUAL "ccache_command-NOTFOUND")
    message(STATUS "Found ccache: ${ccache_command}")
    set(CMAKE_CXX_COMPILER_LAUNCHER "${ccache_command}" CACHE FILEPATH "")
  else()
    message(STATUS "Not found: ccache. Install it and put it into the PATH if you want to speed up partial builds.")
  endif()

endif()

set(TEST_CONFIGS_DIR "${CMAKE_BINARY_DIR}/test_configs")

# osquery versions
set(OSQUERY_VERSION 3.4.0)

# Cache variables
set(PACKAGING_SYSTEM "" CACHE STRING "Packaging system to generate when building packages")
if(DEFINED PLATFORM_WINDOWS)
  set(WIX_ROOT_FOLDER_PATH "" CACHE STRING "Root folder of the WIX installation")
endif()
