# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

# Always generate the compile_commands.json file
set(CMAKE_EXPORT_COMPILE_COMMANDS true)

# Show verbose compilation messages when building Debug binaries
if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  set(CMAKE_VERBOSE_MAKEFILE true)
endif()

# This may be useful to speed up development builds
option(BUILD_SHARED_LIBS "Whether to build shared libraries (like *.dll or *.so) or static ones (like *.a)" ${BUILD_SHARED_LIBS_DEFAULT_VALUE})

option(ADD_HEADERS_AS_SOURCES "Whether to add headers as sources of a target or not. This is needed for some IDEs which wouldn't detect headers properly otherwise")

option(OSQUERY_NO_DEBUG_SYMBOLS "Whether to build without debug symbols or not, even if a build type that normally have them has been selected")

option(BUILD_TESTING "Whether to enable and build tests or not")

# This is the default S3 storage used by Facebook to store 3rd party dependencies; it
# is provided here as a configuration option
if("${THIRD_PARTY_REPOSITORY_URL}" STREQUAL "")
  set(THIRD_PARTY_REPOSITORY_URL "https://s3.amazonaws.com/osquery-packages")
endif()

# osquery versions.
#
# 1. $OSQUERY_VERSION is set, use that.
# 2. Else derive from git
# 3. If set, append $OSQUERY_VERSION_SUFFIX
#
# Note that the build won't like it if the version isn't a semvar.

option(OSQUERY_VERSION "Manually set the osquery version")
option(OSQUERY_VERSION_SUFFIX "String to append to the version")

if(NOT OSQUERY_VERSION OR OSQUERY_VERSION STREQUAL "git")
  message(STATUS "Detecting version from git")

  set(OSQUERY_VERSION 0.0.0)
  find_package(Git REQUIRED)

  if(GIT_FOUND)
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" describe --tags --always --dirty
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
      OUTPUT_VARIABLE branch_version
      RESULT_VARIABLE exit_code
    )

    if(NOT ${exit_code} EQUAL 0)
      message(WARNING "Failed to detect osquery version, it will be left to 0.0.0")
    else()
      string(REGEX REPLACE "\n$" "" branch_version "${branch_version}")
      set(OSQUERY_VERSION ${branch_version})
    endif()
  endif()
endif()

if(OSQUERY_VERSION_SUFFIX)
  string(APPEND OSQUERY_VERSION "${OSQUERY_VERSION_SUFFIX}")
endif()

string(REPLACE "." ";" osquery_version_components "${OSQUERY_VERSION}")

list(LENGTH osquery_version_components osquery_version_components_len)
if(NOT osquery_version_components_len GREATER_EQUAL 3)
  message(FATAL_ERROR "Version should have at least 3 components (semvar).")
endif()

list(GET osquery_version_components 0 CPACK_PACKAGE_VERSION_MAJOR)
list(GET osquery_version_components 1 CPACK_PACKAGE_VERSION_MINOR)
list(GET osquery_version_components 2 CPACK_PACKAGE_VERSION_PATCH)

message(STATUS "osquery version: ${OSQUERY_VERSION}")
