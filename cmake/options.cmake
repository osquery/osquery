# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

# Detect osquery version
# The OSQUERY_VERSION cache variable will be used if set or not empty
# Otherwise detect version through git and set it in the OSQUERY_VERSION_AUTODETECTED cache variable. If detection fails, 0.0.0 will be used.
# Append OSQUERY_VERSION_SUFFIX cache variable to the final version if specified and the version is detected from git.
# Verify if the final version is composed by three semver components, otherwise fail.
# Returns the final version in OSQUERY_VERSION_INTERNAL and its components in OSQUERY_VERSION_COMPONENTS
function(detectOsqueryVersion)
  set(OSQUERY_VERSION "" CACHE STRING "Overrides osquery version with this value")
  set(OSQUERY_VERSION_SUFFIX "" CACHE STRING "String to append when the version is automatically detected")
  set(OSQUERY_VERSION_AUTODETECTED "" CACHE STRING "osquery version autodetected through git. Do not manually set." FORCE)
  set(osquery_version 0.0.0)

  if(NOT OSQUERY_VERSION)
    find_package(Git REQUIRED)

    execute_process(
      COMMAND "${GIT_EXECUTABLE}" describe --tags --always --dirty
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
      OUTPUT_VARIABLE branch_version
      RESULT_VARIABLE exit_code
    )

    if(NOT ${exit_code} EQUAL 0)
      message(WARNING "Failed to detect osquery version. Set it manually through OSQUERY_VERSION or 0.0.0 will be used")
    else()
      string(REGEX REPLACE "\n$" "" branch_version "${branch_version}")
      set(osquery_version ${branch_version})
      overwrite_cache_variable("OSQUERY_VERSION_AUTODETECTED" "STRING" ${osquery_version})

      if(OSQUERY_VERSION_SUFFIX)
        string(APPEND osquery_version "${OSQUERY_VERSION_SUFFIX}")
      endif()
    endif()
  else()
    set(osquery_version "${OSQUERY_VERSION}")
  endif()

  string(REPLACE "." ";" osquery_version_components "${osquery_version}")

  list(LENGTH osquery_version_components osquery_version_components_len)
  if(NOT osquery_version_components_len GREATER_EQUAL 3)
    message(FATAL_ERROR "Version should have at least 3 components (semvar).")
  endif()

  set(OSQUERY_VERSION_INTERNAL "${osquery_version}" PARENT_SCOPE)
  set(OSQUERY_VERSION_COMPONENTS "${osquery_version_components}" PARENT_SCOPE)
endfunction()

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

detectOsqueryVersion()

message(STATUS "osquery version: ${OSQUERY_VERSION_INTERNAL}")
