# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

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

option(OSQUERY_BUILD_TESTS "Whether to enable and build tests or not")
option(OSQUERY_BUILD_ROOT_TESTS "Whether to enable and build tests that require root access")

# Sanitizers
option(OSQUERY_ENABLE_ADDRESS_SANITIZER "Whether to enable Address Sanitizer")

if(DEFINED PLATFORM_POSIX)
  option(OSQUERY_ENABLE_THREAD_SANITIZER "Whether to enable Thread Sanitizer")
endif()

if(DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_WINDOWS)
  option(OSQUERY_BUILD_FUZZERS "Whether to build fuzzing harnesses")

  if(DEFINED PLATFORM_WINDOWS AND OSQUERY_BUILD_FUZZERS)
    if(OSQUERY_MSVC_TOOLSET_VERSION LESS 143)
      message(FATAL_ERROR "Fuzzers are not supported on MSVC toolset version less than 143")
    endif()
  endif()

  if(DEFINED PLATFORM_LINUX)
    option(OSQUERY_ENABLE_LEAK_SANITIZER "Whether to enable Leak Sanitizer")

    # This is required for Boost coroutines/context to be built in a way that are compatible to Valgrind
    option(OSQUERY_ENABLE_VALGRIND_SUPPORT "Whether to enable support for osquery to be run under Valgrind")

    if(OSQUERY_ENABLE_VALGRIND_SUPPORT AND OSQUERY_ENABLE_ADDRESS_SANITIZER)
      message(FATAL_ERROR "Cannot mix Vagrind and ASAN sanitizers, please choose only one.")
    endif()
  endif()
endif()

if(DEFINED PLATFORM_WINDOWS)
  option(OSQUERY_ENABLE_INCREMENTAL_LINKING "Whether to enable or disable incremental linking (/INCREMENTAL or /INCREMENTAL:NO). Enabling it greatly increases disk usage")
endif()

option(OSQUERY_ENABLE_CLANG_TIDY "Enables clang-tidy support")
set(OSQUERY_CLANG_TIDY_CHECKS "-checks=cert-*,cppcoreguidelines-*,performance-*,portability-*,readability-*,modernize-*,bugprone-*" CACHE STRING "List of checks performed by clang-tidy")

option(OSQUERY_BUILD_BPF "Whether to enable and build BPF support" ON)
option(OSQUERY_BUILD_AWS "Whether to build the aws tables and library, to decrease memory usage and increase speed during build." ON)
option(OSQUERY_BUILD_DPKG "Whether to build the dpkg tables" ON)

option(OSQUERY_ENABLE_FORMAT_ONLY "Configure CMake to format only, not build")

# Unfortunately, due glog always enabling BUILD_TESTING, we have to force it off, so that tests won't be built
overwrite_cache_variable("BUILD_TESTING" "BOOL" "OFF")

if(DEFINED PLATFORM_POSIX)
  option(OSQUERY_ENABLE_CCACHE "Whether to search ccache in the system and use it in the build" ON)
endif()

set(third_party_source_list "source;formula")

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules" CACHE STRING "A list of paths containing CMake module files")
set(OSQUERY_THIRD_PARTY_SOURCE "${third_party_source_list}" CACHE STRING "Sources used to acquire third-party dependencies")

set(OSQUERY_INSTALL_DIRECTIVES "${CMAKE_SOURCE_DIR}/cmake/install_directives.cmake" CACHE FILEPATH "Install directives")

# This is the default S3 storage used by Facebook to store 3rd party dependencies; it
# is provided here as a configuration option
if("${THIRD_PARTY_REPOSITORY_URL}" STREQUAL "")
  set(THIRD_PARTY_REPOSITORY_URL "https://s3.amazonaws.com/osquery-packages")
endif()

# When building on macOS, make sure we are only building one architecture at a time
if(PLATFORM_MACOS)
  list(LENGTH CMAKE_OSX_ARCHITECTURES osx_arch_count)

  if(osx_arch_count GREATER 1)
    message(FATAL_ERROR "The CMAKE_OSX_ARCHITECTURES setting can only contain one architecture at a time")
  endif()
endif()

detectOsqueryVersion()

message(STATUS "osquery version: ${OSQUERY_VERSION_INTERNAL}")
