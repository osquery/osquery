# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

cmake_minimum_required(VERSION 3.17.5 FATAL_ERROR)

cmake_policy(SET CMP0083 NEW)

# toolchain.cmake needs to be included before project() because the former sets the compiler path for the custom toolchain,
# if the user specify it and the latter does compiler detection.
# utilities.cmake is a dependency of toolchain.cmake.
include(cmake/utilities.cmake)
include(cmake/toolchain.cmake)

project(osquery)

if(OSQUERY_BUILD_TESTS)
  enable_testing()
endif()

include(cmake/globals.cmake)
include(cmake/options.cmake)
include(cmake/flags.cmake)
include(cmake/packaging.cmake)

if(DEFINED PLATFORM_LINUX AND "${CMAKE_VERSION}" VERSION_GREATER_EQUAL "3.18.0")
  if(OSQUERY_IGNORE_CMAKE_MAX_VERSION_CHECK)
    message(WARNING
      "CPack contained in CMake version 3.18 and newer generates RPM packages that won't install correctly on some distributions. " 
      "You are using version ${CMAKE_VERSION} which has the bug, remember to use version 3.17.5 if a RPM package has to be generated.")
  else()
    message(FATAL_ERROR
      "CPack contained in CMake version 3.18 and newer generates RPM packages that won't install correctly on some distributions. "
      "You are using version ${CMAKE_VERSION} which has the bug, please use version 3.17.5 or set OSQUERY_IGNORE_CMAKE_MAX_VERSION_CHECK=TRUE "
      "if you're not going to generate a RPM package."
    )
  endif()
endif()

if(OSQUERY_TOOLCHAIN_SYSROOT AND NOT DEFINED PLATFORM_LINUX)
  message(FATAL_ERROR "The custom toolchain can only be used with Linux, undefine OSQUERY_TOOLCHAIN_SYSROOT and specify a compiler to use")
endif()

# clang-tidy needs to be initialized in global scope, before any
# target is created
if(OSQUERY_ENABLE_CLANG_TIDY)
  find_package(clang-tidy)
  if(TARGET clang-tidy::clang-tidy)
    foreach(language C CXX)
      set("CMAKE_${language}_CLANG_TIDY"
        "${CLANG-TIDY_EXECUTABLE};${OSQUERY_CLANG_TIDY_CHECKS}"
      )
    endforeach()

  else()
    message(WARNING "clang-tidy: Disabled because it was not found")
  endif()
endif()

function(main)
  message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
  message(STATUS "Shared libraries: ${BUILD_SHARED_LIBS}")

  if(DEFINED PLATFORM_MACOS)
    if((NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" AND NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang") OR
      (NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" AND NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "AppleClang"))
      message(STATUS "Warning: the selected C or C++ compiler is not clang/clang++. Compilation may fail")
    endif()
  elseif(NOT DEFINED PLATFORM_WINDOWS)
    if(NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR
       NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
      message(STATUS "Warning: the selected C or C++ compiler is not clang/clang++. Compilation may fail")
    endif()
  endif()

  findPythonExecutablePath()
  generateSpecialTargets()

  add_subdirectory("libraries")
  importLibraries()

  add_subdirectory("osquery")
  add_subdirectory("plugins")
  add_subdirectory("tools")
  add_subdirectory("specs")
  add_subdirectory("external")
  add_subdirectory("tests")

  if(DEFINED PLATFORM_WINDOWS)
    enableOsqueryWEL()
  endif()

  identifyPackagingSystem()
  generateInstallTargets()
  generatePackageTarget()
endfunction()

function(importLibraries)
  set(library_descriptor_list
    "Linux,Darwin:augeas"
    "Linux:berkeley-db"
    "Linux,Darwin,Windows:boost"
    "Linux,Darwin,Windows:bzip2"
    "Linux,Darwin,Windows:gflags"
    "Linux,Darwin,Windows:glog"
    "Linux,Darwin,Windows:googletest"
    "Linux,Darwin,Windows:libarchive"
    "Linux:libaudit"
    "Linux:libcryptsetup"
    "Linux:libdevmapper"
    "Linux:libdpkg"
    "Linux:libelfin"
    "Linux:libgcrypt"
    "Linux:libgpg-error"
    "Linux:libiptables"
    "Linux,Darwin:libmagic"
    "Linux,Darwin,Windows:librdkafka"
    "Linux:librpm"
    "Linux:libudev"
    "Linux,Darwin,Windows:libxml2"
    "Linux,Darwin,Windows:linenoise-ng"
    "Linux,Darwin:lldpd"
    "Linux,Darwin,Windows:lzma"
    "Linux,Darwin:popt"
    "Linux,Darwin,Windows:rapidjson"
    "Linux,Darwin,Windows:rocksdb"
    "Linux,Darwin,Windows:sleuthkit"
    "Linux,Darwin:smartmontools"
    "Linux,Darwin,Windows:sqlite"
    "Linux,Darwin:ssdeep-cpp"
    "Linux,Darwin,Windows:thrift"
    "Linux:util-linux"
    "Linux,Darwin,Windows:yara"
    "Linux,Darwin,Windows:zlib"
    "Linux,Darwin,Windows:zstd"
    "Linux,Darwin,Windows:openssl"
    "Linux,Darwin,Windows:aws-sdk-cpp"
    "Linux,Darwin,Windows:icu"
    "Linux:expat"
    "Linux:dbus"
    "Linux:libcap"
  )

  if(OSQUERY_BUILD_BPF)
    list(APPEND library_descriptor_list
      "Linux:ebpfpub"
    )
  endif()

  foreach(library_descriptor ${library_descriptor_list})
    # Expand the library descriptor
    string(REPLACE ":" ";" library_descriptor "${library_descriptor}")

    list(GET library_descriptor 0 platform_list)
    list(GET library_descriptor 1 library)

    string(REPLACE "," ";" platform_list "${platform_list}")

    list(FIND platform_list "${CMAKE_SYSTEM_NAME}" platform_index)
    if(platform_index EQUAL -1)
      continue()
    endif()

    find_package("${library}" REQUIRED)

    # Skip libraries which already use our internal target name
    if(TARGET "thirdparty_${library}")
      continue()

    # For generic libraries that import the library name, let's create
    # an alias
    elseif(TARGET "${library}")
      add_library("thirdparty_${library}" ALIAS "${library}")

    # Legacy libraries will just export variables; build a new INTERFACE
    # target with them
    elseif(DEFINED "${library}_LIBRARIES")
      if(NOT DEFINED "${library}_INCLUDE_DIRS")
        message(FATAL_ERROR "Variable ${library}_INCLUDE_DIRS was not found!")
      endif()

      add_library("thirdparty_${library}" INTERFACE)

      target_link_libraries("thirdparty_${library}" INTERFACE
        ${library}_LIBRARIES
      )

      target_include_directories("thirdparty_${library}" INTERFACE
        ${library}_INCLUDE_DIRS
      )

      if(DEFINED "${library}_DEFINITIONS")
        target_compile_definitions("thirdparty_${library}" INTERFACE
          ${library}_DEFINITIONS
        )
      endif()

    else()
      # In case we were trying to import ebpfpub, check whether the build option
      # has been turned OFF automatically because the installed LLVM libraries
      # were broken/not compatible
      if(NOT OSQUERY_BUILD_BPF AND "${library}" STREQUAL "ebpfpub")
        message(WARNING "ebpfpub could not correctly import the LLVM libraries. BPF support has been disabled")
      else()
        message(FATAL_ERROR "The '${library}' library was found but it couldn't be imported correctly")
      endif()
    endif()
  endforeach()
endfunction()

main()
