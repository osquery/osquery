# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(ebpfpubLibraryMain)
  if(NOT DEFINED PLATFORM_LINUX)
    message(FATAL_ERROR "ebpfpub can only be imported when compiling for Linux")
  endif()

  if(NOT STREQUAL "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    message(FATAL_ERROR "Clang is required when building ebpfpub")
  endif()

  if(NOT "${OSQUERY_TOOLCHAIN_SYSROOT}" STREQUAL "")
    set(EBPF_COMMON_TOOLCHAIN_PATH "${OSQUERY_TOOLCHAIN_SYSROOT}" CACHE PATH "osquery toolchain sysroot path" FORCE)
  else()
    unset(EBPF_COMMON_TOOLCHAIN_PATH CACHE)
  endif()

  add_subdirectory("src" EXCLUDE_FROM_ALL)

  target_link_libraries(ebpfpub PRIVATE thirdparty_cxx_settings)
  add_library(thirdparty_ebpfpub ALIAS ebpfpub)
endfunction()

ebpfpubLibraryMain()
