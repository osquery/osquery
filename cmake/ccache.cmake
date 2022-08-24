# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

if(OSQUERY_ENABLE_CCACHE)
  find_program(ccache_command ccache)

  if(NOT "${ccache_command}" STREQUAL "ccache_command-NOTFOUND")
    message(STATUS "Found ccache: ${ccache_command}")
    set(CMAKE_CXX_COMPILER_LAUNCHER "${ccache_command}" CACHE FILEPATH "")
    set(CMAKE_C_COMPILER_LAUNCHER "${ccache_command}" CACHE FILEPATH "")
  else()
    message(STATUS "Not found: ccache. Install it and put it into the PATH if you want to speed up partial builds.")
  endif()
endif()
