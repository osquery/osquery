# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

cmake_minimum_required(VERSION 3.13.3)

macro(librariesMain)
  if("${OSQUERY_THIRD_PARTY_SOURCE}" STREQUAL "")
    message(STATUS "Disabling local third-party sources. Using system libraries")
    return()
  endif()

  foreach(source ${OSQUERY_THIRD_PARTY_SOURCE})
    set(third_party_source_path "${CMAKE_CURRENT_SOURCE_DIR}/cmake/${source}/modules")
    if(NOT EXISTS "${third_party_source_path}")
      message(WARNING "Invalid third-party source setting: ${source}")
      continue()
    endif()

    list(APPEND CMAKE_MODULE_PATH "${third_party_source_path}")
    set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} PARENT_SCOPE)
  endforeach()
endmacro()

librariesMain()
