# Copyright (c) 2018-present, Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.13.1)
project(osquery)

include(cmake/globals.cmake)
include(cmake/utilities.cmake)
include(cmake/options.cmake)

function(main)
  message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
  message(STATUS "Shared libraries: ${BUILD_SHARED_LIBS}")

  if(NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR
     NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    message(STATUS "Warning: the selected C or C++ compiler is not clang/clang++. Compilation may fail")
  endif()

  generateGlobalSettingsTargets()

  add_subdirectory("third-party")
  add_subdirectory("osquery")
  add_subdirectory("tools")
  add_subdirectory("specs")

  processLinkWholeArchiveSettings()
endfunction()

main()
