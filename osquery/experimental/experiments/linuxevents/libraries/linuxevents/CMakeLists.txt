# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

if(NOT EXISTS "src/CMakeLists.txt")
  find_package(Git REQUIRED)

  execute_process(
    COMMAND "${GIT_EXECUTABLE}" submodule update --init --recursive src
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  )
endif()

add_subdirectory("src" EXCLUDE_FROM_ALL)

target_link_libraries(linuxevents PRIVATE
  thirdparty_cxx_settings
)

add_library(thirdparty_linuxevents ALIAS
  linuxevents
)
