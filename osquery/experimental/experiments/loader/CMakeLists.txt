# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

add_osquery_library(osquery_experiments_loader EXCLUDE_FROM_ALL
  include/osquery/experiments/loader.h
  src/loader.cpp
)

target_include_directories(osquery_experiments_loader PRIVATE
  include
)

target_include_directories(osquery_experiments_loader SYSTEM INTERFACE
  include
)

target_link_libraries(osquery_experiments_loader PUBLIC
  osquery_cxx_settings
  osquery_core
  thirdparty_boost
)

if(PLATFORM_LINUX)
  target_link_libraries(osquery_experiments_loader PUBLIC
    osquery_experiments_linuxevents
  )
endif()

target_compile_definitions(osquery_experiments_loader INTERFACE
  OSQUERY_BUILD_EXPERIMENTS=1
)
