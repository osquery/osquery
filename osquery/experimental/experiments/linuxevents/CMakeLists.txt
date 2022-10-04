# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

add_subdirectory("libraries")

add_osquery_library(osquery_experiments_linuxevents EXCLUDE_FROM_ALL
  include/osquery/experiments/linuxevents.h
  src/linuxevents.cpp

  src/bpfprocesseventstable.h
  src/bpfprocesseventstable.cpp

  src/linuxeventsservice.h
  src/linuxeventsservice.cpp
)

target_include_directories(osquery_experiments_linuxevents PRIVATE
  include
)

target_include_directories(osquery_experiments_linuxevents SYSTEM INTERFACE
  include
)

target_link_libraries(osquery_experiments_linuxevents PUBLIC
  osquery_cxx_settings
  osquery_core

  thirdparty_boost
  thirdparty_linuxevents
)
