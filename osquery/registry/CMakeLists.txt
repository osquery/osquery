#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

ADD_OSQUERY_LIBRARY(TRUE osquery_registry "")

target_sources(osquery_registry
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/plugin.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/registry_factory.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/registry_interface.cpp"
)

ADD_OSQUERY_TEST(TRUE
  "${CMAKE_CURRENT_LIST_DIR}/tests/registry_tests.cpp"
)
