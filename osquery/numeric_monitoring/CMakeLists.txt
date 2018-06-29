#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

target_sources(libosquery
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/numeric_monitoring.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/plugin_interface.cpp"
)

ADD_OSQUERY_LIBRARY_ADDITIONAL(
  osquery_numeric_monitoring_plugins
  "${CMAKE_CURRENT_LIST_DIR}/plugins/filesystem.cpp"
)

ADD_OSQUERY_TEST_ADDITIONAL(
  "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/filesystem_tests.cpp"
)
