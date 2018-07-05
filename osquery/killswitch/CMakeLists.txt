#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

target_sources(libosquery
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/killswitch.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/killswitch_plugin.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/killswitch_plugin.h"
    "${CMAKE_CURRENT_LIST_DIR}/killswitch_refreshable_plugin.h"
    "${CMAKE_CURRENT_LIST_DIR}/killswitch_refreshable_plugin.cpp"
)
ADD_OSQUERY_LIBRARY_ADDITIONAL(
  osquery_killswitch_plugin
  "${CMAKE_CURRENT_LIST_DIR}/plugins/killswitch_filesystem.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/killswitch_filesystem.h"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/killswitch_tls.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/killswitch_tls.h"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/killswitch_json.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/killswitch_json.h"
)
ADD_OSQUERY_TEST_CORE(
  "${CMAKE_CURRENT_LIST_DIR}/tests/killswitch_tests.cpp"
)
ADD_OSQUERY_TEST_ADDITIONAL(
  "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/killswitch_filesystem_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/killswitch_json_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/killswitch_tls_tests.cpp"
)
