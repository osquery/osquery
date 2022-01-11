# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryProcessTestsMain)
  generateOsqueryProcessTestsProcessesstatsTest()
endfunction()

function(generateOsqueryProcessTestsProcessesstatsTest)
  add_executable(osquery_process_tests_processesstats-test
    processes_stats_tests.cpp
  )

  target_link_libraries(osquery_process_tests_processesstats-test PRIVATE
    osquery_cxx_settings
    osquery_extensions_implthrift
    osquery_sdk_pluginsdk
    osquery_processes_stats
    thirdparty_googletest
  )
endfunction()

osqueryProcessTestsMain()
