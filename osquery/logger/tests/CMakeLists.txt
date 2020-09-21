# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryLoggerTestsMain)
  generateOsqueryLoggerTestsTest()
endfunction()

function(generateOsqueryLoggerTestsTest)
  add_osquery_executable(osquery_logger_tests-test logger.cpp)

  target_link_libraries(osquery_logger_tests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_registry
    osquery_utils_info
    osquery_utils_system_time
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryLoggerTestsMain()
