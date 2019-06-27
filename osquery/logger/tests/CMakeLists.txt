# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryLoggerTestsMain)
  generateOsqueryLoggerTestsTest()
endfunction()

function(generateOsqueryLoggerTestsTest)
  add_osquery_executable(osquery_logger_tests-test logger.cpp)

  target_link_libraries(osquery_logger_tests-test PRIVATE
    global_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_distributed
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_utils_info
    osquery_utils_system_time
    plugins_config_tlsconfig
    plugins_database_ephemeral
    specs_tables
    thirdparty_googletest
  )
endfunction()

osqueryLoggerTestsMain()
