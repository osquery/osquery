# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryLoggerMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryLogger()
  generateOsqueryLoggerDatalogger()
endfunction()

function(generateOsqueryLogger)
  add_osquery_library(osquery_logger INTERFACE)

  target_link_libraries(osquery_logger INTERFACE
    thirdparty_glog
  )

  set(public_header_files
    data_logger.h
    logger.h
  )

  generateIncludeNamespace(osquery_logger "osquery/logger" "FILE_ONLY" ${public_header_files})
endfunction()

function(generateOsqueryLoggerDatalogger)
  add_osquery_library(osquery_logger_datalogger EXCLUDE_FROM_ALL
    logger.cpp
  )

  target_link_libraries(osquery_logger_datalogger PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_database
    osquery_events_eventsregistry
    osquery_filesystem
    osquery_numericmonitoring
    osquery_registry
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_time
    osquery_logger
  )

  add_test(NAME osquery_logger_tests-test COMMAND osquery_logger_tests-test)
endfunction()

osqueryLoggerMain()
