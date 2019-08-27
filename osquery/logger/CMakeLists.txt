# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryLoggerMain)

  if(BUILD_TESTING)
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
    logger.h
  )

  generateIncludeNamespace(osquery_logger "osquery" "FILE_ONLY" ${public_header_files})
endfunction()

function(generateOsqueryLoggerDatalogger)
  add_osquery_library(osquery_logger_datalogger EXCLUDE_FROM_ALL
    logger.cpp
  )

  target_link_libraries(osquery_logger_datalogger PUBLIC
    global_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_database
    osquery_filesystem
    osquery_killswitch
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
