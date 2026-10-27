# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(pluginsLoggerTestsMain)
  generatePluginsLoggerTestsMergedtestsTest()
endfunction()

function(generatePluginsLoggerTestsMergedtestsTest)
  set(source_files
    filesystem_logger_tests.cpp
    logrotate_tests.cpp
    buffered_tests.cpp
    kafka_producer_tests.cpp
    tls_logger_tests.cpp
  )

  set(link_libraries
    osquery_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_remote_tests_remotetestutils
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_time
    plugins_logger_buffered
    plugins_logger_filesystemlogger
    plugins_logger_kafkaproducer
    plugins_logger_tlslogger
    tests_helper
    thirdparty_googletest
    thirdparty_gflags
  )

  if(OSQUERY_BUILD_AWS)
    list(APPEND source_files aws_kinesis_logger_tests.cpp)
    list(APPEND link_libraries plugins_logger_awskinesis)
  endif()

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files syslog_logger_tests.cpp)
    list(APPEND link_libraries plugins_logger_syslog)
  endif()

  add_osquery_executable(plugins_logger_tests_mergedtests-test ${source_files})

  target_link_libraries(plugins_logger_tests_mergedtests-test PRIVATE
    ${link_libraries}
  )
endfunction()

pluginsLoggerTestsMain()
