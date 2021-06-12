# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(pluginsLoggerTestsMain)
  if(OSQUERY_BUILD_AWS)
    generatePluginsLoggerTestsAwskinesisloggertestsTest()
  endif()
  generatePluginsLoggerTestsFilesystemloggertestsTest()
  generatePluginsLoggerTestsBufferedloggertestsTest()
  generatePluginsLoggerTestsKafkaproducerloggertestsTest()
  generatePluginsLoggerTestsTlsloggertestsTest()

  if(DEFINED PLATFORM_POSIX)
    generatePluginsLoggerTestsSyslogloggertestsTest()
  endif()
endfunction()

function(generatePluginsLoggerTestsFilesystemloggertestsTest)
  add_osquery_executable(plugins_logger_tests_filesystemloggertests-test
    filesystem_logger_tests.cpp
    logrotate_tests.cpp
  )

  target_link_libraries(plugins_logger_tests_filesystemloggertests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_registry
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_time
    plugins_logger_filesystemlogger
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generatePluginsLoggerTestsBufferedloggertestsTest)
  add_osquery_executable(plugins_logger_tests_bufferedloggertests-test buffered_tests.cpp)

  target_link_libraries(plugins_logger_tests_bufferedloggertests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_registry
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_time
    plugins_logger_buffered
    tests_helper
    thirdparty_googletest
  )
endfunction()

function(generatePluginsLoggerTestsKafkaproducerloggertestsTest)
  add_osquery_executable(plugins_logger_tests_kafkaproducerloggertests-test kafka_producer_tests.cpp)

  target_link_libraries(plugins_logger_tests_kafkaproducerloggertests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_registry
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_time
    plugins_logger_kafkaproducer
    tests_helper
    thirdparty_googletest
    thirdparty_gflags
  )
endfunction()

function(generatePluginsLoggerTestsAwskinesisloggertestsTest)
  add_osquery_executable(plugins_logger_tests_awskinesisloggertests-test aws_kinesis_logger_tests.cpp)

  target_link_libraries(plugins_logger_tests_awskinesisloggertests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_registry
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_time
    plugins_logger_awskinesis
    plugins_logger_buffered
    tests_helper
    thirdparty_googletest
    thirdparty_gflags
  )
endfunction()

function(generatePluginsLoggerTestsTlsloggertestsTest)
  add_osquery_executable(plugins_logger_tests_tlsloggertests-test tls_logger_tests.cpp)

  target_link_libraries(plugins_logger_tests_tlsloggertests-test PRIVATE
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
    plugins_logger_tlslogger
    tests_helper
    thirdparty_googletest
    thirdparty_gflags
  )
endfunction()

function(generatePluginsLoggerTestsSyslogloggertestsTest)
  add_osquery_executable(plugins_logger_tests_syslogloggertests-test syslog_logger_tests.cpp)

  target_link_libraries(plugins_logger_tests_syslogloggertests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_registry
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_time
    plugins_logger_syslog
    tests_helper
    thirdparty_googletest
    thirdparty_gflags
  )
endfunction()

pluginsLoggerTestsMain()
