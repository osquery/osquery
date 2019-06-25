# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(pluginsLoggerTestsMain)
  generatePluginsLoggerTestsFilesystemloggertestsTest()
  generatePluginsLoggerTestsBufferedloggertestsTest()

  if(DEFINED PLATFORM_LINUX OR DEFINED PLATFORM_MACOS)
    generatePluginsLoggerTestsKafkaproducerloggertestsTest()
  endif()

  generatePluginsLoggerTestsAwskinesisloggertestsTest()
  generatePluginsLoggerTestsTlsloggertestsTest()

  if(DEFINED PLATFORM_POSIX)
    generatePluginsLoggerTestsSyslogloggertestsTest()
  endif()
endfunction()

function(generatePluginsLoggerTestsFilesystemloggertestsTest)
  add_osquery_executable(plugins_logger_tests_filesystemloggertests-test filesystem_logger.cpp)

  target_link_libraries(plugins_logger_tests_filesystemloggertests-test PRIVATE
    global_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_distributed
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_time
    plugins_config_tlsconfig
    plugins_database_ephemeral
    plugins_logger_filesystemlogger
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generatePluginsLoggerTestsBufferedloggertestsTest)
  add_osquery_executable(plugins_logger_tests_bufferedloggertests-test buffered_tests.cpp)

  target_link_libraries(plugins_logger_tests_bufferedloggertests-test PRIVATE
    global_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_distributed
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_time
    plugins_config_tlsconfig
    plugins_database_ephemeral
    plugins_logger_buffered
    specs_tables
    thirdparty_googletest
  )
endfunction()

function(generatePluginsLoggerTestsKafkaproducerloggertestsTest)
  add_osquery_executable(plugins_logger_tests_kafkaproducerloggertests-test kafka_producer_tests.cpp)

  target_link_libraries(plugins_logger_tests_kafkaproducerloggertests-test PRIVATE
    global_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_distributed
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_time
    plugins_config_tlsconfig
    plugins_database_ephemeral
    plugins_logger_kafkaproducer
    specs_tables
    thirdparty_googletest
    thirdparty_gflags
  )
endfunction()

function(generatePluginsLoggerTestsAwskinesisloggertestsTest)
  add_osquery_executable(plugins_logger_tests_awskinesisloggertests-test aws_kinesis_logger_tests.cpp)

  target_link_libraries(plugins_logger_tests_awskinesisloggertests-test PRIVATE
    global_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_distributed
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_time
    plugins_config_tlsconfig
    plugins_database_ephemeral
    plugins_logger_awskinesis
    plugins_logger_buffered
    specs_tables
    thirdparty_googletest
    thirdparty_gflags
  )
endfunction()

function(generatePluginsLoggerTestsTlsloggertestsTest)
  add_osquery_executable(plugins_logger_tests_tlsloggertests-test tls_logger_tests.cpp)

  target_link_libraries(plugins_logger_tests_tlsloggertests-test PRIVATE
    global_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_distributed
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_remote_tests_remotetestutils
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_time
    plugins_config_tlsconfig
    plugins_database_ephemeral
    plugins_logger_tlslogger
    specs_tables
    thirdparty_googletest
    thirdparty_gflags
    osquery_tools_tests_testfiles
  )
endfunction()

function(generatePluginsLoggerTestsSyslogloggertestsTest)
  add_osquery_executable(plugins_logger_tests_syslogloggertests-test syslog_logger_tests.cpp)

  target_link_libraries(plugins_logger_tests_syslogloggertests-test PRIVATE
    global_cxx_settings
    osquery_core
    osquery_core_plugins
    osquery_distributed
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_time
    plugins_config_tlsconfig
    plugins_database_ephemeral
    plugins_logger_syslog
    specs_tables
    thirdparty_googletest
    thirdparty_gflags
    osquery_remote_tests_remotetestutils
    osquery_tools_tests_testfiles
  )
endfunction()

pluginsLoggerTestsMain()
