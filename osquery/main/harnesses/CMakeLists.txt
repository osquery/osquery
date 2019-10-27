# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryMainHarnesses)
  if(OSQUERY_ENABLE_FUZZER_SANITIZERS AND NOT OSQUERY_ENABLE_ADDRESS_SANITIZER)
    message( FATAL_ERROR "If fuzzing is enabled, a sanitizer must be chosen. (Currently only OSQUERY_ENABLE_ADDRESS_SANITIZER is available.)" )
  endif()

  if(OSQUERY_ENABLE_FUZZER_SANITIZERS AND (NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Release" AND NOT "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo"))
    message( FATAL_ERROR "If fuzzing is enabled, it must be built in Release or RelWithDebInfo" )
  endif()

  generateOsqueryFuzzHarnesses()

endfunction()

function(generateOsqueryFuzzHarnesses)
  set(fuzzing_libraries
    osquery_cxx_settings
    osquery_headers
    osquery_core
    osquery_core_plugins
    osquery_core_sql
    osquery_database
    osquery_devtools
    osquery_dispatcher
    osquery_experimental_eventsstream_registry
    osquery_experimental_tracing_syscallstracing
    osquery_extensions
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_process
    osquery_numericmonitoring
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_sql
    plugins_config_filesystemconfig
    plugins_config_tlsconfig
    plugins_config_parsers
    plugins_config_updateconfigplugin
    plugins_database_ephemeral
    plugins_database_rocksdbplugin
    plugins_database_sqliteplugin
    plugins_distributed_tls_distributedtls
    plugins_logger_buffered
    plugins_logger_filesystemlogger
    plugins_logger_stdout
    plugins_logger_syslog
    plugins_logger_tlslogger
    plugins_numericmonitoring_filesystem
    plugins_remote_enroll_tlsenrollplugin
    specs_tables
  )

  add_osquery_executable(osqueryfuzz-config fuzz_config.cpp)
  set_target_properties(osqueryfuzz-config PROPERTIES POSITION_INDEPENDENT_CODE true)
  target_link_libraries(osqueryfuzz-config PRIVATE ${fuzzing_libraries})
  target_link_options(osqueryfuzz-config PRIVATE -fsanitize=fuzzer)

  add_osquery_executable(osqueryfuzz-sqlquery fuzz_sqlquery.cpp)
  set_target_properties(osqueryfuzz-sqlquery PROPERTIES POSITION_INDEPENDENT_CODE true)
  target_link_libraries(osqueryfuzz-sqlquery PRIVATE ${fuzzing_libraries})
  target_link_options(osqueryfuzz-sqlquery PRIVATE -fsanitize=fuzzer)
endfunction()

osqueryMainHarnesses()
