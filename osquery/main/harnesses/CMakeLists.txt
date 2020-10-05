# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryMainHarnesses)
  if(OSQUERY_ENABLE_FUZZER_SANITIZERS AND NOT OSQUERY_ENABLE_ADDRESS_SANITIZER)
    message( FATAL_ERROR "If fuzzing is enabled, a sanitizer must be chosen. (Currently only OSQUERY_ENABLE_ADDRESS_SANITIZER is available.)" )
  endif()

  if(OSQUERY_ENABLE_FUZZER_SANITIZERS AND
      (NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Release" AND NOT "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo"))
    message( FATAL_ERROR "If fuzzing is enabled, it must be built in Release or RelWithDebInfo" )
  endif()

  add_osquery_library(osquery_harnesses EXCLUDE_FROM_ALL
    fuzz_utils.cpp
  )

  target_link_libraries(osquery_harnesses PUBLIC
    osquery_cxx_settings
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
    plugins_database_rocksdbplugin
    plugins_database_sqliteplugin
    plugins_distributed_tls_distributedtls
    plugins_logger_buffered
    plugins_logger_filesystemlogger
    plugins_logger_stdout
    plugins_logger_syslog
    plugins_logger_tlslogger
    plugins_numericmonitoring_filesystem
    plugins_remote_enroll_tlsenroll
    specs_tables
  )

  set(public_header_files
    fuzz_utils.h
  )

  generateIncludeNamespace(osquery_harnesses "osquery/main/harnesses" "FILE_ONLY" ${public_header_files})

  generateOsqueryFuzzHarness(osqueryfuzz-config fuzz_config.cpp)
  generateOsqueryFuzzHarness(osqueryfuzz-sqlquery fuzz_sqlquery.cpp)
endfunction()

function(generateOsqueryFuzzHarness harness_name source_files)
  add_osquery_executable(${harness_name} ${source_files})
  # TODO: osquery-toolchain libFuzzer is not compiled with -fPIC support,
  # temporarily disable PIE until the toolchain is fixed.
  if(DEFINED OSQUERY_TOOLCHAIN_SYSROOT)
    set_target_properties(${harness_name} PROPERTIES POSITION_INDEPENDENT_CODE OFF)
  endif()
  target_link_libraries(${harness_name} PRIVATE osquery_harnesses)
  target_link_options(${harness_name} PRIVATE -fsanitize=fuzzer)
endfunction()

osqueryMainHarnesses()
