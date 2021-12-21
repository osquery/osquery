# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryMainHarnesses)
  if(OSQUERY_BUILD_FUZZERS AND
      NOT (OSQUERY_ENABLE_ADDRESS_SANITIZER OR OSQUERY_ENABLE_VALGRIND_SUPPORT))
    message(FATAL_ERROR "If fuzzing is enabled, a sanitizer must be chosen. "
      "Please choose between OSQUERY_ENABLE_ADDRESS_SANITIZER and OSQUERY_ENABLE_VALGRIND_SUPPORT.")
  endif()

  if(OSQUERY_BUILD_FUZZERS AND
      NOT ("${CMAKE_BUILD_TYPE}" STREQUAL "Release" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo"))
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

  generateOsqueryFuzzHarness(NAME osqueryfuzz-config SOURCES fuzz_config.cpp)
  generateOsqueryFuzzHarness(NAME osqueryfuzz-sqlquery SOURCES fuzz_sqlquery.cpp)

  set(osqueryfuzz_auditparser_deps
    osquery_core_init
    osquery_extensions_implthrift
    osquery_sdk_pluginsdk_emptyforeigntables
    osquery_tables_events_eventstable
  )
  generateOsqueryFuzzHarness(
    NAME osqueryfuzz-auditparser
    SOURCES fuzz_auditparser.cpp
    DEPS ${osqueryfuzz_auditparser_deps}
  )

  generateIncludeNamespace(osqueryfuzz-auditparser "osquery/main/harnesses" "FILE_ONLY" ${public_header_files})

endfunction()

function(generateOsqueryFuzzHarness)
  set(oneValueArgs NAME)
  set(multiValueArgs SOURCES DEPS INCLUDES)

  cmake_parse_arguments(HARNESS "" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  add_osquery_executable(${HARNESS_NAME} ${HARNESS_SOURCES})
  # TODO: osquery-toolchain libFuzzer is not compiled with -fPIC support,
  # temporarily disable PIE until the toolchain is fixed.
  if(DEFINED OSQUERY_TOOLCHAIN_SYSROOT)
    set_target_properties(${HARNESS_NAME} PROPERTIES POSITION_INDEPENDENT_CODE OFF)
  endif()

  if("${HARNESS_DEPS}" STREQUAL "")
    target_link_libraries(${HARNESS_NAME} PRIVATE osquery_harnesses)
  else()
    list(APPEND HARNESS_DEPS osquery_cxx_settings)
    target_link_libraries(${HARNESS_NAME} PRIVATE ${HARNESS_DEPS})
  endif()

  target_link_options(${HARNESS_NAME} PRIVATE -fsanitize=fuzzer)

  if(NOT "${HARNESS_INCLUDES}" STREQUAL "")
    target_include_directories(${HARNESS_NAME} PRIVATE ${HARNESS_INCLUDES})
  endif()
endfunction()

osqueryMainHarnesses()
