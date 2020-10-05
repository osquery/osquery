# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryMainMain)
  generateOsqueryMain()

  if((OSQUERY_ENABLE_FUZZER_SANITIZERS OR OSQUERY_BUILD_TESTS) AND DEFINED PLATFORM_LINUX)
    add_subdirectory("harnesses")
  endif()
endfunction()

function(generateOsqueryMain)
  set(source_files
    main.cpp
  )

  if(DEFINED PLATFORM_POSIX)
    list(APPEND source_files
      posix/main.cpp
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    list(APPEND source_files
      windows/main.cpp
    )
  endif()

  add_osquery_library(osquery_main EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_main PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_core_init
    osquery_core_plugins
    osquery_core_sql
    osquery_database
    osquery_devtools
    osquery_dispatcher
    osquery_dispatcher_scheduler
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
    thirdparty_boost
  )

  if(DEFINED PLATFORM_LINUX)
    target_link_libraries(osquery_main PUBLIC
      plugins_logger_awsfirehose
      plugins_logger_awskinesis
      plugins_logger_awslogforwarder
      plugins_logger_kafkaproducer
    )

  elseif(DEFINED PLATFORM_MACOS)
    target_link_libraries(osquery_main PUBLIC
      plugins_logger_awsfirehose
      plugins_logger_awskinesis
      plugins_logger_awslogforwarder
      plugins_logger_kafkaproducer
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    target_link_libraries(osquery_main PUBLIC
      plugins_logger_awsfirehose
      plugins_logger_awskinesis
      plugins_logger_awslogforwarder
      plugins_logger_windowseventlog
      plugins_logger_kafkaproducer
    )
  endif()

  set(public_header_files
    main.h
  )

  generateIncludeNamespace(osquery_main "osquery/main" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryMainMain()
