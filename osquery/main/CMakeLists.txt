# Copyright (c) 2018-present, Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.13.1)

function(osquery_main_main)
  generateOsqueryMain()
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

  add_library(osquery_main EXCLUDE_FROM_ALL
    ${source_files}
  )

  target_link_libraries(osquery_main PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_config_parsers
    osquery_config_plugins_filesystemconfig
    osquery_config_plugins_tlsconfig
    osquery_core
    osquery_core_plugins
    osquery_core_sql
    osquery_database
    osquery_database_plugins_ephemeral
    osquery_database_plugins_rocksdb
    osquery_database_plugins_sqlite
    osquery_devtools
    osquery_dispatcher
    osquery_distributed_plugins_tls
    osquery_extensions
    osquery_killswitch
    osquery_killswitch_plugins_filesystem
    osquery_killswitch_plugins_tls
    osquery_logger_datalogger
    osquery_logger_plugins_buffered
    osquery_logger_plugins_filesystem
    osquery_logger_plugins_stdout
    osquery_logger_plugins_syslog
    osquery_logger_plugins_tlslogger
    osquery_process
    osquery_numericmonitoring
    osquery_numericmonitoring_plugins_filesystem
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_sql
    specs_tables
    thirdparty_boost
  )

  if(DEFINED PLATFORM_LINUX)
    target_link_libraries(osquery_main PUBLIC
      osquery_logger_plugins_awsfirehose
      osquery_logger_plugins_awskinesis
      osquery_logger_plugins_awslogforwarder
      osquery_logger_plugins_kafkaproducer
    )

  elseif(DEFINED PLATFORM_MACOS)
    target_link_libraries(osquery_main PUBLIC
      osquery_logger_plugins_awsfirehose
      osquery_logger_plugins_awskinesis
      osquery_logger_plugins_awslogforwarder
      osquery_logger_plugins_kafkaproducer
    )

  elseif(DEFINED PLATFORM_WINDOWS)
    target_link_libraries(osquery_main PUBLIC
      osquery_logger_plugins_awsfirehose
      osquery_logger_plugins_awskinesis
      osquery_logger_plugins_awslogforwarder
      osquery_logger_plugins_windowseventlog
    )
  endif()

  set(public_header_files
    main.h
  )

  generateIncludeNamespace(osquery_main "osquery/main" "FILE_ONLY" ${public_header_files})
endfunction()

osquery_main_main()
