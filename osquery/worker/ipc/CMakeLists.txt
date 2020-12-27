# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryWorkerIpcMain)
  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOsqueryWorkerIpcTableIpcJsonConverter()
  generateOsqueryWorkerIpcPlatformTableContainerIpc()
  generateOsqueryWorkerIpcTableChannel()
  generateOsqueryWorkerIpcTableIpc()

  if(DEFINED PLATFORM_POSIX)
    add_subdirectory("posix")
  endif()

  if(DEFINED PLATFORM_LINUX)
    add_subdirectory("linux")
  endif()
endfunction()

function(generateOsqueryWorkerIpcTableIpcJsonConverter)
  set(source_files
    table_ipc_json_converter.cpp
  )

  set(public_header_files
    table_ipc_json_converter.h
  )

  add_osquery_library(osquery_worker_ipc_tableipcjsonconverter EXCLUDE_FROM_ALL ${source_files})

  target_link_libraries(osquery_worker_ipc_tableipcjsonconverter PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_core_sql
    osquery_utils_status
    osquery_utils_json
  )

  generateIncludeNamespace(osquery_worker_ipc_tableipcjsonconverter "osquery/worker/ipc" FULL_PATH ${public_header_files})

  add_test(NAME osquery_worker_ipc_tests_jsonconversions-test COMMAND osquery_worker_ipc_tests_jsonconversions-test)
endfunction()

function(generateOsqueryWorkerIpcPlatformTableContainerIpc)

  add_osquery_library(osquery_worker_ipc_platformtablecontaineripc INTERFACE)

  if(DEFINED PLATFORM_LINUX)
    target_link_libraries(osquery_worker_ipc_platformtablecontaineripc INTERFACE
      osquery_worker_ipc_linux_platformtablecontaineripc
    )
  else()
    set(public_header_files
      include/platform_table_container_ipc.h
    )

    target_link_libraries(osquery_worker_ipc_platformtablecontaineripc INTERFACE
      osquery_cxx_settings
      osquery_core_sql
      osquery_worker_logging_glog_logger
    )

    generateIncludeNamespace(osquery_worker_ipc_platformtablecontaineripc "osquery/worker/ipc" FILE_ONLY ${public_header_files})
  endif()
endfunction()

function(generateOsqueryWorkerIpcTableChannel)
  set(public_header_files
    include/table_channel_base.h
    include/table_channel_factory_base.h
  )

  add_osquery_library(osquery_worker_ipc_tablechannel INTERFACE)

  target_link_libraries(osquery_worker_ipc_tablechannel INTERFACE
    osquery_cxx_settings
    osquery_utils
  )

  generateIncludeNamespace(osquery_worker_ipc_tablechannel "osquery/worker/ipc" FILE_ONLY ${public_header_files})
endfunction()

function(generateOsqueryWorkerIpcTableIpc)

  set(public_header_files
    include/table_ipc_base.h
    include/table_ipc_message_handler.h
  )

  add_osquery_library(osquery_worker_ipc_tableipc INTERFACE)

  generateIncludeNamespace(osquery_worker_ipc_tableipc "osquery/worker/ipc" FILE_ONLY ${public_header_files})

  target_link_libraries(osquery_worker_ipc_tableipc INTERFACE
    osquery_cxx_settings
    osquery_core
    osquery_core_sql
    osquery_utils_status
    osquery_worker_ipc_tablechannel
    osquery_worker_ipc_tableipcjsonconverter
    osquery_worker_logging_logger
  )

endfunction()

osqueryWorkerIpcMain()
