# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryWorkerIpcLinuxMain)

  if(OSQUERY_BUILD_TESTS)
    add_subdirectory("tests")
  endif()

  generateOSqueryWorkerIpcLinuxTableIpc()
  generateOsqueryWorkerIpcLinuxTableContainerIpc()
  generateOsqueryWorkerIpcLinuxPlatformTableContainerIpc()
endfunction()

function(generateOsqueryWorkerIpcLinuxTableContainerIpc)
  set(source_files
    linux_table_container_ipc.cpp
  )

  set(public_header_files
    linux_table_container_ipc.h
  )

  add_osquery_library(osquery_worker_ipc_linux_tablecontaineripc EXCLUDE_FROM_ALL ${source_files})

  target_link_libraries(osquery_worker_ipc_linux_tablecontaineripc PUBLIC
    osquery_cxx_settings
    osquery_worker_logging_glog_logger
    osquery_worker_ipc_linux_tableipc
  )

  generateIncludeNamespace(osquery_worker_ipc_linux_tablecontaineripc "osquery/worker/ipc/linux" FILE_ONLY ${public_header_files})

  if(OSQUERY_BUILD_ROOT_TESTS)
    add_test(NAME osquery_worker_ipc_linux_tests_tablecontainer-test COMMAND osquery_worker_ipc_linux_tests_tablecontainer-test)
    set_tests_properties(osquery_worker_ipc_linux_tests_tablecontainer-test PROPERTIES LABELS "root-required")
  endif()
endfunction()

function(generateOSqueryWorkerIpcLinuxTableIpc)
  set(source_files
    linux_table_ipc.cpp
  )

  set(public_header_files
    linux_table_ipc.h
  )

  add_osquery_library(osquery_worker_ipc_linux_tableipc EXCLUDE_FROM_ALL ${source_files})

  target_link_libraries(osquery_worker_ipc_linux_tableipc PUBLIC
    osquery_cxx_settings
    osquery_worker_ipc_tableipc
    osquery_worker_ipc_posix_pipechannel
    osquery_worker_ipc_tableipcjsonconverter
  )

  generateIncludeNamespace(osquery_worker_ipc_linux_tableipc "osquery/worker/ipc/linux" FILE_ONLY ${public_header_files})

endfunction()

function(generateOsqueryWorkerIpcLinuxPlatformTableContainerIpc)
  add_osquery_library(osquery_worker_ipc_linux_platformtablecontaineripc INTERFACE)

  set(public_header_files
    platform_table_container_ipc.h
  )

  target_link_libraries(osquery_worker_ipc_linux_platformtablecontaineripc INTERFACE
    osquery_cxx_settings
    osquery_worker_ipc_linux_tablecontaineripc
  )

  generateIncludeNamespace(osquery_worker_ipc_linux_platformtablecontaineripc "osquery/worker/ipc" FILE_ONLY ${public_header_files})
endfunction()


osqueryWorkerIpcLinuxMain()
