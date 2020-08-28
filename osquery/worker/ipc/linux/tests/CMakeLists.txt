# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryWorkerIpcLinuxTestsMain)
  if(OSQUERY_BUILD_ROOT_TESTS)
    generateOsqueryWorkerIpcLinuxTestsTableContainerTest()
  endif()
endfunction()

function(generateOsqueryWorkerIpcLinuxTestsTableContainerTest)
  set(source_files
    worker_table_container_tests.cpp
  )

  add_osquery_executable(osquery_worker_ipc_linux_tests_tablecontainer-test ${source_files})

  target_link_libraries(osquery_worker_ipc_linux_tests_tablecontainer-test PRIVATE
    osquery_cxx_settings
    osquery_cxx_settings
    osquery_core
    osquery_core_sql
    osquery_database
    osquery_dispatcher
    osquery_events
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_remote_enroll_tlsenroll
    osquery_tables_events_eventstable
    osquery_utils_status
    specs_tables
    osquery_worker_ipc_linux_tablecontaineripc
    thirdparty_googletest
  )
endfunction()

osqueryWorkerIpcLinuxTestsMain()
