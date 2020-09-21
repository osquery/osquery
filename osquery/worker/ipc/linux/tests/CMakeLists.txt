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
    osquery_core
    osquery_database
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_utils_status
    osquery_worker_ipc_linux_tablecontaineripc
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryWorkerIpcLinuxTestsMain()
