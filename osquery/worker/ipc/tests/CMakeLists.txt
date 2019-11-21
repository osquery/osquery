# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryWorkerIpcTestsMain)
  generateOsqueryWorkerIpcTestsJsonConversionsTest()
endfunction()

function(generateOsqueryWorkerIpcTestsJsonConversionsTest)
  set(source_files
    worker_json_conversions_test.cpp
  )

  add_osquery_executable(osquery_worker_ipc_tests_jsonconversions-test ${source_files})

  target_link_libraries(osquery_worker_ipc_tests_jsonconversions-test PRIVATE
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
    osquery_worker_ipc_tableipc
    osquery_worker_ipc_tableipcjsonconverter
    specs_tables
    thirdparty_googletest
  )
endfunction()

osqueryWorkerIpcTestsMain()
