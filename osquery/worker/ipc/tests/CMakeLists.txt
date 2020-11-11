# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

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
    osquery_extensions
    osquery_extensions_implthrift
    osquery_registry
    osquery_utils_status
    osquery_worker_ipc_tableipc
    osquery_worker_ipc_tableipcjsonconverter
    tests_helper
    thirdparty_googletest
  )
endfunction()

osqueryWorkerIpcTestsMain()
