# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesUtilityMain)
  generateTablesUtilityUtilitytable()
endfunction()

function(generateTablesUtilityUtilitytable)
  add_osquery_library(osquery_tables_utility_utilitytable EXCLUDE_FROM_ALL
    file.cpp
    osquery.cpp
    time.cpp
  )

  target_link_libraries(osquery_tables_utility_utilitytable PUBLIC
    osquery_cxx_settings
    osquery_config
    osquery_core
    osquery_core_init
    osquery_filesystem
    osquery_process
    osquery_utils_macros
    osquery_utils_system_systemutils
    osquery_worker_ipc_platformtablecontaineripc
    osquery_worker_logging_glog_logger
    thirdparty_boost
  )
endfunction()

osqueryTablesUtilityMain()
