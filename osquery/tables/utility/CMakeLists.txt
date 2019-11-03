# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryTablesUtilityMain)
  generateTablesUtilityUtilitytable()
endfunction()

function(generateTablesUtilityUtilitytable)
  add_osquery_library(osquery_tables_utility_utilitytable EXCLUDE_FROM_ALL
    file.cpp
    osquery.cpp
    time.cpp
  )

  target_link_libraries(osquery_tables_utility_utilitytable PRIVATE
    osquery_cxx_settings
    osquery_config
    osquery_core
    osquery_filesystem
    osquery_process
    osquery_utils
    osquery_utils_system
    thirdparty_boost
  )
endfunction()

osqueryTablesUtilityMain()
