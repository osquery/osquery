# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryTablesForensicMain)
  generateOsqueryTablesForensic()
endfunction()

function(generateOsqueryTablesForensic)
  add_osquery_library(osquery_tables_forensic EXCLUDE_FROM_ALL
    carves.cpp
  )

  target_link_libraries(osquery_tables_forensic PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_carver
    osquery_core
    osquery_database
    osquery_dispatcher
    osquery_distributed
    osquery_logger
    osquery_utils_json
    thirdparty_boost
  )
endfunction()

osqueryTablesForensicMain()
