# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryTablesLldpdMain)
  generateOsqueryTablesLldpdLlpdtable()
endfunction()

function(generateOsqueryTablesLldpdLlpdtable)
  add_osquery_library(osquery_tables_lldpd_llpdtable EXCLUDE_FROM_ALL
    lldp_neighbors.cpp
  )

  target_link_libraries(osquery_tables_lldpd_llpdtable PUBLIC
    global_cxx_settings
    osquery_headers
    osquery_logger
    thirdparty_lldpd
  )
endfunction()

osqueryTablesLldpdMain()
