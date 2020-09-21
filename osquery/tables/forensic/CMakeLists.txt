# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryTablesForensicMain)
  generateOsqueryTablesForensic()
endfunction()

function(generateOsqueryTablesForensic)
  add_osquery_library(osquery_tables_forensic EXCLUDE_FROM_ALL
    carves.cpp
  )

  target_link_libraries(osquery_tables_forensic PUBLIC
    osquery_cxx_settings
    osquery_carver_utils
    osquery_core
    osquery_database
    osquery_logger
    osquery_utils_json
    thirdparty_boost
  )
endfunction()

osqueryTablesForensicMain()
