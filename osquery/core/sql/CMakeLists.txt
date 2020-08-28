# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryCoreSqlMain)
  generateOsqueryCoreSql()
endfunction()

function(generateOsqueryCoreSql)
  add_osquery_library(osquery_core_sql EXCLUDE_FROM_ALL
    column.cpp
    diff_results.cpp
    query_data.cpp
    query_performance.cpp
    row.cpp
    scheduled_query.cpp
    table_rows.cpp
  )

  target_link_libraries(osquery_core_sql PUBLIC
    osquery_cxx_settings
    osquery_utils_json
    osquery_utils_status
    thirdparty_sqlite
  )

  set(public_header_files
    column.h
    diff_results.h
    query_data.h
    query_performance.h
    row.h
    scheduled_query.h
    table_row.h
    table_rows.h
  )

  generateIncludeNamespace(osquery_core_sql "osquery/core/sql" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryCoreSqlMain()
