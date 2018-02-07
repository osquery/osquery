/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <boost/algorithm/string.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#define DECLARE_TABLE_IMPLEMENTATION_autoexec
#include <generated/tables/tbl_autoexec_defs.hpp>

namespace osquery {
namespace tables {

const std::map<std::string, std::map<std::string, std::string>>
    kAutoExecTableMappings = {
        {"startup_items", {{"name", "name"}, {"path", "path"}}},
        {"services", {{"module_path", "path"}, {"name", "name"}}},
        {"scheduled_tasks", {{"name", "name"}, {"path", "path"}}},
        {"ie_extensions", {{"name", "name"}, {"path", "path"}}},
        {"drivers", {{"description", "name"}, {"image", "path"}}}};

QueryData genAutoexec(QueryContext& context) {
  QueryData results;

  for (const auto& table : kAutoExecTableMappings) {
    std::vector<std::string> sql_cols;
    for (const auto& col : table.second) {
      sql_cols.push_back(col.first + " AS " + col.second);
    }
    SQL sql("SELECT '" + table.first + "' as source, " +
            boost::join(sql_cols, ", ") + " FROM " + table.first);
    if (!sql.ok()) {
      LOG(WARNING) << sql.getStatus().getMessage();
    }
    results.insert(results.end(), sql.rows().begin(), sql.rows().end());
  }

  return results;
}
} // namespace tables
} // namespace osquery
