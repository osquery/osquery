/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>

#include <boost/algorithm/string.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

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
