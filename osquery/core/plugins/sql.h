/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

/**
 * @brief The osquery SQL implementation is managed as a plugin.
 *
 * The osquery RegistryFactory creates a Registry type called "sql",
 * then requires a single plugin registration also called "sql". Calls
 * within the application use boilerplate methods that wrap
 * Registry::call%s to this well-known registry and registry item
 * name.
 *
 * Abstracting the SQL implementation behind the osquery registry
 * allows the SDK (libosquery) to describe how the SQL implementation
 * is used without having dependencies on the third-party code.
 *
 * When osqueryd/osqueryi are built libosquery_additional, the library
 * which provides the core plugins and core virtual tables, includes
 * SQLite as the SQL implementation.
 */

#pragma once

#include <osquery/core/plugins/plugin.h>
#include <osquery/core/sql/column.h>
#include <osquery/core/sql/query_data.h>
#include <osquery/utils/status/status.h>

namespace osquery {

class SQLPlugin : public Plugin {
 public:
  /// Run a SQL query string against the SQL implementation.
  virtual Status query(const std::string& query,
                       QueryData& results,
                       bool use_cache) const = 0;

  /// Use the SQL implementation to parse a query string and return details
  /// (name, type) about the columns.
  virtual Status getQueryColumns(const std::string& query,
                                 TableColumns& columns) const = 0;

  /// Given a query, return the list of scanned tables.
  virtual Status getQueryTables(const std::string& query,
                                std::vector<std::string>& tables) const = 0;

  /**
   * @brief Attach a table at runtime.
   *
   * The SQL implementation plugin may need to manage how virtual tables are
   * attached at run time. In the case of SQLite where a single DB object is
   * managed, tables are enumerated and attached during initialization.
   */
  virtual Status attach(const std::string& /*name*/) {
    return Status::success();
  }

  /// Tables may be detached by name.
  virtual Status detach(const std::string& /*name*/) {
    return Status::success();
  }

 public:
  Status call(const PluginRequest& request, PluginResponse& response) override;
};

} // namespace osquery
