/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/core/plugins/sql_plugin.h>
#include <osquery/registry_factory.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/sql/virtual_table.h>

namespace osquery {

/// The SQLiteSQLPlugin implements the "sql" registry for internal/core.
class SQLiteSQLPlugin : public SQLPlugin {
 public:
  /// Execute SQL and store results.
  Status query(const std::string& query,
               QueryData& results,
               bool use_cache) const override;

  /// Introspect, explain, the suspected types selected in an SQL statement.
  Status getQueryColumns(const std::string& query,
                         TableColumns& columns) const override;

  /// Similar to getQueryColumns but return the scanned tables.
  Status getQueryTables(const std::string& query,
                        std::vector<std::string>& tables) const override;

  /// Create a SQLite module and attach (CREATE).
  Status attach(const std::string& name) override;

  /// Detach a virtual table (DROP).
  void detach(const std::string& name) override;
};

/// SQL provider for osquery internal/core.
REGISTER_INTERNAL(SQLiteSQLPlugin, "sql", "sql");

Status SQLiteSQLPlugin::query(const std::string& query,
                              QueryData& results,
                              bool use_cache) const {
  auto dbc = SQLiteDBManager::get();
  dbc->useCache(use_cache);
  auto result = queryInternal(query, results, dbc);
  dbc->clearAffectedTables();
  return result;
}

Status SQLiteSQLPlugin::getQueryColumns(const std::string& query,
                                        TableColumns& columns) const {
  auto dbc = SQLiteDBManager::get();
  return getQueryColumnsInternal(query, columns, dbc);
}

Status SQLiteSQLPlugin::getQueryTables(const std::string& query,
                                       std::vector<std::string>& tables) const {
  auto dbc = SQLiteDBManager::get();
  QueryPlanner planner(query, dbc);
  tables = planner.tables();
  return Status(0);
}

Status SQLiteSQLPlugin::attach(const std::string& name) {
  PluginResponse response;
  auto status =
      Registry::call("table", name, {{"action", "columns"}}, response);
  if (!status.ok()) {
    return status;
  }

  bool is_extension = true;
  auto statement = columnDefinition(response, false, is_extension);

  // Attach requests occurring via the plugin/registry APIs must act on the
  // primary database. To allow this, getConnection can explicitly request the
  // primary instance and avoid the contention decisions.
  auto dbc = SQLiteDBManager::getConnection(true);

  // Attach as an extension, allowing read/write tables
  return attachTableInternal(name, statement, dbc, is_extension);
}

void SQLiteSQLPlugin::detach(const std::string& name) {
  auto dbc = SQLiteDBManager::get();
  if (!dbc->isPrimary()) {
    return;
  }
  detachTableInternal(name, dbc);
}
} // namespace osquery
