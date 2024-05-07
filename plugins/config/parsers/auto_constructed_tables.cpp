/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string.hpp>

#include <osquery/config/config.h>
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/utils/conversions/join.h>
#include <plugins/config/parsers/auto_constructed_tables.h>

namespace rj = rapidjson;

namespace osquery {

TableRows ATCPlugin::generate(QueryContext& context) {
  TableRows result;
  std::vector<std::string> paths;
  auto s = resolveFilePattern(path_, paths);
  if (!s.ok()) {
    LOG(WARNING) << "ATC Table: Could not glob: " << path_ << " skipping";
    return result;
  }
  for (const auto& path : paths) {
    s = getSqliteJournalMode(path);
    bool preserve_locking = false;
    if (!s.ok()) {
      VLOG(1) << "ATC Table: Unable to detect journal mode, applying default "
                 "locking policy"
              << " for path " << path;
    } else {
      preserve_locking = s.getMessage() == "wal";
    }
    s = genTableRowsForSqliteTable(
        path, sqlite_query_, result, preserve_locking);
    if (!s.ok()) {
      LOG(WARNING) << "ATC Table: Error Code: " << s.getCode()
                   << " Could not generate data: " << s.getMessage()
                   << " for path " << path_;
    }
  }
  return result;
}

/// Remove these ATC tables from the registry and database
Status ATCConfigParserPlugin::removeATCTables(
    const std::set<std::string>& detach_tables) {
  auto registry_table = RegistryFactory::get().registry("table");
  std::set<std::string> failed_tables;
  for (const auto& table : detach_tables) {
    if (registry_table->exists(table)) {
      std::string value;
      if (getDatabaseValue(
              kPersistentSettings, kDatabaseKeyPrefix + table, value)
              .ok()) {
        registry_table->remove(table);
        PluginResponse resp;
        Registry::call(
            "sql", "sql", {{"action", "detatch"}, {"table", table}}, resp);
        VLOG(1) << "ATC table: " << table << " Removed";
      } else {
        failed_tables.insert(table);
      }
    }
    deleteDatabaseValue(kPersistentSettings, kDatabaseKeyPrefix + table);
  }
  if (failed_tables.empty()) {
    return Status();
  }
  return Status(
      1, "Attempted to remove non ATC tables: " + join(failed_tables, ", "));
}

/// Get all ATC tables that should be registered from the database
std::set<std::string> ATCConfigParserPlugin::registeredATCTables() {
  std::vector<std::string> tables;
  scanDatabaseKeys(kPersistentSettings, tables, kDatabaseKeyPrefix);
  std::set<std::string> set_tables;

  for (const auto& table : tables) {
    set_tables.insert(table.substr(kDatabaseKeyPrefix.size()));
  }
  return set_tables;
}

Status ATCConfigParserPlugin::setUp() {
  VLOG(1) << "Removing stale ATC entries";
  std::vector<std::string> keys;
  scanDatabaseKeys(kPersistentSettings, keys, kDatabaseKeyPrefix);
  for (const auto& key : keys) {
    auto s = deleteDatabaseValue(kPersistentSettings, key);
    if (!s.ok()) {
      LOG(INFO) << "ATC table: Could not clear ATC key " << key
                << "from database";
    }
  }
  return Status();
}

Status ATCConfigParserPlugin::update(const std::string& source,
                                     const ParserConfig& config) {
  auto cv = config.find(kParserKey);
  if (cv == config.end() || !cv->second.doc().IsObject()) {
    return Status::success();
  }

  {
    auto doc = JSON::newObject();
    auto obj = doc.getObject();
    doc.copyFrom(cv->second.doc(), obj);
    doc.add(kParserKey, obj);
    data_ = std::move(doc);
  }

  const auto& ac_tables = data_.doc()[kParserKey];
  auto tables = RegistryFactory::get().registry("table");
  auto registered = registeredATCTables();

  for (const auto& ac_table : ac_tables.GetObject()) {
    if (!ac_table.name.IsString() || !ac_table.value.IsObject()) {
      // This entry is not formatted correctly.
      continue;
    }

    std::string table_name{ac_table.name.GetString()};
    auto params = ac_table.value.GetObject();

    std::string query{params.HasMember("query") && params["query"].IsString()
                          ? params["query"].GetString()
                          : ""};
    std::string path{params.HasMember("path") && params["path"].IsString()
                         ? params["path"].GetString()
                         : ""};
    std::string platform{params.HasMember("platform") &&
                                 params["platform"].IsString()
                             ? params["platform"].GetString()
                             : ""};

    if (query.empty() || path.empty()) {
      LOG(WARNING) << "ATC Table: Skipping " << table_name
                   << " because it is misconfigured (missing query or path)";
      continue;
    }

    if (!checkPlatform(platform)) {
      VLOG(1) << "ATC table: Skipping " << table_name
              << " because platform doesn't match";
      continue;
    }

    TableColumns columns;
    std::string columns_value;
    columns_value.reserve(256);

    if (!params.HasMember("columns") || !params["columns"].IsArray()) {
      LOG(WARNING) << "ATC Table: Skipping " << table_name
                   << " because it is misconfigured (no columns)";
      continue;
    }

    std::string user_defined_path_column;

    for (const auto& column : params["columns"].GetArray()) {
      if (!column.IsString()) {
        LOG(WARNING) << "ATC Table: " << table_name
                     << " is misconfigured. (non-string column)";
        continue;
      }

      if (boost::iequals(column.GetString(), "path")) {
        user_defined_path_column = column.GetString();
      }

      columns.push_back(make_tuple(
          std::string(column.GetString()), TEXT_TYPE, ColumnOptions::DEFAULT));
      columns_value += std::string(column.GetString()) + ",";
    }

    if (!user_defined_path_column.empty()) {
      LOG(WARNING) << "ATC Table: " << table_name
                   << " is misconfigured. The configuration includes `"
                   << user_defined_path_column
                   << "`. This is a reserved column name";
    } else {
      // Add implicit path column
      columns.push_back(
          make_tuple(std::string("path"), TEXT_TYPE, ColumnOptions::DEFAULT));
      columns_value += "path,";
    }

    registered.erase(table_name);
    std::string table_settings{table_name + query + columns_value + path};
    std::string old_setting;
    auto s = getDatabaseValue(
        kPersistentSettings, kDatabaseKeyPrefix + table_name, old_setting);

    // The ATC table hasn't changed so we skip ahead
    if (table_settings == old_setting) {
      continue;
    }

    // Remove the old table to replace with the new one
    s = removeATCTables({table_name});
    if (!s.ok()) {
      LOG(WARNING) << "ATC Table: " << table_name
                   << " overrides core table; Refusing registration";
      continue;
    }

    s = setDatabaseValue(
        kPersistentSettings, kDatabaseKeyPrefix + table_name, table_settings);
    if (!s.ok()) {
      LOG(WARNING) << "ATC Table: " << table_name
                   << " could not write to database";
      continue;
    }

    s = tables->add(
        table_name, std::make_shared<ATCPlugin>(path, columns, query), true);
    if (!s.ok()) {
      LOG(WARNING) << "ATC Table: " << table_name << ": " << s.getMessage();
      deleteDatabaseValue(kPersistentSettings, kDatabaseKeyPrefix + table_name);
      continue;
    }

    PluginResponse resp;
    Registry::call(
        "sql", "sql", {{"action", "attach"}, {"table", table_name}}, resp);
    LOG(INFO) << "ATC table: " << table_name << " Registered";
  }

  if (registered.size() > 0) {
    VLOG(1)
        << "Removing any ATC tables that were removed in this configuration "
           "change";
    removeATCTables(registered);
  }
  return Status();
}

REGISTER_INTERNAL(ATCConfigParserPlugin,
                  "config_parser",
                  "auto_constructed_tables");
} // namespace osquery
