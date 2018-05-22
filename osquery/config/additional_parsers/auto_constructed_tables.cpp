/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/config.h>
#include <osquery/database.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/config/additional_parsers/auto_constructed_tables.h"
#include "osquery/core/conversions.h"
#include "osquery/sql/sqlite_util.h"

namespace rj = rapidjson;

namespace osquery {

QueryData ATCPlugin::generate(QueryContext& context) {
  QueryData qd;
  std::vector<std::string> paths;
  auto s = resolveFilePattern(path_, paths);
  if (!s.ok()) {
    LOG(WARNING) << "Could not glob: " << path_;
  }
  for (const auto& path : paths) {
    s = genQueryDataForSqliteTable(path, sqlite_query_, qd);
    if (!s.ok()) {
      LOG(WARNING) << "Error Code: " << s.getCode()
                   << " Could not generate data: " << s.getMessage();
    }
  }
  return qd;
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
        LOG(INFO) << "Removed ATC table: " << table;
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
      LOG(INFO) << "Could not clear ATC key " << key << "from database";
    }
  }
  return Status();
}

Status ATCConfigParserPlugin::update(const std::string& source,
                                     const ParserConfig& config) {
  auto cv = config.find(kParserKey);
  if (cv == config.end()) {
    return Status(1, "No configuration for ATC (Auto Table Construction)");
  }
  auto obj = data_.getObject();

  data_.copyFrom(cv->second.doc(), obj);
  data_.add(kParserKey, obj);

  const auto& ac_tables = data_.doc()[kParserKey];
  auto tables = RegistryFactory::get().registry("table");
  auto registered = registeredATCTables();

  for (const auto& ac_table : ac_tables.GetObject()) {
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
      LOG(WARNING) << "ATC Table: " << table_name << " is misconfigured";
      continue;
    }

    if (!checkPlatform(platform)) {
      VLOG(1) << "Skipping ATC table: " << table_name
              << " because platform doesn't match";
      continue;
    }

    TableColumns columns;
    std::string columns_value;
    columns_value.reserve(256);

    for (const auto& column : params["columns"].GetArray()) {
      columns.push_back(make_tuple(
          std::string(column.GetString()), TEXT_TYPE, ColumnOptions::DEFAULT));
      columns_value += std::string(column.GetString()) + ",";
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
      LOG(WARNING) << "ATC table overrides core table; Refusing registration";
      continue;
    }

    s = setDatabaseValue(
        kPersistentSettings, kDatabaseKeyPrefix + table_name, table_settings);

    if (!s.ok()) {
      LOG(WARNING) << "Could not write to database";
      continue;
    }

    s = tables->add(
        table_name, std::make_shared<ATCPlugin>(path, columns, query), true);

    if (!s.ok()) {
      LOG(WARNING) << s.getMessage();
      deleteDatabaseValue(kPersistentSettings, kDatabaseKeyPrefix + table_name);
      continue;
    }

    PluginResponse resp;
    Registry::call(
        "sql", "sql", {{"action", "attach"}, {"table", table_name}}, resp);
    LOG(INFO) << "Registered ATC table: " << table_name;
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
