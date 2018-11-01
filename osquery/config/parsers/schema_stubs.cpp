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
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/sql.h>

#include <osquery/core/conversions.h>

#include "schema_stubs.h"

//   "package_receipts|packages":[
//     "package_id/Ti","package_filename/Tih","version","location",
//     "install_time/D","installer_name","path/a"
//   ],

namespace osquery {

class EmptyTablePlugin : public TablePlugin {
 public:
  EmptyTablePlugin(std::string name,
                   TableColumns columnDefs,
                   std::vector<std::string> aliases)
      : TablePlugin(), name_(name), cols_(columnDefs), aliases_(aliases) {}

 private:
  TableColumns columns() const override {
    return cols_;
  }

  QueryData generate(QueryContext& request) override {
    return QueryData();
  }

  std::vector<std::string> aliases() const override {
    return aliases_;
  }

  std::string name_;
  TableColumns cols_;
  std::vector<std::string> aliases_;
};

/**
 * @brief A simple ConfigParserPlugin for an "schema_stubs" dictionary key.
 * A typical osquery agent deployment may have older agents that have not
 * yet been updated.  Running a query for a recently defined virtual table
 * across your entire fleet will result in 'no such table' errors on older
 * agents.  Adding some 'schema_stubs' definitions in the config for all
 * agents (e.g. using tls_config) will allow these queries to return empty
 * results, rather than errors.
 *
 * Example format of config:
 *
 * "schema_stubs": {
 *   "some_table_name|optional_table_alias":[
 *     "package_id/Ti","package_filename/Tih","version","location",
 *     "install_time/D","installer_name","path/a"
 *   ],
 *   "table_created_after_compile":[ "col1", "int_col1/I"]
 * }
 *
 * By default, columns are TEXT_TYPE.  Column names can be appended with a
 * slash '/' followed by type and option characters defined here:
 *
 * T  TEXT_TYPE
 * I  INTEGER_TYPE
 * D  DOUBLE_TYPE
 *
 * i  INDEX
 * h  HIDDEN
 * r  REQUIRED
 * a  ADDITIONAL
 *
 * Generate using tools/codegen/genschemastub.py <path to .spec file>
 */
class SchemaStubsConfigParserPlugin : public ConfigParserPlugin {
 public:
  virtual ~SchemaStubsConfigParserPlugin() = default;

  std::vector<std::string> keys() const override {
    return {"schema_stubs"};
  }

  Status setUp() override;

  Status update(const std::string& source, const ParserConfig& config) override;

  void updateTypeAndOptions(std::string str,
                            ColumnType& columnType,
                            ColumnOptions& opts);

 private:
};

Status SchemaStubsConfigParserPlugin::setUp() {
  auto paths_obj = data_.getObject();
  data_.add("schema_stubs", paths_obj);

  return Status();
}

void SchemaStubsParseTypeAndOptions(std::string str,
                                    ColumnType& columnType,
                                    ColumnOptions& opts) {
  for (auto c : str) {
    switch (c) {
    case 'T':
      columnType = TEXT_TYPE;
      break;
    case 'D':
      columnType = DOUBLE_TYPE;
      break;
    case 'I':
      columnType = INTEGER_TYPE;
      break;
    case 'L':
      columnType = BIGINT_TYPE;
      break;
    case 'U':
      columnType = UNSIGNED_BIGINT_TYPE;
      break;
    case 'B':
      columnType = BLOB_TYPE;
      break;
    case 'i':
      opts = (ColumnOptions)((int)opts | (int)ColumnOptions::INDEX);
      break;
    case 'a':
      opts = (ColumnOptions)((int)opts | (int)ColumnOptions::ADDITIONAL);
      break;
    case 'h':
      opts = (ColumnOptions)((int)opts | (int)ColumnOptions::HIDDEN);
      break;
    case 'r':
      opts = (ColumnOptions)((int)opts | (int)ColumnOptions::REQUIRED);
      break;
    case 'o':
      opts = (ColumnOptions)((int)opts | (int)ColumnOptions::OPTIMIZED);
      break;
    default:
      LOG(WARNING) << "invalid column type or option:" << c;
    }
  }
}
std::string SchemaStubsParseTableName(std::string str,
                                      std::vector<std::string>& aliases) {
  auto tableNameAndAliases = split(str, SCHEMA_STUBS_ALIAS_DELIMITER);
  std::string tableName = tableNameAndAliases[0];

  for (size_t i = 1; i < tableNameAndAliases.size(); i++) {
    // basic sanity check on alias
    if (tableNameAndAliases[i].size() == 0 ||
        tableNameAndAliases[i] == tableName) {
      continue;
    }
    aliases.push_back(tableNameAndAliases[i]);
  }
  return tableName;
}

std::string SchemaStubsParseColumnName(std::string str,
                                       ColumnType& columnType,
                                       ColumnOptions& opts) {
  auto parts = split(str, SCHEMA_STUBS_COLUMN_DETAIL_DELIMITER);

  std::string columnName = parts[0];
  columnType = TEXT_TYPE;
  opts = ColumnOptions::DEFAULT;

  if (parts.size() > 1) {
    SchemaStubsParseTypeAndOptions(parts[1], columnType, opts);
  }

  return columnName;
}

Status SchemaStubsConfigParserPlugin::update(const std::string& source,
                                             const ParserConfig& config) {
  if (config.count("schema_stubs") == 0) {
    return Status();
  }

  auto tables = RegistryFactory::get().registry("table");

  if (config.count("schema_stubs") > 0) {
    // We know this top-level is an Object.
    const auto& stubs_defs = config.at("schema_stubs").doc();
    if (stubs_defs.IsObject()) {
      for (const auto& tableNode : stubs_defs.GetObject()) {
        if (tableNode.value.IsArray()) {
          TableColumns columns;

          std::vector<std::string> tableAliases;
          auto tableName = SchemaStubsParseTableName(tableNode.name.GetString(),
                                                     tableAliases);

          if (tableName.size() == 0 || tables->exists(tableName)) {
            continue;
          }

          for (const auto& columnStrNode : tableNode.value.GetArray()) {
            std::string columnStr = columnStrNode.GetString();
            if (columnStr.empty()) {
              continue;
            }

            ColumnType columnType;
            ColumnOptions opts;
            std::string columnName =
                SchemaStubsParseColumnName(columnStr, columnType, opts);

            columns.push_back(make_tuple(columnName, columnType, opts));
          }

          Status s = tables->add(tableName,
                                 std::make_shared<EmptyTablePlugin>(
                                     tableName, columns, tableAliases),
                                 true);

          if (!s.ok()) {
            LOG(WARNING) << s.getMessage();
            continue;
          }

          PluginResponse resp;
          Registry::call(
              "sql", "sql", {{"action", "attach"}, {"table", tableName}}, resp);
          LOG(INFO) << "Registered SchemaStub table: " << tableName;
        }
      }
    }
  }

  return Status();
}

REGISTER_INTERNAL(SchemaStubsConfigParserPlugin,
                  "config_parser",
                  "schema_stubs");

} // namespace osquery
