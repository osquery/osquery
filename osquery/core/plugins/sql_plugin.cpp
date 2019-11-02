/**
 * Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
 * @brief The osquery SQL implementation is managed as a plugin.
 *
 * The osquery RegistryFactory creates a Registry type called "sql", then
 * requires a single plugin registration also called "sql". Calls within
 * the application use boilerplate methods that wrap Registry::call%s to this
 * well-known registry and registry item name.
 *
 * Abstracting the SQL implementation behind the osquery registry allows
 * the SDK (libosquery) to describe how the SQL implementation is used without
 * having dependencies on the thrird-party code.
 *
 * When osqueryd/osqueryi are built libosquery_additional, the library which
 * provides the core plugins and core virtual tables, includes SQLite as
 * the SQL implementation.
 */

#include <osquery/core/plugins/sql_plugin.h>
#include <osquery/registry_factory.h>
#include <osquery/tables.h>

namespace osquery {

Status SQLPlugin::call(const PluginRequest& request, PluginResponse& response) {
  response.clear();
  if (request.count("action") == 0) {
    return Status(1, "SQL plugin must include a request action");
  }

  if (request.at("action") == "query") {
    bool use_cache = (request.count("cache") && request.at("cache") == "1");
    return this->query(request.at("query"), response, use_cache);
  } else if (request.at("action") == "columns") {
    TableColumns columns;
    auto status = this->getQueryColumns(request.at("query"), columns);
    // Convert columns to response
    for (const auto& column : columns) {
      response.push_back(
          {{"n", std::get<0>(column)},
           {"t", columnTypeName(std::get<1>(column))},
           {"o", INTEGER(static_cast<size_t>(std::get<2>(column)))}});
    }
    return status;
  } else if (request.at("action") == "attach") {
    // Attach a virtual table name using an optional included definition.
    return this->attach(request.at("table"));
  } else if (request.at("action") == "detach") {
    this->detach(request.at("table"));
    return Status::success();
  } else if (request.at("action") == "tables") {
    std::vector<std::string> tables;
    auto status = this->getQueryTables(request.at("query"), tables);
    if (status.ok()) {
      for (const auto& table : tables) {
        response.push_back({{"t", table}});
      }
    }
    return status;
  }
  return Status(1, "Unknown action");
}

CREATE_LAZY_REGISTRY(SQLPlugin, "sql");
} // namespace osquery
