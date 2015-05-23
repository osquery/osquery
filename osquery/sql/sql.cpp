/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>
#include <osquery/registry.h>

namespace osquery {

FLAG(int32, value_max, 512, "Maximum returned row value size");

const std::map<ConstraintOperator, std::string> kSQLOperatorRepr = {
    {EQUALS, "="},
    {GREATER_THAN, ">"},
    {LESS_THAN_OR_EQUALS, "<="},
    {LESS_THAN, "<"},
    {GREATER_THAN_OR_EQUALS, ">="},
};

SQL::SQL(const std::string& q) { status_ = query(q, results_); }

const QueryData& SQL::rows() { return results_; }

bool SQL::ok() { return status_.ok(); }

Status SQL::getStatus() { return status_; }

std::string SQL::getMessageString() { return status_.toString(); }

const std::string SQL::kHostColumnName = "_source_host";
void SQL::annotateHostInfo() {
  std::string hostname = getHostname();
  for (Row& row : results_) {
    row[kHostColumnName] = hostname;
  }
}

std::vector<std::string> SQL::getTableNames() {
  std::vector<std::string> results;
  for (const auto& name : Registry::names("table")) {
    results.push_back(name);
  }
  return results;
}

QueryData SQL::selectAllFrom(const std::string& table) {
  PluginResponse response;
  PluginRequest request;
  request["action"] = "generate";

  Registry::call("table", table, request, response);
  return response;
}

QueryData SQL::selectAllFrom(const std::string& table,
                             const std::string& column,
                             ConstraintOperator op,
                             const std::string& expr) {
  PluginResponse response;
  PluginRequest request = {{"action", "generate"}};
  QueryContext ctx;
  ctx.constraints[column].add(Constraint(op, expr));

  TablePlugin::setRequestFromContext(ctx, request);
  Registry::call("table", table, request, response);
  return response;
}

Status SQLPlugin::call(const PluginRequest& request, PluginResponse& response) {
  response.clear();
  if (request.count("action") == 0) {
    return Status(1, "SQL plugin must include a request action");
  }

  if (request.at("action") == "query") {
    return this->query(request.at("query"), response);
  } else if (request.at("action") == "columns") {
    TableColumns columns;
    auto status = this->getQueryColumns(request.at("query"), columns);
    // Convert columns to response
    for (const auto& column : columns) {
      response.push_back({{"n", column.first}, {"t", column.second}});
    }
    return status;
  } else if (request.at("action") == "attach") {
    // Attach a virtual table name using an optional included definition.
    return this->attach(request.at("table"));
  } else if (request.at("action") == "detach") {
    this->detach(request.at("table"));
    return Status(0, "OK");
  }
  return Status(1, "Unknown action");
}

Status query(const std::string& q, QueryData& results) {
  return Registry::call(
      "sql", "sql", {{"action", "query"}, {"query", q}}, results);
}

Status getQueryColumns(const std::string& q, TableColumns& columns) {
  PluginResponse response;
  auto status = Registry::call(
      "sql", "sql", {{"action", "columns"}, {"query", q}}, response);

  // Convert response to columns
  for (const auto& item : response) {
    columns.push_back(make_pair(item.at("n"), item.at("t")));
  }
  return status;
}
}
