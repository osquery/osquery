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

#ifndef OSQUERY_BUILD_SDK
#include "osquery/sql/sqlite_util.h"
#endif

namespace osquery {

const std::map<tables::ConstraintOperator, std::string> kSQLOperatorRepr = {
    {tables::EQUALS, "="},
    {tables::GREATER_THAN, ">"},
    {tables::LESS_THAN_OR_EQUALS, "<="},
    {tables::LESS_THAN, "<"},
    {tables::GREATER_THAN_OR_EQUALS, ">="},
};

SQL::SQL(const std::string& q) { status_ = query(q, results_); }

QueryData SQL::rows() { return results_; }

bool SQL::ok() { return status_.ok(); }

std::string SQL::getMessageString() { return status_.toString(); }

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
                             tables::ConstraintOperator op,
                             const std::string& expr) {
  PluginResponse response;
  PluginRequest request = {{"action", "generate"}};
  tables::QueryContext ctx;
  ctx.constraints[column].add(tables::Constraint(op, expr));

  tables::TablePlugin::setRequestFromContext(ctx, request);
  Registry::call("table", table, request, response);
  return response;
}

Status query(const std::string& q, QueryData& results) {
// Depending on the build type (core or sdk/extension) osquery will call the
// internal SQL implementation or the Thrift API endpoint.
#ifndef OSQUERY_BUILD_SDK
  return queryInternal(q, results);
#else
  return Status(0, "OK");
#endif
}

Status getQueryColumns(const std::string& q, tables::TableColumns& columns) {
// Depending on the build type (core or sdk/extension) osquery will call the
// internal SQL implementation or the Thrift API endpoint.
#ifndef OSQUERY_BUILD_SDK
  return getQueryColumnsInternal(q, columns);
#else
  return Status(0, "OK");
#endif
}
}
