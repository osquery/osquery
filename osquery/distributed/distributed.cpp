/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>
#include <utility>

#include <osquery/core.h>
#include <osquery/distributed.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"

namespace pt = boost::property_tree;
namespace rj = rapidjson;

namespace osquery {

CREATE_REGISTRY(DistributedPlugin, "distributed");

FLAG(string, distributed_plugin, "tls", "Distributed plugin name");

FLAG(bool,
     disable_distributed,
     true,
     "Disable distributed queries (default true)");

const std::string kDistributedQueryPrefix{"distributed."};

Status DistributedPlugin::call(const PluginRequest& request,
                               PluginResponse& response) {
  if (request.count("action") == 0) {
    return Status(1, "Distributed plugins require an action in PluginRequest");
  }

  if (request.at("action") == "getQueries") {
    std::string queries;
    getQueries(queries);
    response.push_back({{"results", queries}});
    return Status(0, "OK");
  } else if (request.at("action") == "writeResults") {
    if (request.count("results") == 0) {
      return Status(1, "Missing results field");
    }
    return writeResults(request.at("results"));
  }

  return Status(1,
                "Distributed plugin action unknown: " + request.at("action"));
}

Status Distributed::pullUpdates() {
  auto distributed_plugin = RegistryFactory::get().getActive("distributed");
  if (!RegistryFactory::get().exists("distributed", distributed_plugin)) {
    return Status(1, "Missing distributed plugin: " + distributed_plugin);
  }

  PluginResponse response;
  auto status =
      Registry::call("distributed", {{"action", "getQueries"}}, response);
  if (!status.ok()) {
    return status;
  }

  if (response.size() > 0 && response[0].count("results") > 0) {
    return acceptWork(response[0]["results"]);
  }

  return Status(0, "OK");
}

size_t Distributed::getPendingQueryCount() {
  std::vector<std::string> queries;
  scanDatabaseKeys(kQueries, queries, kDistributedQueryPrefix);
  return queries.size();
}

size_t Distributed::getCompletedCount() {
  return results_.size();
}

Status Distributed::serializeResults(std::string& json) {
  pt::ptree queries;
  pt::ptree statuses;
  for (const auto& result : results_) {
    pt::ptree qd;
    auto s = serializeQueryData(result.results, result.columns, qd);
    if (!s.ok()) {
      return s;
    }

    queries.add_child(result.request.id, qd);
    statuses.put(result.request.id, result.status.getCode());
  }

  pt::ptree results;
  results.add_child("queries", queries);
  results.add_child("statuses", statuses);

  std::stringstream ss;
  try {
    pt::write_json(ss, results, false);
  } catch (const pt::ptree_error& e) {
    return Status(1, "Error writing JSON: " + std::string(e.what()));
  }
  json = ss.str();

  return Status(0, "OK");
}

void Distributed::addResult(const DistributedQueryResult& result) {
  results_.push_back(result);
}

Status Distributed::runQueries() {
  while (getPendingQueryCount() > 0) {
    auto request = popRequest();
    LOG(INFO) << "Executing distributed query: " << request.id << ": "
              << request.query;

    SQL sql(request.query);
    if (!sql.getStatus().ok()) {
      LOG(ERROR) << "Error executing distributed query: " << request.id << ": "
                 << sql.getMessageString();
    }

    DistributedQueryResult result(
        request, sql.rows(), sql.columns(), sql.getStatus());
    addResult(result);
  }
  return flushCompleted();
}

Status Distributed::flushCompleted() {
  if (getCompletedCount() == 0) {
    return Status(0, "OK");
  }

  auto distributed_plugin = RegistryFactory::get().getActive("distributed");
  if (!RegistryFactory::get().exists("distributed", distributed_plugin)) {
    return Status(1, "Missing distributed plugin " + distributed_plugin);
  }

  std::string results;
  auto s = serializeResults(results);
  if (!s.ok()) {
    return s;
  }

  PluginResponse response;
  s = Registry::call("distributed",
                     {{"action", "writeResults"}, {"results", results}},
                     response);
  if (s.ok()) {
    results_.clear();
  }
  return s;
}

Status Distributed::acceptWork(const std::string& work) {
  rj::Document d;
  rj::ParseResult pr = d.Parse(rj::StringRef(work.c_str()));
  if (!pr) {
    return Status(1, "Error Parsing JSON: " +
      std::string(GetParseError_En(pr.Code()), pr.Offset()));
  }
  std::set<std::string> queries_to_run;
  // Check for and run discovery queries first
  if (d.HasMember("discovery")) {
    const rj::Value& queries = d["discovery"];
    for (const auto& query_entry : queries.GetObject()) {
      auto name = std::string(query_entry.name.GetString());
      auto query = std::string(query_entry.value.GetString());

      if (query.empty() || name.empty()) {
        return Status(
            1,
            "Distributed discovery query does not have complete attributes");
      }
      SQL sql(query);
      if (!sql.getStatus().ok()) {
        return Status(1, "Distributed discovery query has an SQL error");
      }
      if (sql.rows().size() > 0) {
        queries_to_run.insert(name);
      }
    }
  }
  if (d.HasMember("queries")) {
    const rj::Value& queries = d["queries"];
    for (const auto& query_entry : queries.GetObject()) {
      auto name = std::string(query_entry.name.GetString());
      auto query = std::string(query_entry.value.GetString());
      if (name.empty() || query.empty()) {
        return Status(1, "Distributed query does not have complete attributes");
      }
      if (queries_to_run.empty() || queries_to_run.count(name)) {
        setDatabaseValue(
          kQueries,
          kDistributedQueryPrefix + name,
          query);
      }
    }
  }

  if (d.HasMember("accelerate")) {
    auto new_time = std::string(d["accelerate"].GetString());
    unsigned long duration;
    Status conversion = safeStrtoul(new_time, 10, duration);
    if (conversion.ok()) {
      LOG(INFO) << "Accelerating distributed query checkins for " << duration
                << " seconds";
      setDatabaseValue(kPersistentSettings,
                       "distributed_accelerate_checkins_expire",
                       std::to_string(getUnixTime() + duration));
    } else {
      LOG(WARNING) << "Failed to Accelerate: Timeframe is not an integer";
    }
  }
  return Status(0, "OK");
}

DistributedQueryRequest Distributed::popRequest() {
  // Read all pending queries.
  std::vector<std::string> queries;
  scanDatabaseKeys(kQueries, queries, kDistributedQueryPrefix);

  // Set the last-most-recent query as the request, and delete it.
  DistributedQueryRequest request;
  const auto& next = queries.front();
  request.id = next.substr(kDistributedQueryPrefix.size());
  getDatabaseValue(kQueries, next, request.query);
  deleteDatabaseValue(kQueries, next);
  return request;
}

Status serializeDistributedQueryRequest(const DistributedQueryRequest& r,
                                        pt::ptree& tree) {
  tree.put("query", r.query);
  tree.put("id", r.id);
  return Status(0, "OK");
}

Status serializeDistributedQueryRequestRJ(const DistributedQueryRequest& r,
                                        rj::Document& d) {
  d.AddMember(
    rapidjson::Value("query", d.GetAllocator()).Move(),
    rapidjson::Value(r.query.c_str(), d.GetAllocator()).Move(),
    d.GetAllocator());

  d.AddMember(
    rapidjson::Value("id", d.GetAllocator()).Move(),
    rapidjson::Value(r.id.c_str(), d.GetAllocator()).Move(),
    d.GetAllocator());

  return Status(0, "OK");
}

Status serializeDistributedQueryRequestJSON(const DistributedQueryRequest& r,
                                            std::string& json) {
  pt::ptree tree;
  auto s = serializeDistributedQueryRequest(r, tree);
  if (!s.ok()) {
    return s;
  }

  std::stringstream ss;
  try {
    pt::write_json(ss, tree, false);
  } catch (const pt::ptree_error& e) {
    return Status(1, "Error serializing JSON: " + std::string(e.what()));
  }
  json = ss.str();

  return Status(0, "OK");
}

Status deserializeDistributedQueryRequest(const pt::ptree& tree,
                                          DistributedQueryRequest& r) {
  r.query = tree.get<std::string>("query", "");
  r.id = tree.get<std::string>("id", "");
  return Status(0, "OK");
}

Status deserializeDistributedQueryRequestJSON(const std::string& json,
                                              DistributedQueryRequest& r) {
  std::stringstream ss(json);
  pt::ptree tree;
  try {
    pt::read_json(ss, tree);
  } catch (const pt::ptree_error& e) {
    return Status(1, "Error serializing JSON: " + std::string(e.what()));
  }
  return deserializeDistributedQueryRequest(tree, r);
}

Status serializeDistributedQueryResult(const DistributedQueryResult& r,
                                       pt::ptree& tree) {
  pt::ptree request;
  auto s = serializeDistributedQueryRequest(r.request, request);
  if (!s.ok()) {
    return s;
  }

  pt::ptree results;
  s = serializeQueryData(r.results, r.columns, results);
  if (!s.ok()) {
    return s;
  }

  tree.add_child("request", request);
  tree.add_child("results", results);

  return Status(0, "OK");
}

Status serializeDistributedQueryResultRJ(const DistributedQueryResult& r,
                                       rj::Document& d) {
  rj::Document request;
  request.SetObject();
  auto s = serializeDistributedQueryRequestRJ(r.request, request);
  if (!s.ok()) {
    return s;
  }

  rj::Document results;
  results.SetArray();
  s = serializeQueryDataRJ(r.results, r.columns, results);
  if (!s.ok()) {
    return s;
  }

  d.AddMember("request", rapidjson::Value(request, d.GetAllocator()).Move(), d.GetAllocator());
  d.AddMember("results", rapidjson::Value(results, d.GetAllocator()).Move(), d.GetAllocator());
  return Status(0, "OK");
}

Status serializeDistributedQueryResultJSON(const DistributedQueryResult& r,
                                           std::string& json) {
  pt::ptree tree;
  auto s = serializeDistributedQueryResult(r, tree);
  if (!s.ok()) {
    return s;
  }

  std::stringstream ss;
  try {
    pt::write_json(ss, tree, false);
  } catch (const pt::ptree_error& e) {
    return Status(1, "Error serializing JSON: " + std::string(e.what()));
  }
  json = ss.str();

  return Status(0, "OK");
}

Status deserializeDistributedQueryResult(const pt::ptree& tree,
                                         DistributedQueryResult& r) {
  DistributedQueryRequest request;
  auto s =
      deserializeDistributedQueryRequest(tree.get_child("request"), request);
  if (!s.ok()) {
    return s;
  }

  QueryData results;
  s = deserializeQueryData(tree.get_child("results"), results);
  if (!s.ok()) {
    return s;
  }

  r.request = request;
  r.results = results;

  return Status(0, "OK");
}

Status deserializeDistributedQueryResultJSON(const std::string& json,
                                             DistributedQueryResult& r) {
  pt::ptree tree;
  try {
    std::stringstream ss(json);
    pt::read_json(ss, tree);
  } catch (const pt::ptree_error& e) {
    return Status(1, "Error serializing JSON: " + std::string(e.what()));
  }
  return deserializeDistributedQueryResult(tree, r);
}
}
