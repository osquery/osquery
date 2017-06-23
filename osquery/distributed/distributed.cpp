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

#undef GetObject

namespace rj = rapidjson;

namespace osquery {

CREATE_REGISTRY(DistributedPlugin, "distributed");

FLAG(string, distributed_plugin, "tls", "Distributed plugin name");

FLAG(bool,
     disable_distributed,
     true,
     "Disable distributed queries (default true)");

const std::string kDistributedQueryPrefix{"distributed."};

std::string Distributed::currentRequestId_{""};

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
  rj::Document results;
  results.SetObject();
  rj::Value queries(rj::kObjectType);
  rj::Value statuses(rj::kObjectType);
  for (const auto& result : results_) {
    rj::Document qd;
    qd.SetArray();
    auto s = serializeQueryDataRJ(result.results, result.columns, qd);
    if (!s.ok()) {
      return s;
    }
    // This is a deep copy of qd which is not ideal, if we can make this a
    // move, that would be best
    queries.AddMember(
        rj::Value(result.request.id.c_str(), results.GetAllocator()).Move(),
        rj::Value(qd, results.GetAllocator()),
        results.GetAllocator());
    statuses.AddMember(
        rj::Value(result.request.id.c_str(), results.GetAllocator()).Move(),
        rj::Value(result.status.getCode()).Move(),
        results.GetAllocator());
  }

  results.AddMember("queries", queries, results.GetAllocator());
  results.AddMember("statuses", statuses, results.GetAllocator());

  rj::StringBuffer sb;
  rj::Writer<rj::StringBuffer> writer(sb);
  results.Accept(writer);
  json = sb.GetString();
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

    // Keep track of the currently executing request
    Distributed::setCurrentRequestId(request.id);

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
    return Status(1,
                  "Error Parsing JSON: " +
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
            1, "Distributed discovery query does not have complete attributes");
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
        setDatabaseValue(kQueries, kDistributedQueryPrefix + name, query);
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

std::string Distributed::getCurrentRequestId() {
  return currentRequestId_;
}

void Distributed::setCurrentRequestId(const std::string& cReqId) {
  currentRequestId_ = cReqId;
}

Status serializeDistributedQueryRequest(const DistributedQueryRequest& r,
                                        rj::Document& d) {
  d.AddMember(rj::Value("query", d.GetAllocator()).Move(),
              rj::Value(r.query.c_str(), d.GetAllocator()),
              d.GetAllocator());

  d.AddMember(rj::Value("id", d.GetAllocator()).Move(),
              rj::Value(r.id.c_str(), d.GetAllocator()),
              d.GetAllocator());

  return Status(0, "OK");
}

Status serializeDistributedQueryRequestJSON(const DistributedQueryRequest& r,
                                            std::string& json) {
  rj::Document d;
  auto s = serializeDistributedQueryRequest(r, d);
  if (!s.ok()) {
    return s;
  }

  rj::StringBuffer sb;
  rj::Writer<rj::StringBuffer> writer(sb);
  d.Accept(writer);
  json = sb.GetString();

  return Status(0, "OK");
}

Status deserializeDistributedQueryRequest(const rj::Value& d,
                                          DistributedQueryRequest& r) {
  if (!(d.HasMember("query") && d.HasMember("id") && d["query"].IsString() &&
        d["id"].IsString())) {
    return Status(1, "Malformed distributed query request");
  }
  r.query = std::string(d["query"].GetString());
  r.id = std::string(d["id"].GetString());
  return Status(0, "OK");
}

Status deserializeDistributedQueryRequestJSON(const std::string& json,
                                              DistributedQueryRequest& r) {
  rj::Document d;
  if (d.Parse(json.c_str()).HasParseError()) {
    return Status(1, "Error serializing JSON");
  }
  return deserializeDistributedQueryRequest(d, r);
}

Status serializeDistributedQueryResult(const DistributedQueryResult& r,
                                       rj::Document& d) {
  rj::Document request;
  request.SetObject();
  auto s = serializeDistributedQueryRequest(r.request, request);
  if (!s.ok()) {
    return s;
  }

  rj::Document results;
  results.SetArray();
  s = serializeQueryDataRJ(r.results, r.columns, results);
  if (!s.ok()) {
    return s;
  }

  d.AddMember(
      "request", rj::Value(request, d.GetAllocator()).Move(), d.GetAllocator());
  d.AddMember(
      "results", rj::Value(results, d.GetAllocator()).Move(), d.GetAllocator());
  return Status(0, "OK");
}

Status serializeDistributedQueryResultJSON(const DistributedQueryResult& r,
                                           std::string& json) {
  rj::Document d;
  auto s = serializeDistributedQueryResult(r, d);
  if (!s.ok()) {
    return s;
  }

  rj::StringBuffer sb;
  rj::Writer<rj::StringBuffer> writer(sb);
  d.Accept(writer);
  json = sb.GetString();

  return Status(0, "OK");
}

Status deserializeDistributedQueryResult(const rj::Document& d,
                                         DistributedQueryResult& r) {
  DistributedQueryRequest request;
  auto s = deserializeDistributedQueryRequest(d["request"], request);
  if (!s.ok()) {
    return s;
  }

  QueryData results;
  s = deserializeQueryDataRJ(d["results"], results);
  if (!s.ok()) {
    return s;
  }

  r.request = request;
  r.results = results;

  return Status(0, "OK");
}

Status deserializeDistributedQueryResultJSON(const std::string& json,
                                             DistributedQueryResult& r) {
  rj::Document d;
  if (d.Parse(json.c_str()).HasParseError()) {
    return Status(1, "Error serializing JSON");
  }
  return deserializeDistributedQueryResult(d, r);
}
}
