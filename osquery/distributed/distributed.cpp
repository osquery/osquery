/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <sstream>
#include <utility>

#include <osquery/database.h>
#include <osquery/distributed.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"

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

  auto& action = request.at("action");
  if (action == "getQueries") {
    std::string queries;
    getQueries(queries);
    response.push_back({{"results", queries}});
    return Status(0, "OK");
  } else if (action == "writeResults") {
    if (request.count("results") == 0) {
      return Status(1, "Missing results field");
    }
    return writeResults(request.at("results"));
  }

  return Status(1, "Distributed plugin action unknown: " + action);
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
  auto doc = JSON::newObject();
  auto queries_obj = doc.getObject();
  auto statuses_obj = doc.getObject();
  for (const auto& result : results_) {
    auto arr = doc.getArray();
    auto s = serializeQueryData(result.results, result.columns, doc, arr);
    if (!s.ok()) {
      return s;
    }
    doc.add(result.request.id, arr, queries_obj);
    doc.add(result.request.id, result.status.getCode(), statuses_obj);
  }

  doc.add("queries", queries_obj);
  doc.add("statuses", queries_obj);
  return doc.toString(json);
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
  auto doc = JSON::newObject();
  if (!doc.fromString(work) || !doc.doc().IsObject()) {
    return Status(1, "Error Parsing JSON");
  }

  std::set<std::string> queries_to_run;
  // Check for and run discovery queries first
  if (doc.doc().HasMember("discovery")) {
    const auto& queries = doc.doc()["discovery"];
    assert(queries.IsObject());

    if (queries.IsObject()) {
      for (const auto& query_entry : queries.GetObject()) {
        if (!query_entry.name.IsString() || !query_entry.value.IsString()) {
          return Status(1, "Distributed discovery query is not a string");
        }

        auto name = std::string(query_entry.name.GetString());
        auto query = std::string(query_entry.value.GetString());
        if (query.empty() || name.empty()) {
          return Status(1, "Distributed discovery query is not a string");
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
  }

  if (doc.doc().HasMember("queries")) {
    const auto& queries = doc.doc()["queries"];
    assert(queries.IsObject());

    if (queries.IsObject()) {
      for (const auto& query_entry : queries.GetObject()) {
        if (!query_entry.name.IsString() || !query_entry.value.IsString()) {
          return Status(1, "Distributed query is not a string");
        }

        auto name = std::string(query_entry.name.GetString());
        auto query = std::string(query_entry.value.GetString());
        if (name.empty() || query.empty()) {
          return Status(1, "Distributed query is not a string");
        }

        if (queries_to_run.empty() || queries_to_run.count(name)) {
          setDatabaseValue(kQueries, kDistributedQueryPrefix + name, query);
        }
      }
    }
  }

  if (doc.doc().HasMember("accelerate")) {
    const auto& accelerate = doc.doc()["accelerate"];
    if (accelerate.IsString()) {
      auto new_time = std::string(accelerate.GetString());
      unsigned long duration = 0;
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
  }
  return Status();
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
                                        JSON& doc,
                                        rj::Value& obj) {
  assert(obj.IsObject());
  doc.addCopy("query", r.query, obj);
  doc.addCopy("id", r.id, obj);
  return Status();
}

Status serializeDistributedQueryRequestJSON(const DistributedQueryRequest& r,
                                            std::string& json) {
  auto doc = JSON::newObject();
  auto s = serializeDistributedQueryRequest(r, doc, doc.doc());
  if (!s.ok()) {
    return s;
  }

  return doc.toString(json);
}

Status deserializeDistributedQueryRequest(const rj::Value& obj,
                                          DistributedQueryRequest& r) {
  if (!obj.HasMember("query") || !obj.HasMember("id") ||
      !obj["query"].IsString() || !obj["id"].IsString()) {
    return Status(1, "Malformed distributed query request");
  }

  r.query = obj["query"].GetString();
  r.id = obj["id"].GetString();
  return Status();
}

Status deserializeDistributedQueryRequestJSON(const std::string& json,
                                              DistributedQueryRequest& r) {
  auto doc = JSON::newObject();
  if (!doc.fromString(json) || !doc.doc().IsObject()) {
    return Status(1, "Error Parsing JSON");
  }
  return deserializeDistributedQueryRequest(doc.doc(), r);
}

Status serializeDistributedQueryResult(const DistributedQueryResult& r,
                                       JSON& doc,
                                       rj::Value& obj) {
  auto request_obj = doc.getObject();
  auto s = serializeDistributedQueryRequest(r.request, doc, request_obj);
  if (!s.ok()) {
    return s;
  }

  auto results_arr = doc.getArray();
  s = serializeQueryData(r.results, r.columns, doc, results_arr);
  if (!s.ok()) {
    return s;
  }

  doc.add("request", request_obj);
  doc.add("results", results_arr);
  return Status();
}

Status serializeDistributedQueryResultJSON(const DistributedQueryResult& r,
                                           std::string& json) {
  auto doc = JSON::newObject();
  auto s = serializeDistributedQueryResult(r, doc, doc.doc());
  if (!s.ok()) {
    return s;
  }

  return doc.toString(json);
}

Status deserializeDistributedQueryResult(const rj::Value& obj,
                                         DistributedQueryResult& r) {
  DistributedQueryRequest request;
  auto s = deserializeDistributedQueryRequest(obj["request"], request);
  if (!s.ok()) {
    return s;
  }

  QueryData results;
  s = deserializeQueryData(obj["results"], results);
  if (!s.ok()) {
    return s;
  }

  r.request = request;
  r.results = results;

  return Status();
}

Status deserializeDistributedQueryResultJSON(const std::string& json,
                                             DistributedQueryResult& r) {
  auto doc = JSON::newObject();
  if (!doc.fromString(json) || !doc.doc().IsObject()) {
    return Status(1, "Error Parsing JSON");
  }
  return deserializeDistributedQueryResult(doc.doc(), r);
}
}
