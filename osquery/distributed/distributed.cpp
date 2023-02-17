/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sstream>
#include <utility>

#include <osquery/core/flags.h>
#include <osquery/core/plugins/logger.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/distributed/distributed.h>
#include <osquery/hashing/hashing.h>
#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/system/time.h>
#include <osquery/worker/system/memory.h>

namespace rj = rapidjson;

namespace osquery {

CREATE_REGISTRY(DistributedPlugin, "distributed");

FLAG(string, distributed_plugin, "tls", "Distributed plugin name");

FLAG(bool,
     disable_distributed,
     true,
     "Disable distributed queries (default true)");

FLAG(bool,
     distributed_loginfo,
     false,
     "Log the running distributed queries name at INFO level");

FLAG(uint64,
     distributed_denylist_duration,
     86400,
     "Seconds to denylist distributed queries (default 1 day)");

DECLARE_bool(verbose);

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
    return Status::success();
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

  return Status::success();
}

std::vector<std::string> Distributed::getPendingQueries() {
  std::vector<std::string> queries;
  scanDatabaseKeys(kDistributedQueries, queries);
  return queries;
}

size_t Distributed::getCompletedCount() {
  return results_.size();
}

Status Distributed::serializeResults(std::string& json) {
  auto doc = JSON::newObject();
  auto queries_obj = doc.getObject();
  auto statuses_obj = doc.getObject();
  auto messages_obj = doc.getObject();
  auto stats_obj = doc.getObject();
  for (const auto& result : results_) {
    auto arr = doc.getArray();
    auto s = serializeQueryData(result.results, result.columns, doc, arr);
    if (!s.ok()) {
      return s;
    }
    doc.add(result.request.id, arr, queries_obj);
    doc.add(result.request.id, result.status.getCode(), statuses_obj);
    doc.add(result.request.id, result.message, messages_obj);

    auto obj = doc.getObject();
    if (performance_.count(result.request.id) > 0) {
      auto perf = performance_[result.request.id];
      obj.AddMember("wall_time_ms",
                    static_cast<uint64_t>(perf.wall_time_ms),
                    obj.GetAllocator());
      obj.AddMember("user_time",
                    static_cast<uint64_t>(perf.user_time),
                    obj.GetAllocator());
      obj.AddMember("system_time",
                    static_cast<uint64_t>(perf.system_time),
                    obj.GetAllocator());
      obj.AddMember("memory",
                    static_cast<uint64_t>(perf.last_memory),
                    obj.GetAllocator());
    };

    doc.add(result.request.id, obj, stats_obj);
  }

  doc.add("queries", queries_obj);
  doc.add("statuses", statuses_obj);
  doc.add("messages", messages_obj);
  doc.add("stats", stats_obj);
  return doc.toString(json);
}

void Distributed::addResult(const DistributedQueryResult& result) {
  results_.push_back(result);
}

Status Distributed::runQueries() {
  auto queries = getPendingQueries();

  for (const auto& query : queries) {
    auto request = popRequest(query);

    const auto denylisted = checkAndSetAsRunning(request.query);
    if (denylisted) {
      VLOG(1) << "Not executing distributed denylisted query: \""
              << request.query << "\"";
      DistributedQueryResult result;
      result.request = request;
      result.status = Status(1, "Denylisted");
      result.message = "distributed query is denylisted";
      addResult(result);
      continue;
    }

    if (FLAGS_verbose) {
      VLOG(1) << "Executing distributed query: " << request.id << ": "
              << request.query;
    } else if (FLAGS_distributed_loginfo) {
      LOG(INFO) << "Executing distributed query: " << request.id << ": "
                << request.query;
    }

    // Keep track of the currently executing request
    Distributed::setCurrentRequestId(request.id);

    auto sql = monitorNonnumeric(request.id, request.query);
    const auto ok = sql.getStatus().ok();
    const auto& msg = ok ? "" : sql.getMessageString();
    if (!ok) {
      LOG(ERROR) << "Error executing distributed query: " << request.id << ": "
                 << msg;
    }

    setAsNotRunning(request.query);

    DistributedQueryResult result(
        request, sql.rows(), sql.columns(), sql.getStatus(), msg);
    addResult(result);
  }
  return flushCompleted();
}

bool Distributed::checkAndSetAsRunning(const std::string& query) {
  std::string ts;
  const auto queryKey = hashQuery(query);
  auto status = getDatabaseValue(kDistributedRunningQueries, queryKey, ts);
  if (status.ok()) {
    return !denylistedQueryTimestampExpired(ts);
  }
  status = setDatabaseValue(
      kDistributedRunningQueries, queryKey, std::to_string(getUnixTime()));
  if (!status.ok()) {
    LOG(ERROR) << "Failed to set distributed query as running: \"" << query
               << "\" (hash: " << queryKey << ")";
  }
  return false;
}

void Distributed::setAsNotRunning(const std::string& query) {
  const auto queryKey = hashQuery(query);
  return setKeyAsNotRunning(queryKey);
}

void Distributed::setKeyAsNotRunning(const std::string& queryKey) {
  const auto status = deleteDatabaseValue(kDistributedRunningQueries, queryKey);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to delete running distributed query with hash: "
               << queryKey << ", status: " << status.getMessage();
  }
}

Status Distributed::cleanupExpiredRunningQueries() {
  std::vector<std::string> queryKeys;
  const auto status = scanDatabaseKeys(kDistributedRunningQueries, queryKeys);

  if (queryKeys.size() > 0) {
    VLOG(1) << "Found " << queryKeys.size()
            << " distributed queries marked as denylisted";
  }

  for (const auto& queryKey : queryKeys) {
    std::string ts;
    const auto status =
        getDatabaseValue(kDistributedRunningQueries, queryKey, ts);
    if (!status.ok()) {
      LOG(ERROR) << "Failed to remove expired running distributed query: "
                 << queryKey;
      continue;
    }
    if (denylistedQueryTimestampExpired(ts)) {
      VLOG(1) << "Removing expired running distributed query: " << queryKey;
      setKeyAsNotRunning(queryKey);
    }
  }
  return Status::success();
}

Status Distributed::flushCompleted() {
  if (getCompletedCount() == 0) {
    return Status::success();
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
    performance_.clear();
  }

#ifdef OSQUERY_LINUX
  // Attempt to release some unused memory kept by malloc internal caching
  releaseRetainedMemory();
#endif

  return s;
}

Status Distributed::acceptWork(const std::string& work) {
  auto doc = JSON::newObject();
  if (!doc.fromString(work) || !doc.doc().IsObject()) {
    return Status(1, "Error Parsing JSON");
  }

  // Check for and run discovery queries first.
  // Store their result in discovery_results.
  std::map<std::string, bool> discovery_results;
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
        discovery_results.insert({name, (sql.rows().size() > 0)});
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

        // If a query does not have a corresponding discovery query
        // or it does and it returned results, then store the query
        // for execution.
        const auto result = discovery_results.find(name);
        if (result == discovery_results.cend() || result->second) {
          setDatabaseValue(kDistributedQueries, name, query);
        }
      }
    }
  }
  if (doc.doc().HasMember("accelerate")) {
    const auto& accelerate = doc.doc()["accelerate"];
    if (accelerate.IsInt()) {
      auto duration = accelerate.GetInt();
      LOG(INFO) << "Accelerating distributed query checkins for " << duration
                << " seconds";
      setDatabaseValue(kPersistentSettings,
                       "distributed_accelerate_checkins_expire",
                       std::to_string(getUnixTime() + duration));
    } else {
      VLOG(1) << "Failed to Accelerate: Timeframe is not an integer";
    }
  }
  return Status::success();
}

DistributedQueryRequest Distributed::popRequest(std::string query) {
  // Prepare a request from the query and then remove it from the database.
  DistributedQueryRequest request{};
  request.id = query;
  getDatabaseValue(kDistributedQueries, query, request.query);
  deleteDatabaseValue(kDistributedQueries, query);
  return request;
}

std::string Distributed::getCurrentRequestId() {
  return currentRequestId_;
}

void Distributed::setCurrentRequestId(const std::string& cReqId) {
  currentRequestId_ = cReqId;
}

SQL Distributed::monitorNonnumeric(const std::string& name,
                                   const std::string& query) {
  // Snapshot the performance and times for the worker before running.
  auto pid = std::to_string(PlatformProcess::getCurrentPid());
  auto r0 = SQL::selectFrom({"resident_size", "user_time", "system_time"},
                            "processes",
                            "pid",
                            EQUALS,
                            pid);

  using namespace std::chrono;
  auto t0 = steady_clock::now();
  SQL sql(query, true);

  // Snapshot the performance after, and compare.
  auto t1 = steady_clock::now();
  auto r1 = SQL::selectFrom({"resident_size", "user_time", "system_time"},
                            "processes",
                            "pid",
                            EQUALS,
                            pid);
  if (r0.size() > 0 && r1.size() > 0) {
    // Always called while processes table is working.
    uint64_t size = sql.rows().size();
    recordQueryPerformance(
        name, duration_cast<milliseconds>(t1 - t0).count(), size, r0[0], r1[0]);
  }
  return sql;
}

void Distributed::recordQueryPerformance(const std::string& name,
                                         uint64_t delay_ms,
                                         uint64_t size,
                                         const Row& r0,
                                         const Row& r1) {
  performance_[name] = QueryPerformance();

  auto& query = performance_.at(name);
  if (!r1.at("user_time").empty() && !r0.at("user_time").empty()) {
    auto ut1 = tryTo<long long>(r1.at("user_time"));
    auto ut0 = tryTo<long long>(r0.at("user_time"));
    auto diff = (ut1 && ut0) ? ut1.take() - ut0.take() : 0;
    if (diff > 0) {
      query.user_time = diff;
    }
  }

  if (!r1.at("system_time").empty() && !r0.at("system_time").empty()) {
    auto st1 = tryTo<long long>(r1.at("system_time"));
    auto st0 = tryTo<long long>(r0.at("system_time"));
    auto diff = (st1 && st0) ? st1.take() - st0.take() : 0;
    if (diff > 0) {
      query.system_time = diff;
    }
  }

  if (!r1.at("resident_size").empty() && !r0.at("resident_size").empty()) {
    auto rs1 = tryTo<long long>(r1.at("resident_size"));
    auto rs0 = tryTo<long long>(r0.at("resident_size"));
    auto diff = (rs1 && rs0) ? rs1.take() - rs0.take() : 0;
    if (diff > 0) {
      query.last_memory = diff;
    }
  }

  query.wall_time_ms = delay_ms;
}

Status serializeDistributedQueryRequest(const DistributedQueryRequest& r,
                                        JSON& doc,
                                        rj::Value& obj) {
  assert(obj.IsObject());
  doc.addCopy("query", r.query, obj);
  doc.addCopy("id", r.id, obj);
  return Status::success();
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
  return Status::success();
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
  return Status::success();
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

  return Status::success();
}

Status deserializeDistributedQueryResultJSON(const std::string& json,
                                             DistributedQueryResult& r) {
  auto doc = JSON::newObject();
  if (!doc.fromString(json) || !doc.doc().IsObject()) {
    return Status(1, "Error Parsing JSON");
  }
  return deserializeDistributedQueryResult(doc.doc(), r);
}

bool denylistedQueryTimestampExpired(const std::string& timestamp) {
  const auto ts = tryTo<uint64_t>(timestamp, 10).takeOr(uint64_t(0));
  return getUnixTime() > ts + denylistDuration();
}

std::string hashQuery(const std::string& query) {
  return hashFromBuffer(
      HashType::HASH_TYPE_SHA256, query.c_str(), query.length());
}

uint64_t denylistDuration() {
  return FLAGS_distributed_denylist_duration;
}

} // namespace osquery
