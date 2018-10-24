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
#include <thread>
#include <utility>

#include <osquery/database.h>
#include <osquery/distributed.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/sql.h>
#include <osquery/system.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"

namespace rj = rapidjson;

#define MAX_ACCEL_DURATION_SEC 3600 // 1 hour

namespace osquery {

CREATE_REGISTRY(DistributedPlugin, "distributed");

FLAG(string, distributed_plugin, "tls", "Distributed plugin name");

FLAG(bool,
     disable_distributed,
     true,
     "Disable distributed queries (default true)");

FLAG(bool,
     distributed_write_individually,
     false,
     "Distributed results are written without waiting for all queries to be "
     "finished (default false)");

FLAG(uint64,
     distributed_intra_sleep,
     0,
     "Seconds to sleep between queries (default 0)");

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

  // should not have any work in progress when this is called.
  assert(results_.size() == 0);

  // if last read document is in DB, worker process was killed
  reportInterruptedWork();

  PluginResponse response;
  auto status =
      Registry::call("distributed", {{"action", "getQueries"}}, response);
  numDistReads_++;

  if (!status.ok()) {
    return status;
  }

  if (response.size() > 0 && response[0].count("results") > 0) {
    return acceptWork(response[0]["results"]);
  }

  return Status(0, "OK");
}

/**
 * getPendingQueryCount
 * Return number of queries waiting to be executed.
 */
size_t Distributed::getPendingQueryCount() {
  int num = 0;
  for (auto item : results_) {
    if (item.isPending()) {
      num += 1;
    }
  }
  return num;
}

// Returns the number of time distributed_read endpoint was accessed
size_t Distributed::numDistReads() {
  return numDistReads_;
}

// Returns the number of time distributed_write endpoint was accessed
size_t Distributed::numDistWrites() {
  return numDistWrites_;
}

Status Distributed::serializeResults(std::string& json,
                                     DistributedQueryResult* item) {
  auto doc = JSON::newObject();
  auto queries_obj = doc.getObject();
  auto statuses_obj = doc.getObject();
  for (const auto& result : results_) {
    if (result.isPending() || result.hasReported) {
      continue;
    }
    if (0L != item && &result != item) {
      continue;
    }
    auto arr = doc.getArray();
    auto s = serializeQueryData(result.results, result.columns, doc, arr);
    if (!s.ok()) {
      return s;
    }
    doc.add(result.id, arr, queries_obj);
    doc.add(result.id, result.status.getCode(), statuses_obj);
  }

  doc.add("queries", queries_obj);
  doc.add("statuses", statuses_obj);
  return doc.toString(json);
}

Status Distributed::runQueries() {
  // sanity check - make sure plugin available
  // Shouldn't ever fail, since read endpoint worked, so plugin must be active
  auto distributed_plugin = RegistryFactory::get().getActive("distributed");
  if (!RegistryFactory::get().exists("distributed", distributed_plugin)) {
    return Status(1, "Missing distributed plugin " + distributed_plugin);
  }

  int i = -1;
  for (auto& item : results_) {
    i++;
    if (false == item.isPending()) {
      continue;
    }

    // if a distributed query has a long list, may need a
    // delay in between to avoid being killed by watcher.
    if (i > 0 && FLAGS_distributed_intra_sleep > 0) {
      if (FLAGS_distributed_intra_sleep > 30) {
        FLAGS_distributed_intra_sleep = 30;
      }
      VLOG(1) << "FLAGS_distributed_intra_sleep "
              << FLAGS_distributed_intra_sleep;
      std::this_thread::sleep_for(
          std::chrono::seconds(FLAGS_distributed_intra_sleep));
    }

    currentRequestId_ = item.id;
    setDatabaseValue(kPersistentSettings, "distributed_query_id", item.id);
    LOG(INFO) << "Executing distributed query: " << item.id << ": "
              << item.query;
    SQL sql(item.query);
    if (!sql.getStatus().ok()) {
      LOG(ERROR) << "Error executing distributed query: " << item.id << ": "
                 << sql.getMessageString();
    }

    item.results = sql.rows();
    item.columns = sql.columns();
    item.status = sql.getStatus();

    currentRequestId_ = "";
    deleteDatabaseValue(kPersistentSettings, "distributed_query_id");

    // if flag set, report results when ready, else flush when all are done.
    if (FLAGS_distributed_write_individually && results_.size() > 0) {
      writeResult(item);
    }
  }

  // DistributedRunner::start does not currently check returned status

  return flushCompleted();
}

Status Distributed::flushCompleted() {
  Status status = Status(0, "OK");

  if (results_.size() == 0) {
    return status;
  }

  if (numUnreported() > 0) {
    std::string results;
    status = serializeResults(results);
    if (!status.ok()) {
      return status;
    }

    PluginResponse response;
    status = Registry::call("distributed",
                            {{"action", "writeResults"}, {"results", results}},
                            response);
    numDistWrites_++;

    // The TLS plugin will retry FLAGS_distributed_tls_max_attempts(3) times.
    // If unsuccessful, we drop it on the floor.
    if (!status.ok()) {
      std::string str;
      for (auto item : results_) {
        str += "{ id:" + item.id;
        str += " query:" + item.query + "}";
      }
      LOG(WARNING) << "writeResults failed. dropping results " << str;
    }
  }

  // cleanup

  results_.clear();
  deleteDatabaseValue(kPersistentSettings, "distributed_work");

  return status;
}

/**
 * return number of unreported results,
 * regardless of the status (could be pending)
 */
int Distributed::numUnreported() {
  int n = 0;
  for (auto& item : results_) {
    if (false == item.hasReported) {
      n++;
    }
  }
  return n;
}

Status Distributed::writeResult(DistributedQueryResult& item) {
  auto distributed_plugin = RegistryFactory::get().getActive("distributed");
  if (!RegistryFactory::get().exists("distributed", distributed_plugin)) {
    return Status(1, "Missing distributed plugin " + distributed_plugin);
  }

  std::string results;
  auto s = serializeResults(results, &item);
  if (!s.ok()) {
    return s;
  }

  PluginResponse response;
  s = Registry::call("distributed",
                     {{"action", "writeResults"}, {"results", results}},
                     response);
  numDistWrites_++;

  // The TLS plugin will retry FLAGS_distributed_tls_max_attempts(3) times.
  // If unsuccessful, we drop it on the floor.
  if (!s.ok()) {
    LOG(WARNING) << "writeResult failed for id:" << item.id;
  }

  item.hasReported = true;
  item.results.clear();

  return s;
}

Status Distributed::passesDiscovery(const JSON& doc) {
  if (!doc.doc().HasMember("discovery")) {
    return Status();
  }

  int numDiscoveryQueries = 0;
  int numDiscoveryPassed = 0;
  const auto& queries = doc.doc()["discovery"];

  if (!queries.IsObject()) {
    return Status(1, "Bad document: Distributed 'discovery' is not an object");
  }

  for (const auto& query_entry : queries.GetObject()) {
    if (!query_entry.name.IsString() || !query_entry.value.IsString()) {
      return Status(1, "Distributed discovery query is not a string");
    }

    auto name = std::string(query_entry.name.GetString());
    auto query = std::string(query_entry.value.GetString());
    if (query.empty() || name.empty()) {
      return Status(1, "Distributed discovery query is not a string");
    }

    numDiscoveryQueries++;
    LOG(INFO) << "Executing distributed DISCOVERY query: " << name << ": "
              << query;

    SQL sql(query);
    if (!sql.getStatus().ok()) {
      return Status(1, "Distributed discovery query has an SQL error");
    }
    if (sql.rows().size() > 0) {
      numDiscoveryPassed++;
    }
  }

  // All discovery queries need to return rows to pass discovery

  if (numDiscoveryPassed < numDiscoveryQueries) {
    return Status(1);
  }

  return Status();
}

static inline std::string getStr(const rj::Value& node) {
  if (node.IsString()) {
    return std::string(node.GetString());
  }
  return "";
}

/**
 * Parses the queries portion of distributed_read body and populates
 * results_ vector.  Each result_ entry will have id, query set, and
 * the status will be set to -1, indicating that the query has not been
 * initiated yet.  With the exception being when discoveryStatus is not
 * success, which indicates queries should not be run, so result_ statuses
 * are set to 0, meaning success.  Discovery queries are used to check
 * whether a set of queries are relevant to the target device.
 */
Status Distributed::populateResultState(const JSON& doc,
                                        Status discoveryStatus) {
  const auto& queries = doc.doc()["queries"];

  for (const auto& query_entry : queries.GetObject()) {
    auto name = getStr(query_entry.name);
    auto query = getStr(query_entry.value);
    if (name.empty() || query.empty()) {
      return Status(1, "Distributed query is not a string");
    }

    // add result placeholder
    DistributedQueryResult result(name, query);
    if (!discoveryStatus.ok()) {
      // queries are not relevant to this device, mark as done
      result.status = Status(0);
    }

    results_.push_back(result);
  }

  return Status();
}

/**
 * reportInterruptedWork()
 * If one of the distributed queries uses too much CPU or memory,
 * the worker process will be killed by Watcher process.  We need to
 * report status on the lost queries.  At startup, pullUpdates() calls this
 * function, and it will check database to see if a request was interrupted.
 */
void Distributed::reportInterruptedWork() {
  std::string work;
  std::string lastQueryId;
  getDatabaseValue(kPersistentSettings, "distributed_work", work);
  getDatabaseValue(kPersistentSettings, "distributed_query_id", lastQueryId);

  // clear
  deleteDatabaseValue(kPersistentSettings, "distributed_work");
  deleteDatabaseValue(kPersistentSettings, "distributed_query_id");

  if (work.empty() && lastQueryId.empty()) {
    return;
  }

  if (work.empty()) {
    LOG(WARNING) << "distributed_work not in DB, but distributed_query_id was";
    return;
  }
  auto doc = JSON::newObject();
  if (!doc.fromString(work) || !doc.doc().IsObject()) {
    LOG(WARNING) << "ERROR distributed_work in DB was invalid";
    return;
  }

  if (!lastQueryId.empty()) {
    LOG(WARNING) << "distributed worker was interrupted running query id "
                 << lastQueryId;
  }

  // load queries

  populateResultState(doc, Status());

  // mark with INTERRUPTED status

  for (auto& item : results_) {
    item.status = Status(DQ_INTERRUPTED_STATUS, "INTERRUPTED");
  }

  // send response

  flushCompleted();
}

Status Distributed::acceptWork(const std::string& work) {
  auto doc = JSON::newObject();
  if (!doc.fromString(work) || !doc.doc().IsObject()) {
    return Status(1, "Error Parsing JSON");
  }

  Status discoveryStatus = passesDiscovery(doc);

  if (doc.doc().HasMember("queries")) {
    const auto& queries = doc.doc()["queries"];

    if (!queries.IsObject()) {
      return Status(1, "Format error: Distributed 'queries' is not object");
    }

    Status status = populateResultState(doc, discoveryStatus);
    if (status.ok()) {
      // good to go. Save work to DB in case watchdog kills worker
      setDatabaseValue(kPersistentSettings, "distributed_work", work);
    } else {
      return status; // parsing failed
    }
  }

  if (doc.doc().HasMember("accelerate")) {
    const auto& accelerate = doc.doc()["accelerate"];
    if (accelerate.IsInt() && accelerate.GetInt() > 0 &&
        accelerate.GetInt() < MAX_ACCEL_DURATION_SEC) {
      auto duration = accelerate.GetInt();
      LOG(INFO) << "Accelerating distributed query checkins for " << duration
                << " seconds";
      setDatabaseValue(kPersistentSettings,
                       "distributed_accelerate_checkins_expire",
                       std::to_string(getUnixTime() + duration));
    } else {
      VLOG(1) << "Invalid argument for accelerate. must be int > 0 < MAX";
    }
  }
  return Status();
}

// static function used by Carver
std::string Distributed::getCurrentRequestId() {
  return currentRequestId_;
}
} // namespace osquery
