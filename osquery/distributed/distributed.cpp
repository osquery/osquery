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

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"
#include "osquery/core/signing.h"

namespace pt = boost::property_tree;

namespace osquery {

const std::string kDistributedQueryPrefix{"distributed."};


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
  try {
    pt::ptree tree;
    {
      std::stringstream ss(work);
      pt::read_json(ss, tree);
    }
    std::set<std::string> queries_to_run;
    std::map<std::string, std::string> signatures;

    if (tree.count("signatures") > 0) {
      auto& signature_tree = tree.get_child("signatures");
      for (const auto& node : signature_tree) {
        auto sig = signature_tree.get<std::string>(node.first, "");
        if (sig.empty() || node.first.empty()) {
          continue;
        }
        signatures[node.first] = sig;
      }
    }

    // Check for and run discovery queries first
    if (tree.count("discovery") > 0) {
      auto& queries = tree.get_child("discovery");

      for (const auto& node : queries) {
        auto query = queries.get<std::string>(node.first, "");
        if (query.empty() || node.first.empty()) {
          return Status(
              1,
              "Distributed discovery query does not have complete attributes");
        }
        if (doesQueryRequireSignature(query)) {
          if (signatures.count(node.first + "_disc") > 0) {
            if (!verifyQuerySignature(signatures[node.first + "_disc"], query)
                     .ok()) {
              // Verification failed so don't run
              LOG(INFO) << "Failed verification for: " << query;
              continue;
            }
          } else {
            // There is no signature so don't run this query, this has the
            // side effect of also not running the query that this was
            // discovery for
            continue;
          }
        }
        SQL sql(query);
        if (!sql.getStatus().ok()) {
          return Status(1, "Distributed discovery query has an SQL error");
        }
        if (sql.rows().size() > 0) {
          queries_to_run.insert(node.first);
        }
      }
    }

    auto& queries = tree.get_child("queries");
    for (const auto& node : queries) {
      auto query = queries.get<std::string>(node.first, "");
      if (query.empty() || node.first.empty()) {
        return Status(1, "Distributed query does not have complete attributes");
      }
      if (doesQueryRequireSignature(query)) {
        if (signatures.count(node.first) > 0) {
          if (!verifyQuerySignature(signatures[node.first], query).ok()) {
            // Verification failed so don't run
            LOG(INFO) << "Failed verification for: " << query;
            continue;
          }
        } else {
          // There is no signature so don't run
          continue;
        }
      }
      if (queries_to_run.empty() || queries_to_run.count(node.first)) {
        setDatabaseValue(kQueries, kDistributedQueryPrefix + node.first, query);
      }
    }

    if (tree.count("accelerate") > 0) {
      auto new_time = tree.get<std::string>("accelerate", "");
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

  } catch (const pt::ptree_error& e) {
    return Status(1, "Error parsing JSON: " + std::string(e.what()));
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
}
