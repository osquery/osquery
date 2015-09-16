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
#include <utility>

#include <boost/property_tree/json_parser.hpp>

#include <osquery/core.h>
#include <osquery/distributed.h>
#include <osquery/logger.h>
#include <osquery/sql.h>


namespace pt = boost::property_tree;

namespace osquery {

FLAG(string, distributed_plugin, "tls", "Distributed plugin name");

FLAG(bool,
     distributed_enabled,
     false,
     "Main killswitch for distributed queries. (default false");

boost::shared_mutex distributed_queries_mutex_;
boost::shared_mutex distributed_results_mutex_;

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
  auto& distributed_plugin = Registry::getActive("distributed");
  if (!Registry::exists("distributed", distributed_plugin)) {
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
  ReadLock rlock(distributed_queries_mutex_);
  return queries_.size();
}

size_t Distributed::getCompletedCount() {
  ReadLock rlock(distributed_results_mutex_);
  return results_.size();
}

Status Distributed::serializeResults(std::string& json) {
  WriteLock wlock(distributed_results_mutex_);

  pt::ptree tree;
  for (const auto& result : results_) {
    pt::ptree qd;
    auto s = serializeQueryData(result.results, qd);
    if (!s.ok()) {
      return s;
    }
    tree.add_child(result.request.id, qd);
  }

  pt::ptree results;
  results.add_child("queries", tree);

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
  WriteLock wlock_results(distributed_results_mutex_);
  results_.push_back(result);
}

Status Distributed::runQueries() {
  while (getPendingQueryCount() > 0) {
    auto query = popRequest();

    auto sql = SQL(query.query);
    if (!sql.getStatus().ok()) {
      LOG(ERROR) << "Error running distributed query[" << query.id
                 << "]: " << query.query;
      continue;
    }

    DistributedQueryResult result(std::move(query), std::move(sql.rows()));
    addResult(result);
  }
  return flushCompleted();
}

Status Distributed::flushCompleted() {
  if (getCompletedCount() == 0) {
    return Status(0, "OK");
  }

  auto& distributed_plugin = Registry::getActive("distributed");
  if (!Registry::exists("distributed", distributed_plugin)) {
    return Status(1, "Missing distributed plugin " + distributed_plugin);
  }

  std::string results;
  auto s = serializeResults(results);
  if (!s.ok()) {
    return s;
  }

  PluginResponse response;
  return Registry::call("distributed",
                        {{"action", "writeResults"}, {"results", results}},
                        response);
}

Status Distributed::acceptWork(const std::string& work) {
  pt::ptree tree;
  std::stringstream ss(work);
  try {
    pt::read_json(ss, tree);

    auto& queries = tree.get_child("queries");
    for (const auto& node : queries) {
      DistributedQueryRequest request;
      request.id = node.first;
      request.query = queries.get<std::string>(node.first, "");
      if (request.query.empty() || request.id.empty()) {
        return Status(1,
                      "Distributed query does not have complete attributes.");
      }
      WriteLock wlock(distributed_queries_mutex_);
      queries_.push_back(request);
    }
  } catch (const pt::ptree_error& e) {
    return Status(1, "Error parsing JSON: " + std::string(e.what()));
  }

  return Status(0, "OK");
}

DistributedQueryRequest Distributed::popRequest() {
  WriteLock wlock_queries(distributed_queries_mutex_);
  auto q = queries_[0];
  queries_.erase(queries_.begin());
  return std::move(q);
}
}
