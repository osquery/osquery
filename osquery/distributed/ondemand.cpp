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

#include <boost/property_tree/ptree.hpp>

#include <osquery/core.h>
#include <osquery/distributed.h>
#include <osquery/logger.h>

#include "osquery/core/json.h"

namespace pt = boost::property_tree;

namespace osquery {

CREATE_REGISTRY(DistributedPlugin, "distributed");

FLAG(string, distributed_plugin, "tls", "Distributed plugin name");

FLAG(bool,
     disable_distributed,
     true,
     "Disable distributed queries (default true)");

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

Status serializeDistributedQueryRequest(const DistributedQueryRequest& r,
                                        pt::ptree& tree) {
  tree.put("query", r.query);
  tree.put("id", r.id);
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