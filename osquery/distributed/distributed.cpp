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

#include <boost/property_tree/json_parser.hpp>

#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/logger.h>

#include "osquery/distributed/distributed.h"

namespace pt = boost::property_tree;

namespace osquery {

DEFINE_osquery_flag(int32,
                    distributed_get_queries_retries,
                    3,
                    "Times to retry retrieving distributed queries");

DEFINE_osquery_flag(int32,
                    distributed_write_results_retries,
                    3,
                    "Times to retry writing distributed query results");

Status MockDistributedProvider::getQueriesJSON(std::string& query_json) {
  query_json = queriesJSON_;
  return Status();
}

Status MockDistributedProvider::writeResultsJSON(const std::string& results) {
    resultsJSON_ = results;
    return Status();
}

Status DistributedQueryHandler::parseQueriesJSON(
    const std::string& query_json,
    std::vector<DistributedQueryRequest>& requests) {
  // Parse the JSON into a ptree
  pt::ptree tree;
  try {
    std::istringstream query_stream(query_json);
    pt::read_json(query_stream, tree);
  }
  catch (const std::exception& e) {
    return Status(1, std::string("Error loading query JSON: ") + e.what());
  }

  // Parse the ptree into DistributedQueryRequests
  std::vector<DistributedQueryRequest> results;
  for (const auto& node : tree) {
    const auto& request_tree = node.second;
    DistributedQueryRequest request;
    try {
      request.query = request_tree.get_child("query").get_value<std::string>();
      request.id = request_tree.get_child("id").get_value<std::string>();
    } catch (const std::exception& e) {
      return Status(1, std::string("Error parsing queries: ") + e.what());
    }
    results.push_back(request);
  }

  requests = std::move(results);

  return Status();
}

SQL DistributedQueryHandler::handleQuery(const std::string& query_string) {
  SQL query = SQL(query_string);
  query.annotateHostInfo();
  return query;
}

Status DistributedQueryHandler::serializeResults(
    const std::vector<std::pair<DistributedQueryRequest, SQL> >& results,
    pt::ptree& tree) {
  try {
    pt::ptree& res_tree = tree.put_child("results", pt::ptree());
    for (const auto& result : results) {
      DistributedQueryRequest request = result.first;
      SQL sql = result.second;
      pt::ptree& child = res_tree.put_child(request.id, pt::ptree());
      child.put("status", sql.getStatus().getCode());
      pt::ptree& rows_child = child.put_child("rows", pt::ptree());
      Status s = serializeQueryData(sql.rows(), rows_child);
      if (!s.ok()) {
        return s;
      }
    }
  }
  catch (const std::exception& e) {
    return Status(1, std::string("Error serializing results: ") + e.what());
  }
  return Status();
}

Status DistributedQueryHandler::doQueries() {
  // Get and parse the queries
  Status status;
  std::string query_json;
  int retries = 0;
  do {
    status = provider_->getQueriesJSON(query_json);
    ++retries;
  } while (!status.ok() && retries <= FLAGS_distributed_get_queries_retries);
  if (!status.ok()) {
    return status;
  }

  std::vector<DistributedQueryRequest> requests;
  status = parseQueriesJSON(query_json, requests);
  if (!status.ok()) {
    return status;
  }

  // Run the queries
  std::vector<std::pair<DistributedQueryRequest, SQL> > query_results;
  std::set<std::string> successful_query_ids;
  for (const auto& request : requests) {
    if (executedRequestIds_.find(request.id) != executedRequestIds_.end()) {
      // We've already successfully returned results for this request, don't
      // process it again.
      continue;
    }
    SQL query_result = handleQuery(request.query);
    if (query_result.ok()) {
      successful_query_ids.insert(request.id);
    }
    query_results.push_back({request, query_result});
  }

  // Serialize the results
  pt::ptree serialized_results;
  serializeResults(query_results, serialized_results);
  std::string json;
  try {
    std::ostringstream ss;
    pt::write_json(ss, serialized_results, false);
    json = ss.str();
  }
  catch (const std::exception& e) {
    return Status(1, e.what());
  }

  // Write the results
  retries = 0;
  do {
    status = provider_->writeResultsJSON(json);
    ++retries;
  } while (!status.ok() && retries <= FLAGS_distributed_write_results_retries);
  if (!status.ok()) {
    return status;
  }

  // Only note that the queries were successfully completed if we were actually
  // able to write the results.
  executedRequestIds_.insert(successful_query_ids.begin(),
                             successful_query_ids.end());

  return status;
}
}
