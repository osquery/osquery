/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <set>
#include <vector>

#include <boost/property_tree/ptree.hpp>

#include <osquery/database/results.h>
#include <osquery/sql.h>

namespace osquery {

/**
 * @brief This is an interface for distributed query "providers"
 *
 * Providers implement the communication between the distributed query master
 * and the individual host. A provider may utilize any communications strategy
 * that supports reading and writing JSON (i.e. HTTPS requests, reading from a
 * file, querying a message queue, etc.)
 */
class IDistributedProvider {
public:
  virtual ~IDistributedProvider() {}

  /*
   * @brief Get the JSON string containing the queries to be executed
   *
   * @param query_json A string to fill with the retrieved JSON
   *
   * @return osquery::Status indicating success or failure of the operation
   */
  virtual Status getQueriesJSON(std::string& query_json) = 0;

  /*
   * @brief Write the results JSON back to the master
   *
   * @param results A string containing the results JSON
   *
   * @return osquery::Status indicating success or failure of the operation
   */
  virtual Status writeResultsJSON(const std::string& results) = 0;
};

/**
 * @brief A mocked implementation of IDistributedProvider
 *
 * This implementation is useful for writing unit tests of the
 * DistributedQueryHandler functionality.
 */
class MockDistributedProvider : public IDistributedProvider {
public:
 // These methods just read/write the corresponding public members
  Status getQueriesJSON(std::string& query_json) override;
  Status writeResultsJSON(const std::string& results) override;

  std::string queriesJSON_;
  std::string resultsJSON_;
};

/**
 * @brief Small struct containing the query and ID information for a
 * distributed query
 */
struct DistributedQueryRequest {
public:
 explicit DistributedQueryRequest() {}
 explicit DistributedQueryRequest(const std::string& q, const std::string& i)
     : query(q), id(i) {}
  std::string query;
  std::string id;
};

/**
 * @brief The main handler class for distributed queries
 *
 * This class is responsible for implementing the core functionality of
 * distributed queries. It manages state, uses the provider to read/write from
 * the master, and executes queries.
 */
class DistributedQueryHandler {
public:
 /**
  * @brief Construct a new handler with the given provider
  *
  * @param provider The provider used retrieving queries and writing results
  */
 explicit DistributedQueryHandler(
     std::unique_ptr<IDistributedProvider> provider)
     : provider_(std::move(provider)) {}

 /**
  * @brief Retrieve queries, run them, and write results
  *
  * This is the core method of DistributedQueryHandler, tying together all the
  * other components to read the requests from the provider, execute the
  * queries, and write the results back to the provider.
  *
  * @return osquery::Status indicating success or failure of the operation
  */
 Status doQueries();

 /**
  * @brief Run and annotate an individual query
  *
  * @param query_string A string containing the query to be executed
  *
  * @return A SQL object containing the (annotated) query results
  */
 static SQL handleQuery(const std::string& query_string);

 /**
  * @brief Serialize the results of all requests into a ptree
  *
  * @param results The vector of requests and results
  * @param tree The tree to serialize results into
  *
  * @return osquery::Status indicating success or failure of the operation
  */
 static Status serializeResults(
     const std::vector<std::pair<DistributedQueryRequest, SQL> >& results,
     boost::property_tree::ptree& tree);

 /**
  * @brief Parse the query JSON into the individual query objects
  *
  * @param query_json The JSON string containing the queries
  * @param requests A vector to fill with the query objects
  *
  * @return osquery::Status indicating success or failure of the parsing
  */
  static Status parseQueriesJSON(const std::string& query_json,
                                 std::vector<DistributedQueryRequest>& requests);

private:
  // The provider used to read and write queries and results
  std::unique_ptr<IDistributedProvider> provider_;

  // Used to store already executed queries to avoid duplication. (Some master
  // configurations may asynchronously process the results of requests, so a
  // request might be seen by the host after it has already been executed.)
  std::set<std::string> executedRequestIds_;
};

} // namespace osquery
