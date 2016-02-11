/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <string>
#include <vector>

#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/registry.h>
#include <osquery/status.h>

#include <osquery/dispatcher/dispatcher.h>

namespace osquery {

class DistributedPlugin : public Plugin {
 public:
  /**
   * @brief Get the queries to be executed
   *
   * Consider the following example JSON which represents the expected format
   *
   * @code{.json}
   *   {
   *     "queries": {
   *       "id1": "select * from osquery_info",
   *       "id2": "select * from osquery_schedule"
   *     }
   *   }
   * @endcode
   *
   * @param json is the string to populate the queries data structure with
   * @return a Status indicating the success or failure of the operation
   */
  virtual Status getQueries(std::string& json) = 0;

  /**
   * @brief Write the results that were executed
   *
   * Consider the following JSON which represents the format that will be used:
   *
   * @code{.json}
   *   {
   *     "queries": {
   *       "id1": [
   *         {
   *           "col1": "val1",
   *           "col2": "val2"
   *         },
   *         {
   *           "col1": "val1",
   *           "col2": "val2"
   *         }
   *       ],
   *       "id2": [
   *         {
   *           "col1": "val1",
   *           "col2": "val2"
   *         }
   *       ]
   *     }
   *   }
   * @endcode
   *
   * @param json is the results data to write
   * @return a Status indicating the success or failure of the operation
   */
  virtual Status writeResults(const std::string& json) = 0;

  /// Main entrypoint for distirbuted plugin requests
  Status call(const PluginRequest& request, PluginResponse& response);
};

CREATE_REGISTRY(DistributedPlugin, "distributed");

/**
 * @brief Class for managing the set of distributed queries to execute
 *
 * Consider the following workflow example, without any error handling
 *
 * @code{.cpp}
 *   auto dist = Distributed();
 *   while (true) {
 *     dist.pullUpdates();
 *     if (dist.getPendingQueryCount() > 0) {
 *       dist.runQueries();
 *     }
 *   }
 * @endcode
 */
class Distributed {
 public:
  /// Default constructor
  Distributed(){};

  /// Retrieve queued queries from a remote server
  Status pullUpdates();

  /// Get the number of queries which are waiting to be executed
  size_t getPendingQueryCount();

  /// Get the number of results which are waiting to be flushed
  size_t getCompletedCount();

  /// Serialize result data into a JSON string and clear the results
  Status serializeResults(std::string& json);

  /// Process and execute queued queries
  Status runQueries();

 protected:
  /**
   * @brief Process several queries from a distributed plugin
   *
   * Given a response from a distributed plugin, parse the results and enqueue
   * them in the internal state of the class
   *
   * @param work is the string from DistributedPlugin::getQueries
   * @return a Status indicating the success or failure of the operation
   */
  Status acceptWork(const std::string& work);

  /**
   * @brief Pop a request object off of the queries_ member
   *
   * @return a DistributedQueryRequest object which needs to be executed
   */
  DistributedQueryRequest popRequest();

  /**
   * @brief Queue a result to be batch sent to the server
   *
   * @param result is a DistributedQueryResult object to be sent to the server
   */
  void addResult(const DistributedQueryResult& result);

  /**
   * @brief Flush all of the collected results to the server
   */
  Status flushCompleted();

 protected:
  std::vector<DistributedQueryRequest> queries_;
  std::vector<DistributedQueryResult> results_;

 private:
  friend class DistributedTests;
  FRIEND_TEST(DistributedTests, test_workflow);
};
}
