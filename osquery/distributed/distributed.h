/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>
#include <vector>

#include <osquery/core/plugins/plugin.h>
#include <osquery/core/query.h>
#include <osquery/utils/status/status.h>

namespace osquery {

/**
 * @brief Small struct containing the query and ID information for a
 * distributed query
 */
struct DistributedQueryRequest {
 public:
  explicit DistributedQueryRequest() {}

  std::string query;
  std::string id;
};

/**
 * @brief Serialize a DistributedQueryRequest into a property tree
 *
 * @param r the DistributedQueryRequest to serialize
 * @param doc the input JSON managed document
 * @param obj the output rapidjson document [object]
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeDistributedQueryRequest(const DistributedQueryRequest& r,
                                        JSON& doc,
                                        rapidjson::Value& obj);

/**
 * @brief Serialize a DistributedQueryRequest object into a JSON string
 *
 * @param r the DistributedQueryRequest to serialize
 * @param json the output JSON string
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeDistributedQueryRequestJSON(const DistributedQueryRequest& r,
                                            std::string& json);

/**
 * @brief Deserialize a DistributedQueryRequest object from a property tree
 *
 * @param obj the input rapidjson value [object]
 * @param r the output DistributedQueryRequest structure
 *
 * @return Status indicating the success or failure of the operation
 */
Status deserializeDistributedQueryRequest(const rapidjson::Value& obj,
                                          DistributedQueryRequest& r);

/**
 * @brief Deserialize a DistributedQueryRequest object from a JSON string
 *
 * @param json the input JSON string
 * @param r the output DistributedQueryRequest structure
 *
 * @return Status indicating the success or failure of the operation
 */
Status deserializeDistributedQueryRequestJSON(const std::string& json,
                                              DistributedQueryRequest& r);

/**
 * @brief Small struct containing the results of a distributed query
 */
struct DistributedQueryResult {
 public:
  DistributedQueryResult() {}
  DistributedQueryResult(const DistributedQueryRequest& req,
                         const QueryData& res,
                         const ColumnNames& cols,
                         const Status& s,
                         const std::string& msg)
      : request(req), results(res), columns(cols), status(s), message(msg) {}

  DistributedQueryRequest request;
  QueryData results;
  ColumnNames columns;
  Status status;
  std::string message;
};

/**
 * @brief Serialize a DistributedQueryResult into a property tree
 *
 * @param r the DistributedQueryResult to serialize
 * @param doc the input JSON managed document
 * @param obj the output rapidjson document [object]
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeDistributedQueryResult(const DistributedQueryResult& r,
                                       JSON& doc,
                                       rapidjson::Value& obj);
/**
 * @brief Serialize a DistributedQueryResult object into a JSON string
 *
 * @param r the DistributedQueryResult to serialize
 * @param json the output JSON string
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeDistributedQueryResultJSON(const DistributedQueryResult& r,
                                           std::string& json);

/**
 * @brief Deserialize a DistributedQueryResult object from a property tree
 *
 * @param obj the input rapidjson document [object]
 * @param r the output DistributedQueryResult structure
 *
 * @return Status indicating the success or failure of the operation
 */
Status deserializeDistributedQueryResult(const rapidjson::Value& obj,
                                         DistributedQueryResult& r);

/**
 * @brief Deserialize a DistributedQueryResult object from a JSON string
 *
 * @param json the input JSON string
 * @param r the output DistributedQueryResult structure
 *
 * @return Status indicating the success or failure of the operation
 */
Status deserializeDistributedQueryResultJSON(const std::string& json,
                                             DistributedQueryResult& r);

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

  /// Main entrypoint for distributed plugin requests
  Status call(const PluginRequest& request, PluginResponse& response) override;
};

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
  Distributed() {}

  /// Retrieve queued queries from a remote server
  Status pullUpdates();

  /// Get the queries which are waiting to be executed
  std::vector<std::string> getPendingQueries();

  /// Get the number of results which are waiting to be flushed
  size_t getCompletedCount();

  /// Serialize result data into a JSON string and clear the results
  Status serializeResults(std::string& json);

  /// Process and execute queued queries
  Status runQueries();

  // Getter for ID of currently executing request
  static std::string getCurrentRequestId();

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
   * @brief Pop a request off of the database for the query in the argument
   *
   * @return a DistributedQueryRequest object which needs to be executed
   */
  DistributedQueryRequest popRequest(std::string query);

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

  // Setter for ID of currently executing request
  static void setCurrentRequestId(const std::string& cReqId);

  std::vector<DistributedQueryResult> results_;

  // ID of the currently executing query
  static std::string currentRequestId_;

 private:
  friend class DistributedTests;
  FRIEND_TEST(DistributedTests, test_workflow);
};
} // namespace osquery
