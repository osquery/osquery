/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <string>
#include <vector>

#include <osquery/plugin.h>
#include <osquery/query.h>
#include <osquery/status.h>

// PENDING status is runtime only, never reported back to endpoint
#define DQ_PENDING_STATUS -1

// INTERRUPTED status is when watcher kills resource intensive dist query
#define DQ_INTERRUPTED_STATUS 9

namespace osquery {

/**
 * @brief Small struct containing the state of a distributed query
 */
struct DistributedQueryResult {
 public:
  DistributedQueryResult() {}
  DistributedQueryResult(std::string qid, std::string q)
      : id(qid),
        query(q),
        results(),
        columns(),
        status(DQ_PENDING_STATUS),
        hasReported(false) {}

  bool isPending() const {
    return status.getCode() == DQ_PENDING_STATUS;
  }

  std::string id;
  std::string query;
  QueryData results;
  ColumnNames columns;
  Status status;
  bool hasReported;
};

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

  /// Get the number of queries which are waiting to be executed
  size_t getPendingQueryCount();

  /// Get the number of results which are waiting to be flushed
  size_t getCompletedCount();

  /// Process and execute queries obtained from pullUpdates().
  Status runQueries();

  // Getter for ID of currently executing request
  // NOTE referenced externally by Carver
  static std::string getCurrentRequestId();

  // Returns the number of time distributed_read endpoint was accessed
  size_t numDistReads();

  // Returns the number of time distributed_write endpoint was accessed
  size_t numDistWrites();

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
   * @brief Flush all of the collected results to the server
   */
  Status flushCompleted();

  /// Serialize result data into a JSON string
  Status serializeResults(std::string& json,
                          DistributedQueryResult* result = 0L);

  /**
   * @brief Used to write a single result when
   * FLAGS_distributed_write_individually==true.
   */
  Status writeResult(DistributedQueryResult& result);

  /**
   * @brief Checks for 'discovery' queries in doc and executes them.
   * @return true if no discovery, or all discovery queries return
   *         more than one row.  false otherwise.
   */
  Status passesDiscovery(const JSON& doc);

  /**
   * @brief Populates results_ with id and query for all queries in doc.
   * If discoveryStatus.ok()==false, will mark all results_ as
   * completed with OK status and no rows.  This is because if discovery
   * queries fail, these queries are not relevant to this device.
   */
  Status populateResultState(const JSON& doc, Status discoveryStatus);

  /**
   * @brief When a distributed read endpoint returns some work to be done,
   * Distributed class will write the document to the DB, and when all work
   * is done, remove it.  When the Distributed class starts up, it will check
   * for the presence of the work doc in DB, and if present, it knows that
   * distributed work was interrupted or restarted (presumably by watcher).
   * This function is called from pullUpdates(), and will check for this
   * scenario and report DQ_INTERRUPTED_STATUS(9) status for all queries.
   */
  void reportInterruptedWork();

  // if any of results[].hasReported are false
  int numUnreported();

  std::vector<DistributedQueryResult> results_;

  // ID of the currently executing query
  static std::string currentRequestId_;

  size_t numDistReads_{0U};
  size_t numDistWrites_{0U};

 private:
  friend class DistributedTests;
  FRIEND_TEST(DistributedTests, test_workflow);
};
} // namespace osquery
