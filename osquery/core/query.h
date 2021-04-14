/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest_prod.h>

#include <osquery/core/core.h>
#include <osquery/core/sql/diff_results.h>
#include <osquery/core/sql/scheduled_query.h>
#include <osquery/utils/json/json.h>

namespace osquery {

class Status;

/**
 * @brief Query results from a schedule, snapshot, or ad-hoc execution.
 *
 * When a scheduled query yields new results, we need to log that information
 * to our upstream logging receiver. A QueryLogItem contains metadata and
 * results in potentially-differential form for a logger.
 */
struct QueryLogItem {
 public:
  /// Differential results from the query.
  DiffResults results;

  /// Optional snapshot results, no differential applied.
  QueryDataTyped snapshot_results;

  /// The name of the scheduled query.
  std::string name;

  /// The identifier (hostname, or uuid) of the host.
  std::string identifier;

  /// The time that the query was executed, seconds as UNIX time.
  uint64_t time{0};

  /// The epoch at the time the query was executed
  uint64_t epoch{};

  /// Query execution counter for current epoch
  uint64_t counter{0};

  /// The time that the query was executed, an ASCII string.
  std::string calendar_time;

  /// A set of additional fields to emit with the log line.
  std::map<std::string, std::string> decorations;

  /// equals operator
  bool operator==(const QueryLogItem& comp) const {
    return (comp.results == results) && (comp.name == name);
  }

  /// not equals operator
  bool operator!=(const QueryLogItem& comp) const {
    return !(*this == comp);
  }
};

/**
 * @brief Serialize a QueryLogItem object into a JSON document.
 *
 * @param item the QueryLogItem to serialize.
 * @param doc [output] the output JSON document (object type).
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeQueryLogItem(const QueryLogItem& item, JSON& doc);

/**
 * @brief Serialize a QueryLogItem object into a JSON string.
 *
 * @param item the QueryLogItem to serialize.
 * @param json [output] the output JSON string.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeQueryLogItemJSON(const QueryLogItem& item, std::string& json);

/**
 * @brief Serialize a QueryLogItem object into a JSON document containing
 * events, a list of actions.
 *
 * @param item the QueryLogItem to serialize
 * @param json [output] the output JSON document.
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeQueryLogItemAsEvents(const QueryLogItem& item, JSON& json);

/**
 * @brief Serialize a QueryLogItem object into a JSON string of events,
 * a list of actions.
 *
 * @param i the QueryLogItem to serialize
 * @param items [output] vector of JSON output strings
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeQueryLogItemAsEventsJSON(const QueryLogItem& i,
                                         std::vector<std::string>& items);

/**
 * @brief Interact with the historical on-disk storage for a given query.
 */
class Query {
 public:
  /**
   * @brief Constructor which sets up necessary parameters of a Query object.
   *
   * Given a query, this constructor calculates the value of columnFamily_,
   * which can be accessed via the getColumnFamilyName getter method.
   *
   * @param name The query name.
   * @param q a ScheduledQuery struct.
   */
  explicit Query(std::string name, const ScheduledQuery& q)
      : query_(q.query), name_(std::move(name)) {}

  /**
   * @brief Serialize the data in RocksDB into a useful data structure
   *
   * This method retrieves the data from RocksDB and returns the data in a
   * std::multiset, in-order to apply binary search in diff function.
   *
   * @param results the output QueryDataSet struct.
   *
   * @return the success or failure of the operation.
   */
  Status getPreviousQueryResults(QueryDataSet& results) const;

  /**
   * @brief Get the epoch associated with the previous query results.
   *
   * This method retrieves the epoch associated with the results data that was
   * was stored in rocksdb.
   *
   * @return the epoch associated with the previous query results.
   */
  uint64_t getPreviousEpoch() const;

  /**
   * @brief Get the query invocation counter.
   *
   * This method returns query invocation counter. If the query is a new query,
   * 0 is returned. Otherwise the counter associated with the query is retrieved
   * from database and incremented by 1.
   *
   * @param new_query Whether or not the query is new.
   *
   * @return the query invocation counter.
   */
  uint64_t getQueryCounter(bool new_query) const;

  /**
   * @brief Check if a given scheduled query exists in the database.
   *
   * @return true if the scheduled query already exists in the database.
   */
  bool isQueryNameInDatabase() const;

  /**
   * @brief Check if a query (not query name) is 'new' or altered.
   *
   * @return true if the scheduled query has not been altered.
   */
  bool isNewQuery() const;

  /// Determines if this is a first run or new query.
  void getQueryStatus(uint64_t epoch,
                      bool& fresh_results,
                      bool& new_query) const;

  /// Increment and return the query counter.
  Status incrementCounter(bool reset, uint64_t& counter) const;

  /**
   * @brief Add a new set of results to the persistent storage.
   *
   * Given the results of the execution of a scheduled query, add the results
   * to the database using addNewResults.
   *
   * @param qd the QueryDataTyped object, which has the results of the query.
   * @param epoch the epoch associated with QueryData
   * @param counter [output] the output that holds the query execution counter.
   *
   * @return the success or failure of the operation.
   */
  Status addNewResults(QueryDataTyped qd,
                       uint64_t epoch,
                       uint64_t& counter) const;

  /**
   * @brief Add a new set of results to the persistent storage and get back
   * the differential results.
   *
   * Given the results of an execution of a scheduled query, add the results
   * to the database using addNewResults and get back a data structure
   * indicating what rows in the query's results have changed.
   *
   * @param qd the QueryDataTyped object containing query results to store.
   * @param epoch the epoch associated with QueryData
   * @param counter the output that holds the query execution counter.
   * @param dr an output to a DiffResults object populated based on last run.
   * @param calculate_diff default true to populate dr.
   *
   * @return the success or failure of the operation.
   */
  Status addNewResults(QueryDataTyped qd,
                       uint64_t epoch,
                       uint64_t& counter,
                       DiffResults& dr,
                       bool calculate_diff = true) const;

  /// A version of adding new results for events-based queries.
  Status addNewEvents(QueryDataTyped current_qd,
                      const uint64_t current_epoch,
                      uint64_t& counter,
                      DiffResults& dr) const;

  /**
   * @brief The most recent result set for a scheduled query.
   *
   * @param qd the output QueryData object.
   *
   * @return the success or failure of the operation.
   */
  Status getCurrentResults(QueryData& qd);

 public:
  /**
   * @brief Get the names of all historical queries.
   *
   * If you'd like to perform some database maintenance, getStoredQueryNames()
   * allows you to get a vector of the names of all queries which are
   * currently stored in RocksDB
   *
   * @return a vector containing the string names of all scheduled queries.
   */
  static std::vector<std::string> getStoredQueryNames();

 private:
  /// The scheduled query's query string.
  std::string query_;

  /// The scheduled query name.
  std::string name_;

 private:
  FRIEND_TEST(QueryTests, test_private_members);
  FRIEND_TEST(QueryTests, test_add_and_get_current_results);
  FRIEND_TEST(QueryTests, test_is_query_name_in_database);
  FRIEND_TEST(QueryTests, test_get_stored_query_names);
  FRIEND_TEST(QueryTests, test_get_executions);
  FRIEND_TEST(QueryTests, test_get_query_results);
  FRIEND_TEST(QueryTests, test_query_name_not_found_in_db);
};

} // namespace osquery
