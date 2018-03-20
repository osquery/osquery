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

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <osquery/core.h>
#include <osquery/status.h>

#include "osquery/core/json.h"

namespace osquery {

/**
 * @brief A variant type for the SQLite type affinities.
 */
using RowData = std::string;

/**
 * @brief A single row from a database query
 *
 * Row is a simple map where individual column names are keys, which map to
 * the Row's respective value
 */
using Row = std::map<std::string, RowData>;

/**
 * @brief A vector of column names associated with a query
 *
 * ColumnNames is a vector of the column names, in order, returned by a query.
 */
using ColumnNames = std::vector<std::string>;

/**
 * @brief Serialize a Row into a JSON document.
 *
 * @param r the Row to serialize.
 * @param cols the TableColumn vector indicating column order
 * @param doc the managed JSON document.
 * @param obj [output] the JSON object to assign values.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeRow(const Row& r,
                    const ColumnNames& cols,
                    JSON& doc,
                    rapidjson::Value& obj);

/**
 * @brief Serialize a Row object into a JSON string.
 *
 * @param r the Row to serialize.
 * @param json [output] the output JSON string.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeRowJSON(const Row& r, std::string& json);

/**
 * @brief Deserialize a Row object from JSON object.
 *
 * @param obj the input JSON value (should be an object).
 * @param r [output] the output Row structure.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status deserializeRow(const rapidjson::Value& obj, Row& r);

/**
 * @brief Deserialize a Row object from a JSON string.
 *
 * @param json the input JSON string.
 * @param r [output] the output Row structure.
 *
 * @return Status indicating the success or failure of the operation
 */
Status deserializeRowJSON(const std::string& json, Row& r);

/**
 * @brief The result set returned from a osquery SQL query
 *
 * QueryData is the canonical way to represent the results of SQL queries in
 * osquery. It's just a vector of Rows.
 */
using QueryData = std::vector<Row>;

/**
 * @brief Set representation result returned from a osquery SQL query
 *
 * QueryDataSet -  It's set of Rows for fast search of a specific row.
 */
using QueryDataSet = std::multiset<Row>;

/**
 * @brief Serialize a QueryData object into a JSON array.
 *
 * @param q the QueryData to serialize.
 * @param cols the TableColumn vector indicating column order.
 * @param doc the managed JSON document.
 * @param arr [output] the output JSON array.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeQueryData(const QueryData& q,
                          const ColumnNames& cols,
                          JSON& doc,
                          rapidjson::Document& arr);

/**
 * @brief Serialize a QueryData object into a JSON string.
 *
 * @param q the QueryData to serialize.
 * @param json [output] the output JSON string.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeQueryDataJSON(const QueryData& q, std::string& json);

/// Inverse of serializeQueryData, convert JSON to QueryData.
Status deserializeQueryData(const rapidjson::Value& arr, QueryData& qd);

/// Inverse of serializeQueryData, convert JSON to QueryDataSet.
Status deserializeQueryData(const rapidjson::Value& arr, QueryDataSet& qd);

/// Inverse of serializeQueryDataJSON, convert a JSON string to QueryData.
Status deserializeQueryDataJSON(const std::string& json, QueryData& qd);

/// Inverse of serializeQueryDataJSON, convert a JSON string to QueryDataSet.
Status deserializeQueryDataJSON(const std::string& json, QueryDataSet& qd);

/**
 * @brief Data structure representing the difference between the results of
 * two queries
 *
 * The representation of two diffed QueryData result sets. Given and old and
 * new QueryData, DiffResults indicates the "added" subset of rows and the
 * "removed" subset of rows.
 */
struct DiffResults : private only_movable {
 public:
  /// vector of added rows
  QueryData added;

  /// vector of removed rows
  QueryData removed;

  DiffResults() {}
  DiffResults(DiffResults&&) = default;
  DiffResults& operator=(DiffResults&&) = default;

  /// equals operator
  bool operator==(const DiffResults& comp) const {
    return (comp.added == added) && (comp.removed == removed);
  }

  /// not equals operator
  bool operator!=(const DiffResults& comp) const {
    return !(*this == comp);
  }
};

/**
 * @brief Serialize a DiffResults object into a JSON object.
 *
 * The object JSON will contain two new keys: added and removed.
 *
 * @param d the DiffResults to serialize.
 * @param cols the TableColumn vector indicating column order.
 * @param doc the managed JSON document.
 * @param obj [output] the output JSON object.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeDiffResults(const DiffResults& d,
                            const ColumnNames& cols,
                            JSON& doc,
                            rapidjson::Document& obj);

/**
 * @brief Serialize a DiffResults object into a JSON string.
 *
 * @param d the DiffResults to serialize.
 * @param json [output] the output JSON string.
 *
 * @return Status indicating the success or failure of the operation.
 */
Status serializeDiffResultsJSON(const DiffResults& d, std::string& json);

/**
 * @brief Diff QueryDataSet object and QueryData object
 *        and create a DiffResults object
 *
 * @param old_ the "old" set of results.
 * @param new_ the "new" set of results.
 *
 * @return a DiffResults object which indicates the change from old_ to new_
 *
 * @see DiffResults
 */
DiffResults diff(QueryDataSet& old_, QueryData& new_);

/**
 * @brief Add a Row to a QueryData if the Row hasn't appeared in the QueryData
 * already
 *
 * Note that this function will iterate through the QueryData list until a
 * given Row is found (or not found). This shouldn't be that significant of an
 * overhead for most use-cases, but it's worth keeping in mind before you use
 * this in it's current state.
 *
 * @param q the QueryData list to append to
 * @param r the Row to add to q
 *
 * @return true if the Row was added to the QueryData, false if it was not
 */
bool addUniqueRowToQueryData(QueryData& q, const Row& r);

/**
 * @brief Construct a new QueryData from an existing one, replacing all
 * non-ASCII characters with their \\u encoding.
 *
 * This function is intended as a workaround for
 * https://svn.boost.org/trac/boost/ticket/8883,
 * and will allow rows containing data with non-ASCII characters to be stored in
 * the database and parsed back into a JSON document.
 *
 * @param oldData the old QueryData to copy
 * @param newData the new escaped QueryData object
 */
void escapeQueryData(const QueryData& oldData, QueryData& newData);

/**
 * @brief performance statistics about a query
 */
struct QueryPerformance {
  /// Number of executions.
  size_t executions{0};

  /// Last UNIX time in seconds the query was executed successfully.
  size_t last_executed{0};

  /// Total wall time taken
  unsigned long long int wall_time{0};

  /// Total user time (cycles)
  unsigned long long int user_time{0};

  /// Total system time (cycles)
  unsigned long long int system_time{0};

  /// Average memory differentials. This should be near 0.
  unsigned long long int average_memory{0};

  /// Total characters, bytes, generated by query.
  unsigned long long int output_size{0};
};

/**
 * @brief Represents the relevant parameters of a scheduled query.
 *
 * Within the context of osqueryd, a scheduled query may have many relevant
 * attributes. Those attributes are represented in this data structure.
 */
struct ScheduledQuery : private only_movable {
 public:
  /// The SQL query.
  std::string query;

  /// How often the query should be executed, in second.
  size_t interval{0};

  /// A temporary splayed internal.
  size_t splayed_interval{0};

  /**
   * @brief Queries are blacklisted based on logic in the configuration.
   *
   * Most calls to inspect scheduled queries will abstract away the blacklisting
   * concept and only return non-blacklisted queries. The config may be asked
   * to return all queries, thus it is important to capture this optional data.
   */
  bool blacklisted{false};

  /// Set of query options.
  std::map<std::string, bool> options;

  ScheduledQuery() = default;
  ScheduledQuery(ScheduledQuery&&) = default;
  ScheduledQuery& operator=(ScheduledQuery&&) = default;

  /// equals operator
  bool operator==(const ScheduledQuery& comp) const {
    return (comp.query == query) && (comp.interval == interval);
  }

  /// not equals operator
  bool operator!=(const ScheduledQuery& comp) const {
    return !(*this == comp);
  }
};

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
  QueryData snapshot_results;

  /// The name of the scheduled query.
  std::string name;

  /// The identifier (hostname, or uuid) of the host.
  std::string identifier;

  /// The time that the query was executed, seconds as UNIX time.
  size_t time{0};

  /// The epoch at the time the query was executed
  uint64_t epoch{};

  /// Query execution counter for current epoch
  uint64_t counter{0};

  /// The time that the query was executed, an ASCII string.
  std::string calendar_time;

  /// A set of additional fields to emit with the log line.
  std::map<std::string, std::string> decorations;

  /// The ordered map of columns from the query.
  ColumnNames columns;

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

/// Inverse of serializeQueryLogItem, convert JSON to QueryLogItem.
Status deserializeQueryLogItem(const JSON& doc, QueryLogItem& item);

/// Inverse of serializeQueryLogItem, convert a JSON string to QueryLogItem.
Status deserializeQueryLogItemJSON(const std::string& json, QueryLogItem& item);

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
   * @param q a SheduledQuery struct.
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

  /**
   * @brief Add a new set of results to the persistent storage.
   *
   * Given the results of the execution of a scheduled query, add the results
   * to the database using addNewResults.
   *
   * @param qd the QueryData object, which has the results of the query.
   * @param epoch the epoch associated with QueryData
   * @param counter [output] the output that holds the query execution counter.
   *
   * @return the success or failure of the operation.
   */
  Status addNewResults(QueryData qd, uint64_t epoch, uint64_t& counter) const;

  /**
   * @brief Add a new set of results to the persistent storage and get back
   * the differential results.
   *
   * Given the results of an execution of a scheduled query, add the results
   * to the database using addNewResults and get back a data structure
   * indicating what rows in the query's results have changed.
   *
   * @param qd the QueryData object containing query results to store.
   * @param epoch the epoch associated with QueryData
   * @param counter the output that holds the query execution counter.
   * @param dr an output to a DiffResults object populated based on last run.
   * @param calculate_diff default true to populate dr.
   *
   * @return the success or failure of the operation.
   */
  Status addNewResults(QueryData qd,
                       uint64_t epoch,
                       uint64_t& counter,
                       DiffResults& dr,
                       bool calculate_diff = true) const;

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
