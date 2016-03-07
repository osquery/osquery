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

#include <memory>
#include <string>
#include <vector>

#include <osquery/database.h>
#include <osquery/status.h>

namespace osquery {

/// Error message used when a query name isn't found in the database
extern const std::string kQueryNameNotFoundError;

/**
 * @brief A class that is used to interact with the historical on-disk storage
 * for a given query.
 */
class Query {
 public:
  /**
   * @brief Constructor which sets up necessary parameters of a Query object
   *
   * Given a query, this constructor calculates the value of columnFamily_,
   * which can be accessed via the getColumnFamilyName getter method.
   *
   * @param q a SheduledQuery struct
   */
  explicit Query(const std::string& name, const ScheduledQuery& q)
      : query_(q), name_(name) {}

  /////////////////////////////////////////////////////////////////////////////
  // Data access methods
  /////////////////////////////////////////////////////////////////////////////

 public:
  /**
   * @brief Serialize the data in RocksDB into a useful data structure
   *
   * This method retrieves the data from RocksDB and returns the data in a
   * HistoricalQueryResults struct.
   *
   * @param hQR the output HistoricalQueryResults struct
   *
   * @return the success or failure of the operation
   */
  Status getPreviousQueryResults(QueryData& results);

 public:
  /**
   * @brief Get the names of all historical queries that are stored in RocksDB
   *
   * If you'd like to perform some database maintenance, getStoredQueryNames()
   * allows you to get a vector of the names of all queries which are
   * currently stored in RocksDB
   *
   * @return a vector containing the string names of all scheduled queries
   * which currently exist in the database
   */
  static std::vector<std::string> getStoredQueryNames();

 public:
  /**
   * @brief Accessor method for checking if a given scheduled query exists in
   * the database
   *
   * @return does the scheduled query which is already exists in the database
   */
  bool isQueryNameInDatabase();

 public:
  /**
   * @brief Add a new set of results to the persistant storage
   *
   * Given the results of the execution of a scheduled query, add the results
   * to the database using addNewResults
   *
   * @param qd the QueryData object, which has the results of the query which
   * you would like to store
   * @param unix_time the time that the query was executed
   *
   * @return an instance of osquery::Status indicating the success or failure
   * of the operation
   */
  Status addNewResults(const QueryData& qd);

 public:
  /**
   * @brief Add a new set of results to the persistent storage and get back
   * the differential results.
   *
   * Given the results of an execution of a scheduled query, add the results
   * to the database using addNewResults and get back a data structure
   * indicating what rows in the query's results have changed.
   *
   * @param qd the QueryData object containing query results to store
   * @param dr an output to a DiffResults object populated based on last run
   *
   * @return the success or failure of the operation
   */
  Status addNewResults(const QueryData& qd, DiffResults& dr);

 private:
  /**
   * @brief Add a new set of results to the persistent storage and get back
   * the differential results, using a custom database handle.
   *
   * This method is the same as Query::addNewResults, but with the addition of a
   * parameter which allows you to pass a custom RocksDB database handle
   *
   * @param qd the QueryData object containing query results to store
   * @param dr an output to a DiffResults object populated based on last run
   *
   * @return the success or failure of the operation
   */
  Status addNewResults(const QueryData& qd,
                       DiffResults& dr,
                       bool calculate_diff);

 public:
  /**
   * @brief A getter for the most recent result set for a scheduled query
   *
   * @param qd the output QueryData object
   *
   * @return the success or failure of the operation
   */
  Status getCurrentResults(QueryData& qd);

 private:
  /////////////////////////////////////////////////////////////////////////////
  // Private members
  /////////////////////////////////////////////////////////////////////////////

  /// The scheduled query and internal
  ScheduledQuery query_;

  /// The scheduled query name.
  std::string name_;

 private:
  /////////////////////////////////////////////////////////////////////////////
  // Unit tests which can access private members
  /////////////////////////////////////////////////////////////////////////////

  FRIEND_TEST(QueryTests, test_private_members);
  FRIEND_TEST(QueryTests, test_add_and_get_current_results);
  FRIEND_TEST(QueryTests, test_is_query_name_in_database);
  FRIEND_TEST(QueryTests, test_get_stored_query_names);
  FRIEND_TEST(QueryTests, test_get_executions);
  FRIEND_TEST(QueryTests, test_get_query_results);
  FRIEND_TEST(QueryTests, test_query_name_not_found_in_db);
};
}
