// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <deque>
#include <memory>
#include <string>

#include <gtest/gtest_prod.h>

#include "osquery/config.h"
#include "osquery/database/db_handle.h"
#include "osquery/database/results.h"
#include "osquery/status.h"

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
   * @param q an OsqueryScheduledQuery struct which represents the query which
   * you would like to interact with
   */
  explicit Query(osquery::OsqueryScheduledQuery q) : query_(q) {}

  /////////////////////////////////////////////////////////////////////////////
  // Getters and setters
  /////////////////////////////////////////////////////////////////////////////

  /**
   * @brief Getter for the name of a given scheduled query
   *
   * @return the name of the scheduled query which is being operated on
   */
  std::string getQueryName();

  /**
   * @brief Getter for the SQL query of a scheduled query
   *
   * @return the SQL of the scheduled query which is being operated on
   */
  std::string getQuery();

  /**
   * @brief Getter for the interval of a scheduled query
   *
   * @return the interval of the scheduled query which is being operated on
   */
  int getInterval();

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
   * @param hQR a reference to a HistoricalQueryResults struct which will be
   * populated with results if the osquery::Status indicates the operation was
   * successful
   *
   * @return an instance of osquery::Status indicating the success or failure
   * of the operation
   */
  osquery::Status getHistoricalQueryResults(HistoricalQueryResults& hQR);

 private:
  /**
   * @brief Serialize the data in RocksDB into a useful data structure using a
   * custom database handle
   *
   * This method is the same as getHistoricalQueryResults(), but with the
   * addition of a parameter which allows you to pass a custom RocksDB
   * database handle. This version of getHistoricalQueryResults should only be
   * used internally and by unit tests.
   *
   * @param hQR a reference to a HistoricalQueryResults struct which will be
   * populated with results if the osquery::Status indicates the operation was
   * successful @param db the RocksDB database handle to use to acquire the
   * relevant data
   *
   * @param db a shared pointer to a custom DBHandle
   *
   * @return an instance of osquery::Status indicating the success or failure
   * of the operation
   *
   * @see getHistoricalQueryResults
   */
  osquery::Status getHistoricalQueryResults(HistoricalQueryResults& hQR,
                                            std::shared_ptr<DBHandle> db);

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

 private:
  /**
   * @brief Get the names of all historical queries that are stored in RocksDB
   * using a custom database handle
   *
   * This method is the same as getStoredQueryNames(), but with the addition
   * of a parameter which allows you to pass a custom RocksDB database handle.
   *
   * @param db a custom RocksDB database handle
   *
   * @return a vector containing the string names of all scheduled queries
   * which currently exist in the database
   *
   * @see getStoredQueryNames()
   */
  static std::vector<std::string> getStoredQueryNames(
      std::shared_ptr<DBHandle> db);

 public:
  /**
   * @brief Accessor method for checking if a given scheduled query exists in
   * the database
   *
   * @return a boolean indicating whether or not the scheduled query which is
   * being operated on already exists in the database
   */
  bool isQueryNameInDatabase();

 private:
  /**
   * @brief Accessor method for checking if a given scheduled query exists in
   * the database, using a custom database handle
   *
   * This method is the same as isQueryNameInDatabase(), but with the addition
   * of a parameter which allows you to pass a custom RocksDB database handle
   *
   * @param db a custom RocksDB database handle
   *
   * @return a boolean indicating whether or not the scheduled query which is
   * being operated on already exists in the database
   */
  bool isQueryNameInDatabase(std::shared_ptr<DBHandle> db);

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
  osquery::Status addNewResults(const osquery::QueryData& qd, int unix_time);

 private:
  /**
   * @brief Add a new set of results to the persistant storage using a custom
   * database handle
   *
   * This method is the same as addNewResults(), but with the addition of a
   * parameter which allows you to pass a custom RocksDB database handle
   *
   * @param qd the QueryData object, which has the results of the query which
   * you would like to store
   * @param unix_time the time that the query was executed
   * @param db a custom RocksDB database handle
   *
   * @return an instance of osquery::Status indicating the success or failure
   * of the operation
   */
  osquery::Status addNewResults(const osquery::QueryData& qd,
                                int unix_time,
                                std::shared_ptr<DBHandle> db);

 public:
  /**
   * @brief Add a new set of results to the persistant storage and get back
   * the diff results.
   *
   * Given the results of the execution of a scheduled query, add the results
   * to the database using addNewResults and get back a data structure
   * indicating what rows in the query's results have changed.
   *
   * @param qd the QueryData object, which has the results of the query which
   * you would like to store
   * @param dr a reference to a DiffResults object, which will be populated
   * with the difference of the execution which is currently in the database
   * and the execution you just put in the database
   * @param unix_time the time that the query was executed
   *
   * @return an instance of osquery::Status indicating the success or failure
   * of the operation
   */
  osquery::Status addNewResults(const osquery::QueryData& qd,
                                osquery::DiffResults& dr,
                                int unix_time);

 private:
  /**
   * @brief Add a new set of results to the persistant storage and get back
   * the diff results, using a custom database handle.
   *
   * This method is the same as addNewResults(), but with the addition of a
   * parameter which allows you to pass a custom RocksDB database handle
   *
   * @param qd the QueryData object, which has the results of the query which
   * you would like to store
   * @param dr a reference to a DiffResults object, which will be populated
   * with the difference of the execution which is currently in the database
   * and the execution you just put in the database
   * @param calculate_diff a boolean indicating whether or not you'd like to
   * calculate the diff result to be stored in the dr parameter.
   * @param unix_time the time that the query was executed
   *
   * @return an instance of osquery::Status indicating the success or failure
   * of the operation
   */
  osquery::Status addNewResults(const osquery::QueryData& qd,
                                osquery::DiffResults& dr,
                                bool calculate_diff,
                                int unix_time,
                                std::shared_ptr<DBHandle> db);

 public:
  /**
   * @brief A getter for the most recent result set for a scheduled query
   *
   * @param qd the QueryData object which will be populated if all operations
   * are successful
   *
   * @return an instance of osquery::Status indicating the success or failure
   * of the operation
   */
  osquery::Status getCurrentResults(osquery::QueryData& qd);

 private:
  /**
   * @brief A getter for the most recent result set for a scheduled query,
   * but with the addition of a parameter which allows you to pass a custom
   * RocksDB database handle
   *
   * This method is the same as getCurrentResults(), but with addition of a
   * parameter which allows you to pass a custom RocksDB database handle
   *
   * @param qd the QueryData object which will be populated if all operations
   * are successful
   * @param db a custom RocksDB database handle
   *
   * @return an instance of osquery::Status indicating the success or failure
   * of the operation
   */
  osquery::Status getCurrentResults(osquery::QueryData& qd,
                                    std::shared_ptr<DBHandle> db);

 private:
  /////////////////////////////////////////////////////////////////////////////
  // Private members
  /////////////////////////////////////////////////////////////////////////////

  /// The scheduled query that Query is operating on
  osquery::OsqueryScheduledQuery query_;

 private:
  /////////////////////////////////////////////////////////////////////////////
  // Unit tests which can access private members
  /////////////////////////////////////////////////////////////////////////////

  FRIEND_TEST(QueryTests, test_private_members);
  FRIEND_TEST(QueryTests, test_add_and_get_current_results);
  FRIEND_TEST(QueryTests, test_is_query_name_in_database);
  FRIEND_TEST(QueryTests, test_get_stored_query_names);
  FRIEND_TEST(QueryTests, test_get_executions);
  FRIEND_TEST(QueryTests, test_get_current_results);
  FRIEND_TEST(QueryTests, test_get_historical_query_results);
  FRIEND_TEST(QueryTests, test_query_name_not_found_in_db);
};
}
