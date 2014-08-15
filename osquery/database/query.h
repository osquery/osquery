// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_DATABASE_QUERY_H
#define OSQUERY_DATABASE_QUERY_H

#include <deque>
#include <memory>
#include <string>

#include <gtest/gtest_prod.h>

#include "osquery/config.h"
#include "osquery/database/db_handle.h"
#include "osquery/database/results.h"
#include "osquery/status.h"

namespace osquery {
namespace db {

// Error message used when a query name isn't found in the database
extern const std::string kQueryNameNotFoundError;

// Query is a class that is used to interact with the historical on-disk
// storage for a given query.
class Query {
 public:
  // Accepts a string which represents the query that one wants to receive a
  // column family object for.
  //
  // Given the query, the constructor calculates the value of columnFamily_,
  // which can be accessed via the getColumnFamilyName() getter method.
  explicit Query(osquery::config::OsqueryScheduledQuery q) : query_(q) {}

  /////////////////////////////////////////////////////////////////////////////
  // Getters and setters
  /////////////////////////////////////////////////////////////////////////////

  // getColumnFamilyName() returns the query_.name property.
  std::string getColumnFamilyName();

  // getQuery() returns the query_.query property.
  std::string getQuery();

  // getInterval() returns the query_.interval property
  int getInterval();

  /////////////////////////////////////////////////////////////////////////////
  // Data access methods
  /////////////////////////////////////////////////////////////////////////////

  // getHistoricalQueryResults() returns the entire historical query result
  // set for a given scheduled query
 public:
  osquery::Status getHistoricalQueryResults(HistoricalQueryResults& hQR);

 private:
  osquery::Status getHistoricalQueryResults(HistoricalQueryResults& hQR,
                                            std::shared_ptr<DBHandle> db);

  // getStoredQueryNames() returns a vector of strings which represents the
  // names of queries that are stored in the local store
 public:
  static std::vector<std::string> getStoredQueryNames();

 private:
  static std::vector<std::string> getStoredQueryNames(
      std::shared_ptr<DBHandle> db);

  // isQueryNameInDatabase returns true if the scheduled query being operated
  // on is already in the local store and false if it is not (ie: it would not
  // be in the local store if the query is new / has never been ran yet)
 public:
  bool isQueryNameInDatabase();

 private:
  bool isQueryNameInDatabase(std::shared_ptr<DBHandle> db);

  // getExecutions() returns a deque of timestamps of previous query
  // executions. These timestamp values are used as the RocksDB sub-keys which
  // represent the data stored as a result of those executions.
 public:
  osquery::Status getExecutions(std::deque<int>& results);

 private:
  osquery::Status getExecutions(std::deque<int>& results,
                                std::shared_ptr<DBHandle> db);

  // addNewResults adds a new result set to the local data store. If you
  // want the diff of the results you've just added, pass a reference to a
  // diffResults struct
 public:
  osquery::Status addNewResults(const osquery::db::QueryData& qd,
                                int unix_time);

 private:
  osquery::Status addNewResults(const osquery::db::QueryData& qd,
                                int unix_time,
                                std::shared_ptr<DBHandle> db);

 public:
  osquery::Status addNewResults(const osquery::db::QueryData& qd,
                                osquery::db::DiffResults& dr,
                                int unix_time);

 private:
  osquery::Status addNewResults(const osquery::db::QueryData& qd,
                                osquery::db::DiffResults& dr,
                                bool calculate_diff,
                                int unix_time,
                                std::shared_ptr<DBHandle> db);

  // getCurrentResults returns the most recent result set from the database
 public:
  osquery::Status getCurrentResults(osquery::db::QueryData& qd);

 private:
  osquery::Status getCurrentResults(osquery::db::QueryData& qd,
                                    std::shared_ptr<DBHandle> db);

 private:
  /////////////////////////////////////////////////////////////////////////////
  // Private members
  /////////////////////////////////////////////////////////////////////////////

  // query_ represents the scheduled query that Query is operating on
  osquery::config::OsqueryScheduledQuery query_;

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
}

#endif /* OSQUERY_DATABASE_QUERY_H */
