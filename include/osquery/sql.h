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

#include <map>
#include <string>
#include <vector>

#include <osquery/database/results.h>
#include <osquery/tables.h>

namespace osquery {
/**
 * @brief The core interface to executing osquery SQL commands
 *
 * @code{.cpp}
 *   auto sql = SQL("SELECT * FROM time");
 *   if (sql.ok()) {
 *     LOG(INFO) << "============================";
 *     for (const auto& row : sql.rows()) {
 *       for (const auto& it : row) {
 *         LOG(INFO) << it.first << " => " << it.second;
 *       }
 *       LOG(INFO) << "============================";
 *     }
 *   } else {
 *     LOG(ERROR) << sql.getMessageString();
 *   }
 * @endcode
 */
class SQL {
 public:
  /**
   * @brief Instantiate an instance of the class with a query
   *
   * @param q An osquery SQL query
   */
  explicit SQL(const std::string& q);

  /**
   * @brief Accessor for the rows returned by the query
   *
   * @return A QueryData object of the query results
   */
  const QueryData& rows();

  /**
   * @brief Accessor to switch off of when checking the success of a query
   *
   * @return A bool indicating the success or failure of the operation
   */
  bool ok();

  /**
   * @brief Get the status returned by the query
   *
   * @return The query status
   */
  Status getStatus();

  /**
   * @brief Accessor for the message string indicating the status of the query
   *
   * @return The message string indicating the status of the query
   */
  std::string getMessageString();

  /**
   * @brief Add host info columns onto existing QueryData
   *
   * Use this to add columns providing host info to the query results.
   * Distributed queries use this to add host information before returning
   * results to the aggregator.
   */
  void annotateHostInfo();

  /**
   * @brief Accessor for the list of queryable tables
   *
   * @return A vector of table names
   */
  static std::vector<std::string> getTableNames();

  /**
   * @brief Get all, 'SELECT * ...', results given a virtual table name.
   *
   * @param table The name of the virtual table.
   * @return A QueryData object of the 'SELECT *...' query results.
   */
  static QueryData selectAllFrom(const std::string& table);

  /**
   * @brief Get all with constraint, 'SELECT * ... where', results given
   * a virtual table name and single constraint
   *
   * @param table The name of the virtual table.
   * @param column Table column name to apply constraint.
   * @param op The SQL comparitive operator.
   * @param expr The constraint expression.
   * @return A QueryData object of the 'SELECT *...' query results.
   */
  static QueryData selectAllFrom(const std::string& table,
                                 const std::string& column,
                                 tables::ConstraintOperator op,
                                 const std::string& expr);

 protected:
  /**
   * @brief Private default constructor
   *
   * The osquery::SQL class should only ever be instantiated with a query
   */
  SQL(){};

  // The key used to store hostname for annotateHostInfo
  static const std::string kHostColumnName;

  /// the internal member which holds the results of the query
  QueryData results_;

  /// the internal member which holds the status of the query
  Status status_;
};

class SQLPlugin : public Plugin {
 public:
  virtual Status query(const std::string& q, QueryData& results) const = 0;
  virtual Status getQueryColumns(const std::string& q,
                                 tables::TableColumns& columns) const = 0;

 public:
  Status call(const PluginRequest& request, PluginResponse& response);
};

/**
 * @brief Execute a query
 *
 * This is a lower-level version of osquery::SQL. Prefer to use osquery::SQL.
 *
 * @code{.cpp}
 *   std::string q = "SELECT * FROM time;";
 *   QueryData results;
 *   auto status = query(q, results);
 *   if (status.ok()) {
 *     for (const auto& each : results) {
 *       for (const auto& it : each) {
 *         LOG(INFO) << it.first << ": " << it.second;
 *       }
 *     }
 *   } else {
 *     LOG(ERROR) << "Error: " << status.what();
 *   }
 * @endcode
 *
 * @param q the query to execute
 * @param results A QueryData structure to emit result rows on success.
 * @return A status indicating query success.
 */
Status query(const std::string& query, QueryData& results);

/**
 * @brief Analyze a query, providing information about the result columns
 *
 * This function asks SQLite to determine what the names and types are of the
 * result columns of the provided query. Only table columns (not expressions or
 * subqueries) can have their types determined. Types that are not determined
 * are indicated with the string "UNKNOWN".
 *
 * @param q the query to analyze
 * @param columns the vector to fill with column information
 *
 * @return status indicating success or failure of the operation
 */
Status getQueryColumns(const std::string& q, tables::TableColumns& columns);

/*
 * @brief A mocked subclass of SQL useful for testing
 */
class MockSQL : public SQL {
 public:
  explicit MockSQL() : MockSQL(QueryData{}) {}
  explicit MockSQL(const QueryData& results) : MockSQL(results, Status()) {}
  explicit MockSQL(const QueryData& results, const Status& status) {
    results_ = results;
    status_ = status;
  }
};

CREATE_REGISTRY(SQLPlugin, "sql");
}
