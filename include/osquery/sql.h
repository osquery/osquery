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
 * @brief A map of SQLite status codes to their corresponding message string
 *
 * Details of this map are defined at: http://www.sqlite.org/c3ref/c_abort.html
 */
extern const std::map<int, std::string> kSQLiteReturnCodes;

/**
 * @brief Get a string representation of a SQLite return code
 */
std::string getStringForSQLiteReturnCode(int code);

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
  QueryData rows();

  /**
   * @brief Accessor to switch off of when checking the success of a query
   *
   * @return A bool indicating the success or failure of the operation
   */
  bool ok();

  /**
   * @brief Accessor for the message string indicating the status of the query
   *
   * @return The message string indicating the status of the query
   */
  std::string getMessageString();

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

 private:
  /**
   * @brief Private default constructor
   *
   * The osquery::SQL class should only ever be instantiated with a query
   */
  SQL(){};

 private:
  /// the internal member which holds the results of the query
  QueryData results_;

  /// the internal member which holds the status of the query
  Status status_;
};
}
