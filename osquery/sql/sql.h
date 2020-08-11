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
#include <string>
#include <vector>

#include <osquery/core/flags.h>
#include <osquery/core/query.h>
#include <osquery/core/tables.h>

namespace osquery {

/**
 * @brief The core interface to executing osquery SQL commands.
 *
 * @code{.cpp}
 *   SQL sql("SELECT * FROM time");
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
class SQL : private only_movable {
 public:
  /**
   * @brief Instantiate an instance of the class with a query.
   *
   * @param query An osquery SQL query.
   * @param use_cache [optional] Set true to use the query cache.
   */
  explicit SQL(const std::string& query, bool use_cache = false);

  /// Allow moving.
  SQL(SQL&&) noexcept = default;

  /// Allow move assignment.
  SQL& operator=(SQL&&) = default;

 public:
  /**
   * @brief Const accessor for the rows returned by the query.
   *
   * @return A QueryData object of the query results.
   */
  const QueryData& rows() const;

  /**
   * @brief Accessor for the rows returned by the query.
   *
   * @return A QueryData object of the query results.
   */
  QueryData& rows();

  /**
   * @brief Column information for the query
   *
   * @return A ColumnNames object for the query
   */
  const ColumnNames& columns() const;

  /**
   * @brief Accessor to switch off of when checking the success of a query.
   *
   * @return A bool indicating the success or failure of the operation.
   */
  bool ok() const;

  /**
   * @brief Get the status returned by the query.
   *
   * @return The query status.
   */
  const Status& getStatus() const;

  /**
   * @brief Accessor for the message string indicating the status of the query.
   *
   * @return The message string indicating the status of the query.
   */
  std::string getMessageString() const;

 public:
  /**
   * @brief Get all, 'SELECT * ...', results given a virtual table name.
   *
   * @param table The name of the virtual table.
   * @return A QueryData object of the 'SELECT *...' query results.
   */
  static QueryData selectAllFrom(const std::string& table);

  /**
   * @brief Get all with constraint, 'SELECT * ... where', results given
   * a virtual table name and single constraint.
   *
   * @param table The name of the virtual table.
   * @param column Table column name to apply constraint.
   * @param op The SQL comparative operator.
   * @param expr The constraint expression.
   * @return A QueryData object of the 'SELECT *...' query results.
   */
  static QueryData selectAllFrom(const std::string& table,
                                 const std::string& column,
                                 ConstraintOperator op,
                                 const std::string& expr);

  /**
   * @brief Get columns with constraint, 'SELECT [columns] ... where', results
   * given a virtual table name, column names, and single constraint.
   *
   * @param columns the columns to return
   * @param table The name of the virtual table.
   * @param column Table column name to apply constraint.
   * @param op The SQL comparative operator.
   * @param expr The constraint expression.
   * @return A QueryData object of the 'SELECT [columns] ...' query results.
   */
  static QueryData selectFrom(const std::initializer_list<std::string>& columns,
                              const std::string& table,
                              const std::string& column,
                              ConstraintOperator op,
                              const std::string& expr);

 protected:
  /**
   * @brief Private default constructor.
   *
   * The osquery::SQL class should only ever be instantiated with a query.
   */
  SQL() = default;

 protected:
  /// The internal member which holds the results of the query.
  QueryData results_;

  /// The internal member which holds the status of the query.
  Status status_;

  /// The internal member which holds the column names and order for the query
  ColumnNames columns_;
};

/**
 * @brief Execute a query.
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
 * @param query the query to execute
 * @param results [output] A QueryData structure to emit result rows on success.
 * @param use_cache [optional] Set true to use the query cache.
 * @return A status indicating query success.
 */
Status query(const std::string& query,
             QueryData& results,
             bool use_cache = false);

/**
 * @brief Analyze a query, providing information about the result columns.
 *
 * This function asks SQLite to determine what the names and types are of the
 * result columns of the provided query. Only table columns (not expressions or
 * subqueries) can have their types determined. Types that are not determined
 * are indicated with the string "UNKNOWN".
 *
 * @param q the query to analyze.
 * @param columns the vector to fill with column information.
 *
 * @return status indicating success or failure of the operation.
 */
Status getQueryColumns(const std::string& q, TableColumns& columns);

/**
 * @brief Extract table names from an input query.
 *
 * This should return the scanned virtual tables, not aliases or intermediate
 * tables, from a given query.
 *
 * @param q the query to analyze.
 * @param tables the output vector to fill with table names.
 *
 * @return status indicating success or failure of the operation.
 */
Status getQueryTables(const std::string& q, std::vector<std::string>& tables);
} // namespace osquery
