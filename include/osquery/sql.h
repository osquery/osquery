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

#include <map>
#include <string>
#include <vector>

#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/registry.h>
#include <osquery/tables.h>

namespace osquery {

DECLARE_int32(value_max);

/**
 * @brief An abstract similar to boost's noncopyable that defines moves.
 *
 * By defining protected move constructors we allow the children to assign
 * their's as default.
 */
class only_movable {
 protected:
  /// Boilerplate self default constructor.
  only_movable() {}

  /// Boilerplate self destructor.
  ~only_movable() {}

  /// Important, existance of a move constructor.
  only_movable(only_movable&&) {}

 private:
  /// Important, a private copy constructor prevents copying.
  only_movable(const only_movable&);

  /// Important, a private copy assignment constructor prevents copying.
  only_movable& operator=(const only_movable&);
};

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
   * @param q An osquery SQL query.
   */
  explicit SQL(const std::string& q);

  /// Allow moving.
  SQL(SQL&&) = default;

  /// Allow move assignment.
  SQL& operator=(SQL&&) = default;

 public:
  /**
   * @brief Accessor for the rows returned by the query.
   *
   * @return A QueryData object of the query results.
   */
  const QueryData& rows() const;

  /**
   * @brief Column information for the query
   *
   * @return A ColumnNames object for the query
   */
  const ColumnNames& columns();

  /**
   * @brief Accessor to switch off of when checking the success of a query.
   *
   * @return A bool indicating the success or failure of the operation.
   */
  bool ok();

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
  std::string getMessageString();

  /// ASCII escape the results of the query.
  void escapeResults();

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

 protected:
  /**
   * @brief Private default constructor.
   *
   * The osquery::SQL class should only ever be instantiated with a query.
   */
  SQL() {}

 protected:
  /// The internal member which holds the query string
  std::string q_;

  /// The internal member which holds the results of the query.
  QueryData results_;

  /// The internal member which holds the status of the query.
  Status status_;

  /// The internal member which holds the column names and order for the query
  ColumnNames columns_;
};

/**
 * @brief The osquery SQL implementation is managed as a plugin.
 *
 * The osquery RegistryFactory creates a Registry type called "sql", then
 * requires a single plugin registration also called "sql". Calls within
 * the application use boilerplate methods that wrap Registry::call%s to this
 * well-known registry and registry item name.
 *
 * Abstracting the SQL implementation behind the osquery registry allows
 * the SDK (libosquery) to describe how the SQL implementation is used without
 * having dependencies on the thrird-party code.
 *
 * When osqueryd/osqueryi are built libosquery_additional, the library which
 * provides the core plugins and core virtual tables, includes SQLite as
 * the SQL implementation.
 */
class SQLPlugin : public Plugin {
 public:
  /// Run a SQL query string against the SQL implementation.
  virtual Status query(const std::string& q, QueryData& results) const = 0;

  /// Use the SQL implementation to parse a query string and return details
  /// (name, type) about the columns.
  virtual Status getQueryColumns(const std::string& q,
                                 TableColumns& columns) const = 0;

  /**
   * @brief Attach a table at runtime.
   *
   * The SQL implementation plugin may need to manage how virtual tables are
   * attached at run time. In the case of SQLite where a single DB object is
   * managed, tables are enumerated and attached during initialization.
   */
  virtual Status attach(const std::string& name) {
    return Status(0, "Not used");
  }

  /// Tables may be detached by name.
  virtual void detach(const std::string& name) {}

 public:
  Status call(const PluginRequest& request, PluginResponse& response) override;
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
 * @param results A QueryData structure to emit result rows on success.
 * @return A status indicating query success.
 */
Status query(const std::string& query, QueryData& results);

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
}
