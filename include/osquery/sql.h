// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <map>
#include <string>
#include <vector>

#include "osquery/database/results.h"

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

 private:
  /**
   * @brief Private default constructor
   *
   * The osquery::SQL class should only ever be instantiated with a query
   */
  SQL() {};

 private:
  /// the internal member which holds the results of the query
  QueryData results_;

  /// the internal member which holds the status of the query
  Status status_;
};
}
