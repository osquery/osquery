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

#include <sqlite3.h>

namespace osquery {
/**
 * @brief A map of SQLite status codes to their corresponding message string
 *
 * Details of this map are defined at: http://www.sqlite.org/c3ref/c_abort.html
 */
extern const std::map<int, std::string> kSQLiteReturnCodes;

/// Internal (core) SQL implementation of the osquery query API.
Status queryInternal(const std::string& q, QueryData& results);

/**
 * @brief Execute a query on a specific database
 *
 * If you need to use a different database, other than the osquery default,
 * use this method and pass along a pointer to a SQLite3 database. This is
 * useful for testing.
 *
 * @param q the query to execute
 * @param results The QueryData struct to emit row on query success.
 * @param db the SQLite3 database to execute query q against
 *
 * @return A status indicating SQL query results.
 */
Status queryInternal(const std::string& q, QueryData& results, sqlite3* db);

/// Internal (core) SQL implementation of the osquery getQueryColumns API.
Status getQueryColumnsInternal(const std::string& q, tables::TableColumns& columns);

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
 * @param db the SQLite3 database to perform the analysis on
 *
 * @return status indicating success or failure of the operation
 */
Status getQueryColumnsInternal(const std::string& q,
                               tables::TableColumns& columns,
                               sqlite3* db);

/**
 * @brief Return a fully configured sqlite3 database object
 *
 * An osquery database is basically just a SQLite3 database with several
 * virtual tables attached. This method is the main abstraction for creating
 * SQLite3 databases within osquery.
 *
 * Note: osquery::initOsquery must be called before calling createDB in order
 * for virtual tables to be registered.
 *
 * @return a SQLite3 database with all virtual tables attached
 */
sqlite3* createDB();

/**
 * @brief Get a string representation of a SQLite return code
 */
std::string getStringForSQLiteReturnCode(int code);

// the callback for populating a std::vector<row> set of results. "argument"
// should be a non-const reference to a std::vector<row>
int queryDataCallback(void* argument, int argc, char* argv[], char* column[]);
}
