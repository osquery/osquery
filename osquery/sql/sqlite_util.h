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
#include <mutex>

#include <sqlite3.h>

#include <boost/thread/mutex.hpp>
#include <boost/noncopyable.hpp>

namespace osquery {

/**
 * @brief An RAII wrapper around an `sqlite3` object.
 *
 * The SQLiteDBInstance is also "smart" in that it may unlock access to a
 * managed `sqlite3` resource. If there's no contention then only a single
 * database is needed during the life of an osquery tool.
 *
 * If there is resource contention (multiple threads want access to the SQLite
 * abstraction layer), then the SQLiteDBManager will provide a transient
 * SQLiteDBInstance.
 */
class SQLiteDBInstance {
 public:
  SQLiteDBInstance();
  SQLiteDBInstance(sqlite3*& db);
  ~SQLiteDBInstance();

  /**
   * @brief Accessor to the internal `sqlite3` object, do not store references
   * to the object within osquery code.
   */
  sqlite3* db() { return db_; }

 private:
  bool primary_;
  sqlite3* db_;
};

/**
 * @brief osquery internal SQLite DB abstraction resource management.
 *
 * The SQLiteDBManager should be the ONLY method for accessing SQLite resources.
 * The manager provides an abstraction to manage internal SQLite memory and
 * resources as well as provide optimization around resource access.
 */
class SQLiteDBManager : private boost::noncopyable {
 public:
  static SQLiteDBManager& instance() {
    static SQLiteDBManager instance;
    return instance;
  }

  /**
   * @brief Return a fully configured `sqlite3` database object wrapper.
   *
   * An osquery database is basically just a SQLite3 database with several
   * virtual tables attached. This method is the main abstraction for accessing
   * SQLite3 databases within osquery.
   *
   * A RAII wrapper around the `sqlite3` database will manage attaching tables
   * and freeing resources when the instance (connection per-say) goes out of
   * scope. Using the SQLiteDBManager will also try to optimize the number of
   * `sqlite3` databases in use by managing a single global instance and
   * returning resource-safe transient databases if there's access contention.
   *
   * Note: osquery::initOsquery must be called before calling `get` in order
   * for virtual tables to be registered.
   *
   * @return a SQLiteDBInstance with all virtual tables attached.
   */
  static SQLiteDBInstance get();

  /// See `get` but always return a transient DB connection (for testing).
  static SQLiteDBInstance getUnique();

  /// When the primary SQLiteDBInstance is destructed it will unlock.
  static void unlock();

 protected:
  SQLiteDBManager() : db_(nullptr), lock_(mutex_, boost::defer_lock) {}
  SQLiteDBManager(SQLiteDBManager const&);
  void operator=(SQLiteDBManager const&);
  virtual ~SQLiteDBManager();

 private:
  /// Primary (managed) sqlite3 database.
  sqlite3* db_;
  /// Mutex and lock around sqlite3 access.
  boost::mutex mutex_;
  /// Mutex and lock around sqlite3 access.
  boost::unique_lock<boost::mutex> lock_;
};

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
 * @brief Get a string representation of a SQLite return code
 */
std::string getStringForSQLiteReturnCode(int code);

// the callback for populating a std::vector<row> set of results. "argument"
// should be a non-const reference to a std::vector<row>
int queryDataCallback(void* argument, int argc, char* argv[], char* column[]);
}
