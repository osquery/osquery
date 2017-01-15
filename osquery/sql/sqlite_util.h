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

#include <atomic>
#include <map>
#include <mutex>
#include <unordered_set>

#include <sqlite3.h>

#include <boost/noncopyable.hpp>

#include <osquery/sql.h>

#define SQLITE_SOFT_HEAP_LIMIT (5 * 1024 * 1024)

namespace osquery {

class SQLiteDBManager;

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
class SQLiteDBInstance : private boost::noncopyable {
 public:
  SQLiteDBInstance() {
    init();
  }
  SQLiteDBInstance(sqlite3*& db, Mutex& mtx);
  ~SQLiteDBInstance();

  /// Check if the instance is the osquery primary.
  bool isPrimary() const {
    return primary_;
  }

  /// Generate a new 'transient' connection.
  void init();

  /**
   * @brief Accessor to the internal `sqlite3` object, do not store references
   * to the object within osquery code.
   */
  sqlite3* db() const {
    return db_;
  }

  /// Allow a virtual table implementation to record use/access of a table.
  void addAffectedTable(VirtualTableContent* table);

  /// Clear per-query state of a table affected by the use of this instance.
  void clearAffectedTables();

 private:
  /// Handle the primary/forwarding requests for table attribute accesses.
  TableAttributes getAttributes() const;

 private:
  /// An opaque constructor only used by the DBManager.
  explicit SQLiteDBInstance(sqlite3* db)
      : primary_(true), managed_(true), db_(db) {}

 private:
  /// Introspection into the database pointer, primary means managed.
  bool primary_{false};

  /// Track whether this instance is managed internally by the DB manager.
  bool managed_{false};

  /// Either the managed primary database or an ephemeral instance.
  sqlite3* db_{nullptr};

  /// An attempted unique lock on the manager's primary database access mutex.
  WriteLock lock_;

  /// Vector of tables that need their constraints cleared after execution.
  std::map<std::string, VirtualTableContent*> affected_tables_;

 private:
  friend class SQLiteDBManager;
  friend class SQLInternal;

 private:
  FRIEND_TEST(SQLiteUtilTests, test_affected_tables);
};

using SQLiteDBInstanceRef = std::shared_ptr<SQLiteDBInstance>;

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
  static SQLiteDBInstanceRef get() {
    return getConnection();
  }

  /// See `get` but always return a transient DB connection (for testing).
  static SQLiteDBInstanceRef getUnique();

  /**
   * @brief Check if `table_name` is disabled.
   *
   * Check if `table_name` is in the list of tables passed in to the
   * `--disable_tables` flag.
   *
   * @param The name of the Table to check.
   * @return If `table_name` is disabled.
   */
  static bool isDisabled(const std::string& table_name);

 protected:
  SQLiteDBManager();
  virtual ~SQLiteDBManager();

 public:
  SQLiteDBManager(SQLiteDBManager const&) = delete;
  SQLiteDBManager& operator=(SQLiteDBManager const&) = delete;

 private:
  /// Primary (managed) sqlite3 database.
  sqlite3* db_{nullptr};

  /// The primary connection maintains an opaque instance.
  SQLiteDBInstanceRef connection_{nullptr};

  /// Mutex and lock around sqlite3 access.
  Mutex mutex_;

  /// A write mutex for initializing the primary database.
  Mutex create_mutex_;

  /// Member variable to hold set of disabled tables.
  std::unordered_set<std::string> disabled_tables_;

  /// Parse a comma-delimited set of tables names, passed in as a flag.
  void setDisabledTables(const std::string& s);

  /// Request a connection, optionally request the primary connection.
  static SQLiteDBInstanceRef getConnection(bool primary = false);

 private:
  friend class SQLiteDBInstance;
  friend class SQLiteSQLPlugin;
};

/**
 * @brief A barebones query planner based on SQLite explain statement results.
 *
 * The query planner issues two EXPLAIN queries to the internal SQLite instance
 * to determine a table scan plan and execution program.
 *
 * It is mildly expensive to run a query planner since most data is TEXT type
 * and requires string tokenization and lexical casting. Only run a planner
 * once per new query and only when needed (aka an unusable expression).
 */
class QueryPlanner : private boost::noncopyable {
 public:
  explicit QueryPlanner(const std::string& query)
      : QueryPlanner(query, SQLiteDBManager::get()->db()) {}
  QueryPlanner(const std::string& query, sqlite3* db);
  ~QueryPlanner() {}

 public:
  /**
   * @brief Scan the plan and program for opcodes that infer types.
   *
   * This allows column type inference based on column expressions. The query
   * column introspection may use a QueryPlanner to apply types to the unknown
   * columns (which are usually expressions).
   *
   * @param column an ordered set of columns to fill in type information.
   * @return success if all columns types were found, otherwise false.
   */
  Status applyTypes(TableColumns& columns);

  /**
   * @brief A helper structure to represent an opcode's result and type.
   *
   * An opcode can be defined by a register and type, for the sake of the
   * only known use case of resultant type determination.
   */
  struct Opcode {
    enum Register {
      P1 = 0,
      P2,
      P3,
    };

    Register reg;
    ColumnType type;

   public:
    Opcode(Register r, ColumnType t) : reg(r), type(t) {}

    /// Return a register as its column string name.
    static std::string regString(Register r) {
      static std::vector<std::string> regs = {"p1", "p2", "p3"};
      return regs[r];
    }
  };

 private:
  /// The results of EXPLAIN q.
  QueryData program_;
  /// The order of tables scanned.
  std::vector<std::string> tables_;
};

/// Specific SQLite opcodes that change column/expression type.
extern const std::map<std::string, QueryPlanner::Opcode> kSQLOpcodes;

/**
 * @brief SQLite Internal: Execute a query on a specific database
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

/**
 * @brief SQLite Intern: Analyze a query, providing information about the
 * result columns
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
                               TableColumns& columns,
                               sqlite3* db);

/**
 * @brief SQLInternal: SQL, but backed by internal calls.
 */
class SQLInternal : public SQL {
 public:
  /**
   * @brief Instantiate an instance of the class with an internal query.
   *
   * @param q An osquery SQL query.
   */
  explicit SQLInternal(const std::string& q);

 public:
  /**
   * @brief Check if the SQL query's results use event-based tables.
   *
   * Higher level SQL facilities, like the scheduler, may act differently when
   * the results of a query (including a JOIN) are event-based. For example,
   * it does not make sense to perform set difference checks for an
   * always-append result set.
   *
   * All the tables used in the query will be checked. The TableAttributes of
   * each will be ORed and if any include EVENT_BASED, this will return true.
   */
  bool eventBased() const {
    return event_based_;
  }

 private:
  /// Before completing the execution, store a check for EVENT_BASED.
  bool event_based_{false};
};

/**
 * @brief Get a string representation of a SQLite return code.
 */
std::string getStringForSQLiteReturnCode(int code);

/**
 * @brief Accumulate rows from an SQLite exec into a QueryData struct.
 *
 * The callback for populating a std::vector<Row> set of results. "argument"
 * should be a non-const reference to a std::vector<Row>.
 */
int queryDataCallback(void* argument, int argc, char* argv[], char* column[]);

/**
 * @brief Register math-related 'custom' functions.
 */
void registerMathExtensions(sqlite3* db);

/**
 * @brief Register string-related 'custom' functions.
 */
void registerStringExtensions(sqlite3* db);
}
