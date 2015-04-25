/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/sql/sqlite_util.h"
#include "osquery/sql/virtual_table.h"

namespace osquery {
/// SQL provider for osquery internal/core.
REGISTER_INTERNAL(SQLiteSQLPlugin, "sql", "sql");

/**
 * @brief A map of SQLite status codes to their corresponding message string
 *
 * Details of this map are defined at: http://www.sqlite.org/c3ref/c_abort.html
 */
const std::map<int, std::string> kSQLiteReturnCodes = {
    {0, "SQLITE_OK: Successful result"},
    {1, "SQLITE_ERROR: SQL error or missing database"},
    {2, "SQLITE_INTERNAL: Internal logic error in SQLite"},
    {3, "SQLITE_PERM: Access permission denied"},
    {4, "SQLITE_ABORT: Callback routine requested an abort"},
    {5, "SQLITE_BUSY: The database file is locked"},
    {6, "SQLITE_LOCKED: A table in the database is locked"},
    {7, "SQLITE_NOMEM: A malloc() failed"},
    {8, "SQLITE_READONLY: Attempt to write a readonly database"},
    {9, "SQLITE_INTERRUPT: Operation terminated by sqlite3_interrupt()"},
    {10, "SQLITE_IOERR: Some kind of disk I/O error occurred"},
    {11, "SQLITE_CORRUPT: The database disk image is malformed"},
    {12, "SQLITE_NOTFOUND: Unknown opcode in sqlite3_file_control()"},
    {13, "SQLITE_FULL: Insertion failed because database is full"},
    {14, "SQLITE_CANTOPEN: Unable to open the database file"},
    {15, "SQLITE_PROTOCOL: Database lock protocol error"},
    {16, "SQLITE_EMPTY: Database is empty"},
    {17, "SQLITE_SCHEMA: The database schema changed"},
    {18, "SQLITE_TOOBIG: String or BLOB exceeds size limit"},
    {19, "SQLITE_CONSTRAINT: Abort due to constraint violation"},
    {20, "SQLITE_MISMATCH: Data type mismatch"},
    {21, "SQLITE_MISUSE: Library used incorrectly"},
    {22, "SQLITE_NOLFS: Uses OS features not supported on host"},
    {23, "SQLITE_AUTH: Authorization denied"},
    {24, "SQLITE_FORMAT: Auxiliary database format error"},
    {25, "SQLITE_RANGE: 2nd parameter to sqlite3_bind out of range"},
    {26, "SQLITE_NOTADB: File opened that is not a database file"},
    {27, "SQLITE_NOTICE: Notifications from sqlite3_log()"},
    {28, "SQLITE_WARNING: Warnings from sqlite3_log()"},
    {100, "SQLITE_ROW: sqlite3_step() has another row ready"},
    {101, "SQLITE_DONE: sqlite3_step() has finished executing"},
};

std::string getStringForSQLiteReturnCode(int code) {
  if (kSQLiteReturnCodes.find(code) != kSQLiteReturnCodes.end()) {
    return kSQLiteReturnCodes.at(code);
  } else {
    std::ostringstream s;
    s << "Error: " << code << " is not a valid SQLite result code";
    return s.str();
  }
}

Status SQLiteSQLPlugin::attach(const std::string& name) {
  // This may be the managed DB, or a transient.
  auto dbc = SQLiteDBManager::get();
  if (!dbc.isPrimary()) {
    // Do not "reattach" to transient instance.
    return Status(0, "OK");
  }

  PluginResponse response;
  auto status =
      Registry::call("table", name, {{"action", "columns"}}, response);
  if (!status.ok()) {
    return status;
  }

  auto statement = tables::columnDefinition(response);
  return tables::attachTableInternal(name, statement, dbc.db());
}

void SQLiteSQLPlugin::detach(const std::string& name) {
  auto dbc = SQLiteDBManager::get();
  if (!dbc.isPrimary()) {
    return;
  }
  tables::detachTableInternal(name, dbc.db());
}

SQLiteDBInstance::SQLiteDBInstance() {
  primary_ = false;
  sqlite3_open(":memory:", &db_);
  tables::attachVirtualTables(db_);
}

SQLiteDBInstance::SQLiteDBInstance(sqlite3*& db) {
  primary_ = true;
  db_ = db;
}

SQLiteDBInstance::~SQLiteDBInstance() {
  if (!primary_) {
    sqlite3_close(db_);
  } else {
    SQLiteDBManager::unlock();
    db_ = nullptr;
  }
}

void SQLiteDBManager::unlock() { instance().lock_.unlock(); }

SQLiteDBInstance SQLiteDBManager::getUnique() { return SQLiteDBInstance(); }

SQLiteDBInstance SQLiteDBManager::get() {
  auto& self = instance();

  if (!self.lock_.owns_lock() && self.lock_.try_lock()) {
    if (self.db_ == nullptr) {
      // Create primary sqlite DB instance.
      sqlite3_open(":memory:", &self.db_);
      tables::attachVirtualTables(self.db_);
    }
    return SQLiteDBInstance(self.db_);
  } else {
    // If this thread or another has the lock, return a transient db.
    VLOG(1) << "DBManager contention: opening transient SQLite database";
    return SQLiteDBInstance();
  }
}

SQLiteDBManager::~SQLiteDBManager() {
  if (db_ != nullptr) {
    sqlite3_close(db_);
    db_ = nullptr;
  }
}

int queryDataCallback(void* argument, int argc, char* argv[], char* column[]) {
  if (argument == nullptr) {
    LOG(ERROR) << "queryDataCallback received nullptr as data argument";
    return SQLITE_MISUSE;
  }

  QueryData* qData = (QueryData*)argument;
  Row r;
  for (int i = 0; i < argc; i++) {
    if (column[i] != nullptr) {
      r[column[i]] = (argv[i] != nullptr) ? argv[i] : "";
    }
  }
  (*qData).push_back(r);
  return 0;
}

Status queryInternal(const std::string& q, QueryData& results, sqlite3* db) {
  char* err = nullptr;
  sqlite3_exec(db, q.c_str(), queryDataCallback, &results, &err);
  if (err != nullptr) {
    sqlite3_free(err);
    return Status(1, "Error running query: " + q);
  }

  return Status(0, "OK");
}

Status getQueryColumnsInternal(const std::string& q,
                               tables::TableColumns& columns,
                               sqlite3* db) {
  int rc;

  // Will automatically handle calling sqlite3_finalize on the prepared stmt
  // (Note that sqlite3_finalize is explicitly a nop for nullptr)
  std::unique_ptr<sqlite3_stmt, decltype(sqlite3_finalize)*> stmt_managed(
      nullptr, sqlite3_finalize);
  sqlite3_stmt* stmt = stmt_managed.get();

  // Turn the query into a prepared statement
  rc = sqlite3_prepare_v2(db, q.c_str(), q.length() + 1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    return Status(1, sqlite3_errmsg(db));
  }

  // Get column count
  int num_columns = sqlite3_column_count(stmt);
  tables::TableColumns results;
  results.reserve(num_columns);

  // Get column names and types
  for (int i = 0; i < num_columns; ++i) {
    const char* col_name = sqlite3_column_name(stmt, i);
    const char* col_type = sqlite3_column_decltype(stmt, i);
    if (col_name == nullptr) {
      return Status(1, "Got nullptr for column name");
    }
    if (col_type == nullptr) {
      // Types are only returned for table columns (not expressions or
      // subqueries). See docs for column_decltype
      // (https://www.sqlite.org/c3ref/column_decltype.html).
      col_type = "UNKNOWN";
    }
    results.push_back({col_name, col_type});
  }

  columns = std::move(results);

  return Status(0, "OK");
}
}
