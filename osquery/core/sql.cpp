// Copyright 2004-present Facebook. All Rights Reserved.

#include <sstream>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/core/virtual_table.h"

namespace osquery {

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

SQL::SQL(const std::string& q) {
  int code = 0;
  results_ = query(q, code);
  status_ = Status(code, getStringForSQLiteReturnCode(code));
}

QueryData SQL::rows() { return results_; }

bool SQL::ok() { return status_.ok(); }

std::string SQL::getMessageString() { return status_.toString(); }

std::vector<std::string> SQL::getTableNames() {
  std::vector<std::string> results;
  for (const auto& it : REGISTERED_TABLES) {
    results.push_back(it.first);
  }
  return results;
}

QueryData SQL::selectAllFrom(const std::string& table) {
  std::string query = "select * from " + table + ";";
  return SQL(query).rows();
}
}
