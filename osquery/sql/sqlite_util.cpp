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
#include <osquery/logger.h>
#include <osquery/flags.h>
#include <osquery/sql.h>

#include "osquery/sql/sqlite_util.h"
#include "osquery/sql/virtual_table.h"

namespace osquery {

using OpReg = QueryPlanner::Opcode::Register;

/// SQL provider for osquery internal/core.
REGISTER_INTERNAL(SQLiteSQLPlugin, "sql", "sql");

FLAG(string,
     disable_tables,
     "Not Specified",
     "Comma-delimited list of table names to be disabled");

/**
 * @brief A map of SQLite status codes to their corresponding message string
 *
 * Details of this map are defined at: http://www.sqlite.org/c3ref/c_abort.html
 */
const std::map<int, std::string> kSQLiteReturnCodes = {
    {0, "SQLITE_OK"},
    {1, "SQLITE_ERROR"},
    {2, "SQLITE_INTERNAL"},
    {3, "SQLITE_PERM"},
    {4, "SQLITE_ABORT"},
    {5, "SQLITE_BUSY"},
    {6, "SQLITE_LOCKED"},
    {7, "SQLITE_NOMEM"},
    {8, "SQLITE_READONLY"},
    {9, "SQLITE_INTERRUPT"},
    {10, "SQLITE_IOERR"},
    {11, "SQLITE_CORRUPT"},
    {12, "SQLITE_NOTFOUND"},
    {13, "SQLITE_FULL"},
    {14, "SQLITE_CANTOPEN"},
    {15, "SQLITE_PROTOCOL"},
    {16, "SQLITE_EMPTY"},
    {17, "SQLITE_SCHEMA"},
    {18, "SQLITE_TOOBIG"},
    {19, "SQLITE_CONSTRAINT"},
    {20, "SQLITE_MISMATCH"},
    {21, "SQLITE_MISUSE"},
    {22, "SQLITE_NOLFS"},
    {23, "SQLITE_AUTH"},
    {24, "SQLITE_FORMAT"},
    {25, "SQLITE_RANGE"},
    {26, "SQLITE_NOTADB"},
    {27, "SQLITE_NOTICE"},
    {28, "SQLITE_WARNING"},
    {100, "SQLITE_ROW"},
    {101, "SQLITE_DONE"},
};

#define OpComparator(x) \
  { x, QueryPlanner::Opcode(OpReg::P2, INTEGER_TYPE) }
#define Arithmetic(x) \
  { x, QueryPlanner::Opcode(OpReg::P3, BIGINT_TYPE) }

/**
 * @brief A map from opcode to pair of result register and resultant type.
 *
 * For most opcodes we can deduce a column type based on an interred input
 * to the opcode "function". These come in a few sets, arithmetic operators,
 * comparators, aggregates, and copies.
 */
const std::map<std::string, QueryPlanner::Opcode> kSQLOpcodes = {
    {"Concat", QueryPlanner::Opcode(OpReg::P3, TEXT_TYPE)},
    {"AggStep", QueryPlanner::Opcode(OpReg::P3, BIGINT_TYPE)},
    {"Integer", QueryPlanner::Opcode(OpReg::P2, INTEGER_TYPE)},
    {"Int64", QueryPlanner::Opcode(OpReg::P2, BIGINT_TYPE)},
    {"String", QueryPlanner::Opcode(OpReg::P2, TEXT_TYPE)},
    {"String8", QueryPlanner::Opcode(OpReg::P2, TEXT_TYPE)},
    {"Or", QueryPlanner::Opcode(OpReg::P3, INTEGER_TYPE)},
    {"And", QueryPlanner::Opcode(OpReg::P3, INTEGER_TYPE)},

    // Arithmetic yields a BIGINT for safety.
    Arithmetic("BitAnd"),
    Arithmetic("BitAnd"),
    Arithmetic("BitOr"),
    Arithmetic("ShiftLeft"),
    Arithmetic("ShiftRight"),
    Arithmetic("Add"),
    Arithmetic("Subtract"),
    Arithmetic("Multiply"),
    Arithmetic("Divide"),
    Arithmetic("Remainder"),

    // Comparators result in booleans and are treated as INTEGERs.
    OpComparator("Not"),
    OpComparator("IsNull"),
    OpComparator("NotNull"),
    OpComparator("Ne"),
    OpComparator("Eq"),
    OpComparator("Gt"),
    OpComparator("Le"),
    OpComparator("Lt"),
    OpComparator("Ge"),
    OpComparator("IfNeg"),
    OpComparator("IfNotZero"),
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

  auto statement = columnDefinition(response);
  return attachTableInternal(name, statement, dbc.db());
}

void SQLiteSQLPlugin::detach(const std::string& name) {
  auto dbc = SQLiteDBManager::get();
  if (!dbc.isPrimary()) {
    return;
  }
  detachTableInternal(name, dbc.db());
}

SQLiteDBInstance::SQLiteDBInstance() {
  primary_ = false;
  sqlite3_open(":memory:", &db_);
  attachVirtualTables(db_);
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

bool SQLiteDBManager::isDisabled(const std::string& table_name) {
  const auto& element = instance().disabled_tables_.find(table_name);
  return (element != instance().disabled_tables_.end());
}

std::unordered_set<std::string> SQLiteDBManager::parseDisableTablesFlag(
    const std::string& list) {
  const auto& tables = split(list, ",");
  return std::unordered_set<std::string>(tables.begin(), tables.end());
}

SQLiteDBInstance SQLiteDBManager::getUnique() { return SQLiteDBInstance(); }

SQLiteDBInstance SQLiteDBManager::get() {
  auto& self = instance();

  if (!self.lock_.owns_lock() && self.lock_.try_lock()) {
    if (self.db_ == nullptr) {
      // Create primary SQLite DB instance.
      sqlite3_open(":memory:", &self.db_);
      attachVirtualTables(self.db_);
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

QueryPlanner::QueryPlanner(const std::string& query, sqlite3* db) {
  QueryData plan;
  queryInternal("EXPLAIN QUERY PLAN " + query, plan, db);
  queryInternal("EXPLAIN " + query, program_, db);

  for (const auto& row : plan) {
    auto details = osquery::split(row.at("detail"));
    tables_.push_back(details[2]);
  }
}

Status QueryPlanner::applyTypes(TableColumns& columns) {
  std::map<size_t, ColumnType> column_types;
  for (const auto& row : program_) {
    if (row.at("opcode") == "ResultRow") {
      // The column parsing is finished.
      auto k = boost::lexical_cast<size_t>(row.at("p1"));
      for (const auto& type : column_types) {
        if (type.first - k < columns.size()) {
          columns[type.first - k].second = type.second;
        }
      }
    }

    if (row.at("opcode") == "Copy") {
      // Copy P1 -> P1 + P3 into P2 -> P2 + P3.
      auto from = boost::lexical_cast<size_t>(row.at("p1"));
      auto to = boost::lexical_cast<size_t>(row.at("p2"));
      auto size = boost::lexical_cast<size_t>(row.at("p3"));
      for (size_t i = 0; i <= size; i++) {
        if (column_types.count(from + i)) {
          column_types[to + i] = std::move(column_types[from + i]);
          column_types.erase(from + i);
        }
      }
    }

    if (kSQLOpcodes.count(row.at("opcode"))) {
      const auto& op = kSQLOpcodes.at(row.at("opcode"));
      auto k = boost::lexical_cast<size_t>(row.at(Opcode::regString(op.reg)));
      column_types[k] = op.type;
    }
  }

  return Status(0);
}

int queryDataCallback(void* argument, int argc, char* argv[], char* column[]) {
  if (argument == nullptr) {
    VLOG(1) << "Query execution failed: received a bad callback argument";
    return SQLITE_MISUSE;
  }

  QueryData* qData = (QueryData*)argument;
  Row r;
  for (int i = 0; i < argc; i++) {
    if (column[i] != nullptr) {
      r[column[i]] = (argv[i] != nullptr) ? argv[i] : "";
    }
  }
  (*qData).push_back(std::move(r));
  return 0;
}

Status queryInternal(const std::string& q, QueryData& results, sqlite3* db) {
  char* err = nullptr;
  sqlite3_exec(db, q.c_str(), queryDataCallback, &results, &err);
  sqlite3_db_release_memory(db);
  if (err != nullptr) {
    auto error_string = std::string(err);
    sqlite3_free(err);
    return Status(1, "Error running query: " + error_string);
  }

  return Status(0, "OK");
}

Status getQueryColumnsInternal(const std::string& q,
                               TableColumns& columns,
                               sqlite3* db) {
  // Turn the query into a prepared statement
  sqlite3_stmt *stmt{nullptr};
  auto rc = sqlite3_prepare_v2(db, q.c_str(), q.length() + 1, &stmt, nullptr);
  if (rc != SQLITE_OK || stmt == nullptr) {
    if (stmt != nullptr) {
      sqlite3_finalize(stmt);
    }
    return Status(1, sqlite3_errmsg(db));
  }

  // Get column count
  auto num_columns = sqlite3_column_count(stmt);
  TableColumns results;
  results.reserve(num_columns);

  // Get column names and types
  Status status = Status();
  bool unknown_type = false;
  for (int i = 0; i < num_columns; ++i) {
    auto col_name = sqlite3_column_name(stmt, i);
    auto col_type = sqlite3_column_decltype(stmt, i);

    if (col_name == nullptr) {
      status = Status(1, "Could not get column type");
      break;
    }

    if (col_type == nullptr) {
      // Types are only returned for table columns (not expressions).
      col_type = "UNKNOWN";
      unknown_type = true;
    }
    results.push_back({col_name, columnTypeName(col_type)});
  }

  // An unknown type means we have to parse the plan and SQLite opcodes.
  if (unknown_type) {
    QueryPlanner planner(q, db);
    planner.applyTypes(results);
  }

  if (status.ok()) {
    columns = std::move(results);
  }

  sqlite3_finalize(stmt);
  return status;
}
}
