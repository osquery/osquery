/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/core.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/sql/sqlite_util.h"
#include "osquery/sql/virtual_table.h"

namespace osquery {

FLAG(string,
     disable_tables,
     "Not Specified",
     "Comma-delimited list of table names to be disabled");

DECLARE_string(nullvalue);

using OpReg = QueryPlanner::Opcode::Register;

using SQLiteDBInstanceRef = std::shared_ptr<SQLiteDBInstance>;

/**
 * @brief A map of SQLite status codes to their corresponding message string
 *
 * Details of this map are defined at: http://www.sqlite.org/c3ref/c_abort.html
 */
// clang-format off
const std::map<int, std::string> kSQLiteReturnCodes = {
    {0, "SQLITE_OK"},        {1, "SQLITE_ERROR"},       {2, "SQLITE_INTERNAL"},
    {3, "SQLITE_PERM"},      {4, "SQLITE_ABORT"},       {5, "SQLITE_BUSY"},
    {6, "SQLITE_LOCKED"},    {7, "SQLITE_NOMEM"},       {8, "SQLITE_READONLY"},
    {9, "SQLITE_INTERRUPT"}, {10, "SQLITE_IOERR"},      {11, "SQLITE_CORRUPT"},
    {12, "SQLITE_NOTFOUND"}, {13, "SQLITE_FULL"},       {14, "SQLITE_CANTOPEN"},
    {15, "SQLITE_PROTOCOL"}, {16, "SQLITE_EMPTY"},      {17, "SQLITE_SCHEMA"},
    {18, "SQLITE_TOOBIG"},   {19, "SQLITE_CONSTRAINT"}, {20, "SQLITE_MISMATCH"},
    {21, "SQLITE_MISUSE"},   {22, "SQLITE_NOLFS"},      {23, "SQLITE_AUTH"},
    {24, "SQLITE_FORMAT"},   {25, "SQLITE_RANGE"},      {26, "SQLITE_NOTADB"},
    {27, "SQLITE_NOTICE"},   {28, "SQLITE_WARNING"},    {100, "SQLITE_ROW"},
    {101, "SQLITE_DONE"},
};

const std::map<std::string, std::string> kMemoryDBSettings = {
    {"synchronous", "OFF"},      {"count_changes", "OFF"},
    {"default_temp_store", "0"}, {"auto_vacuum", "FULL"},
    {"journal_mode", "OFF"},     {"cache_size", "0"},
    {"page_count", "0"},
};
// clang-format on

#define OpComparator(x)                                                        \
  { x, QueryPlanner::Opcode(OpReg::P2, INTEGER_TYPE) }
#define Arithmetic(x)                                                          \
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
    {"AggStep0", QueryPlanner::Opcode(OpReg::P3, BIGINT_TYPE)},
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

/// The SQLiteSQLPlugin implements the "sql" registry for internal/core.
class SQLiteSQLPlugin : public SQLPlugin {
 public:
  /// Execute SQL and store results.
  Status query(const std::string& q, QueryData& results) const override;

  /// Introspect, explain, the suspected types selected in an SQL statement.
  Status getQueryColumns(const std::string& q,
                         TableColumns& columns) const override;

  /// Create a SQLite module and attach (CREATE).
  Status attach(const std::string& name) override;

  /// Detach a virtual table (DROP).
  void detach(const std::string& name) override;
};

/// SQL provider for osquery internal/core.
REGISTER_INTERNAL(SQLiteSQLPlugin, "sql", "sql");

std::string getStringForSQLiteReturnCode(int code) {
  if (kSQLiteReturnCodes.find(code) != kSQLiteReturnCodes.end()) {
    return kSQLiteReturnCodes.at(code);
  } else {
    std::ostringstream s;
    s << "Error: " << code << " is not a valid SQLite result code";
    return s.str();
  }
}

Status SQLiteSQLPlugin::query(const std::string& q, QueryData& results) const {
  auto dbc = SQLiteDBManager::get();
  auto result = queryInternal(q, results, dbc->db());
  dbc->clearAffectedTables();
  return result;
}

Status SQLiteSQLPlugin::getQueryColumns(const std::string& q,
                                        TableColumns& columns) const {
  auto dbc = SQLiteDBManager::get();
  return getQueryColumnsInternal(q, columns, dbc->db());
}

SQLInternal::SQLInternal(const std::string& q) {
  auto dbc = SQLiteDBManager::get();
  status_ = queryInternal(q, results_, dbc->db());

  // One of the advantages of using SQLInternal (aside from the Registry-bypass)
  // is the ability to "deep-inspect" the table attributes and actions.
  event_based_ = (dbc->getAttributes() & TableAttributes::EVENT_BASED) != 0;

  dbc->clearAffectedTables();
}

Status SQLiteSQLPlugin::attach(const std::string& name) {
  PluginResponse response;
  auto status =
      Registry::call("table", name, {{"action", "columns"}}, response);
  if (!status.ok()) {
    return status;
  }

  auto statement = columnDefinition(response);
  // Attach requests occurring via the plugin/registry APIs must act on the
  // primary database. To allow this, getConnection can explicitly request the
  // primary instance and avoid the contention decisions.
  auto dbc = SQLiteDBManager::getConnection(true);
  return attachTableInternal(name, statement, dbc);
}

void SQLiteSQLPlugin::detach(const std::string& name) {
  auto dbc = SQLiteDBManager::get();
  if (!dbc->isPrimary()) {
    return;
  }
  detachTableInternal(name, dbc->db());
}

SQLiteDBInstance::SQLiteDBInstance(sqlite3*& db, Mutex& mtx)
    : db_(db), lock_(mtx, MUTEX_IMPL::try_to_lock) {
  if (lock_.owns_lock()) {
    primary_ = true;
  } else {
    db_ = nullptr;
    VLOG(1) << "DBManager contention: opening transient SQLite database";
    init();
  }
}

static inline void openOptimized(sqlite3*& db) {
  sqlite3_open(":memory:", &db);

  std::string settings;
  for (const auto& setting : kMemoryDBSettings) {
    settings += "PRAGMA " + setting.first + "=" + setting.second + "; ";
  }
  sqlite3_exec(db, settings.c_str(), nullptr, nullptr, nullptr);

  // Register function extensions.
  registerMathExtensions(db);
#if !defined(FREEBSD)
  registerStringExtensions(db);
#endif
}

void SQLiteDBInstance::init() {
  primary_ = false;
  openOptimized(db_);
}

void SQLiteDBInstance::addAffectedTable(VirtualTableContent* table) {
  // An xFilter/scan was requested for this virtual table.
  affected_tables_.insert(std::make_pair(table->name, table));
}

TableAttributes SQLiteDBInstance::getAttributes() const {
  const SQLiteDBInstance* rdbc = this;
  if (isPrimary() && !managed_) {
    // Similarly to clearAffectedTables, the connection may be forwarded.
    rdbc = SQLiteDBManager::getConnection(true).get();
  }

  TableAttributes attributes = TableAttributes::NONE;
  for (const auto& table : rdbc->affected_tables_) {
    attributes = table.second->attributes | attributes;
  }
  return attributes;
}

void SQLiteDBInstance::clearAffectedTables() {
  if (isPrimary() && !managed_) {
    // A primary instance must forward clear requests to the DB manager's
    // 'connection' instance. This is a temporary primary instance.
    SQLiteDBManager::getConnection(true)->clearAffectedTables();
    return;
  }

  for (const auto& table : affected_tables_) {
    table.second->constraints.clear();
    table.second->cache.clear();
  }
  // Since the affected tables are cleared, there are no more affected tables.
  // There is no concept of compounding tables between queries.
  affected_tables_.clear();
}

SQLiteDBInstance::~SQLiteDBInstance() {
  if (!isPrimary() && db_ != nullptr) {
    sqlite3_close(db_);
  } else {
    db_ = nullptr;
  }
}

SQLiteDBManager::SQLiteDBManager() : db_(nullptr) {
  sqlite3_soft_heap_limit64(1);
  setDisabledTables(Flag::getValue("disable_tables"));
}

bool SQLiteDBManager::isDisabled(const std::string& table_name) {
  const auto& element = instance().disabled_tables_.find(table_name);
  return (element != instance().disabled_tables_.end());
}

void SQLiteDBManager::resetPrimary() {
  auto& self = instance();

  WriteLock connection_lock(self.mutex_);
  self.connection_.reset();

  {
    WriteLock create_lock(self.create_mutex_);
    sqlite3_close(self.db_);
    self.db_ = nullptr;
  }
}

void SQLiteDBManager::setDisabledTables(const std::string& list) {
  const auto& tables = split(list, ",");
  disabled_tables_ =
      std::unordered_set<std::string>(tables.begin(), tables.end());
}

SQLiteDBInstanceRef SQLiteDBManager::getUnique() {
  auto instance = std::make_shared<SQLiteDBInstance>();
  attachVirtualTables(instance);
  return instance;
}

SQLiteDBInstanceRef SQLiteDBManager::getConnection(bool primary) {
  auto& self = instance();
  WriteLock lock(self.create_mutex_);

  if (self.db_ == nullptr) {
    // Create primary SQLite DB instance.
    openOptimized(self.db_);
    self.connection_ = SQLiteDBInstanceRef(new SQLiteDBInstance(self.db_));
    attachVirtualTables(self.connection_);
  }

  // Internal usage may request the primary connection explicitly.
  if (primary) {
    return self.connection_;
  }

  // Create a 'database connection' for the managed database instance.
  auto instance = std::make_shared<SQLiteDBInstance>(self.db_, self.mutex_);
  if (!instance->isPrimary()) {
    attachVirtualTables(instance);
  }
  return instance;
}

SQLiteDBManager::~SQLiteDBManager() {
  connection_ = nullptr;
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
          std::get<1>(columns[type.first - k]) = type.second;
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

  auto qData = static_cast<QueryData*>(argument);
  Row r;
  for (int i = 0; i < argc; i++) {
    if (column[i] != nullptr) {
      if (r.count(column[i])) {
        // Found a column name collision in the result.
        VLOG(1) << "Detected overloaded column name " << column[i]
                << " in query result consider using aliases";
      }
      r[column[i]] = (argv[i] != nullptr) ? argv[i] : FLAGS_nullvalue;
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
  sqlite3_stmt* stmt{nullptr};
  auto rc = sqlite3_prepare_v2(
      db, q.c_str(), static_cast<int>(q.length() + 1), &stmt, nullptr);
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
    results.push_back(std::make_tuple(
        col_name, columnTypeName(col_type), ColumnOptions::DEFAULT));
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
