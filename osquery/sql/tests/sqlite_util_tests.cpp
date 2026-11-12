/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/carver/carver_utils.h>
#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry_interface.h>
#include <osquery/sql/sql.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/sql/tests/sql_test_utils.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/scope_guard.h>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/variant.hpp>

namespace fs = boost::filesystem;

namespace osquery {
class SQLiteUtilTests : public testing::Test {
 public:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    Flag::updateValue("enable_tables",
                      "test_table,time,process_events,osquery_info,file,users,"
                      "curl,fake_table");
    Flag::updateValue("disable_tables", "fake_table");
  }
};

std::shared_ptr<SQLiteDBInstance> getTestDBC() {
  auto dbc = SQLiteDBManager::getUnique();

  char* err = nullptr;
  std::vector<std::string> queries = {
      "CREATE TABLE test_table (username varchar(30), age int)",
      "INSERT INTO test_table VALUES (\"mike\", 23)",
      "INSERT INTO test_table VALUES (\"matt\", 24)"};

  for (auto q : queries) {
    sqlite3_exec(dbc->db(), q.c_str(), nullptr, nullptr, &err);
    if (err != nullptr) {
      throw std::domain_error(std::string("Cannot create testing DBC's db: ") +
                              err);
    }
  }

  return dbc;
}

TEST_F(SQLiteUtilTests, test_zero_as_float_doesnt_convert_to_int) {
  auto sql = SQL("SELECT 0.0 as zero");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  Row r;
  r["zero"] = "0.0";
  EXPECT_EQ(sql.rows()[0], r);
}

TEST_F(SQLiteUtilTests, test_precision_is_maintained) {
  auto sql = SQL("SELECT 0.123456789 as high_precision, 0.12 as low_precision");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  Row r;
  r["high_precision"] = "0.123456789";
  r["low_precision"] = "0.12";
  EXPECT_EQ(sql.rows()[0], r);
}

TEST_F(SQLiteUtilTests, test_simple_query_execution) {
  // Access to the internal SQL implementation is only available in core.
  auto sql = SQL("SELECT * FROM time");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
}

TEST_F(SQLiteUtilTests, test_sqlite_instance_manager) {
  auto dbc1 = SQLiteDBManager::get();
  auto dbc2 = SQLiteDBManager::get();
  EXPECT_NE(dbc1->db(), dbc2->db());
  EXPECT_EQ(dbc1->db(), dbc1->db());
}

TEST_F(SQLiteUtilTests, test_sqlite_instance) {
  // Don't do this at home kids.
  // Keep a copy of the internal DB and let the SQLiteDBInstance go oos.
  auto internal_db = SQLiteDBManager::get()->db();
  // Compare the internal DB to another request with no SQLiteDBInstances
  // in scope, meaning the primary will be returned.
  EXPECT_EQ(internal_db, SQLiteDBManager::get()->db());
}

TEST_F(SQLiteUtilTests, test_reset) {
  auto internal_db = SQLiteDBManager::get()->db();
  ASSERT_NE(nullptr, internal_db);

  sqlite3_exec(internal_db,
               "create view test_view as select 'test';",
               nullptr,
               nullptr,
               nullptr);

  SQLiteDBManager::resetPrimary();
  auto instance = SQLiteDBManager::get();

  QueryDataTyped results;
  queryInternal("select * from test_view", results, instance);

  // Assume the internal (primary) database we reset and recreated.
  EXPECT_EQ(results.size(), 0U);
}

TEST_F(SQLiteUtilTests, test_direct_query_execution) {
  auto dbc = getTestDBC();
  QueryDataTyped results;
  auto status = queryInternal(kTestQuery, results, dbc);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results, getTestDBExpectedResults());
}

TEST_F(SQLiteUtilTests, test_aggregate_query) {
  auto dbc = getTestDBC();
  QueryDataTyped results;
  auto status = queryInternal(kTestQuery, results, dbc);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results, getTestDBExpectedResults());
}

TEST_F(SQLiteUtilTests, test_aggregate_terms_above_i16_limit_after_reopen) {
  const auto database_path =
      fs::temp_directory_path() /
      fs::unique_path("osquery.sqlite.aggregate_terms.%%%%.%%%%.db");
  const auto database_cleanup = scope_guard::create([&database_path]() {
    boost::system::error_code cleanup_error;
    fs::remove(database_path, cleanup_error);
  });

  sqlite3* raw_database = nullptr;
  auto rc = sqlite3_open(database_path.string().c_str(), &raw_database);
  std::unique_ptr<sqlite3, decltype(&sqlite3_close)> database(raw_database,
                                                              sqlite3_close);
  ASSERT_EQ(SQLITE_OK, rc) << (database != nullptr
                                   ? sqlite3_errmsg(database.get())
                                   : "sqlite3_open did not return a handle");

  constexpr std::size_t kColumnCount = 2000U;
  std::string create_tables = "CREATE TABLE many_columns(";
  for (std::size_t column_index = 0U; column_index < kColumnCount;
       ++column_index) {
    if (column_index > 0U) {
      create_tables += ',';
    }

    create_tables += "c" + std::to_string(column_index) + " INTEGER";
  }

  create_tables +=
      "); CREATE TABLE files(file_name TEXT, folder TEXT, fs_id TEXT);";

  char* error = nullptr;
  rc = sqlite3_exec(
      database.get(), create_tables.c_str(), nullptr, nullptr, &error);
  std::string error_message = error == nullptr ? "" : error;
  sqlite3_free(error);
  ASSERT_EQ(SQLITE_OK, rc) << error_message;

  // The zero-based aggregate index first exceeds i16 at term 32,769.
  constexpr std::size_t kAggregateTermCount = 32769U;
  // Keep each AND group below SQLITE_MAX_EXPR_DEPTH.
  constexpr std::size_t kTermGroupSize = 100U;
  constexpr std::size_t kTableCount =
      (kAggregateTermCount + kColumnCount - 1U) / kColumnCount;

  std::string create_view =
      "CREATE VIEW thumbnails AS SELECT t0.c0 AS file_id, "
      "0 AS last_hit_date, 0 AS hit_count, 0 AS icon_mode FROM ";

  for (std::size_t table_index = 0U; table_index < kTableCount; ++table_index) {
    if (table_index > 0U) {
      create_view += ',';
    }

    create_view += "many_columns AS t" + std::to_string(table_index);
  }

  create_view += " GROUP BY t0.c0 HAVING ";

  for (std::size_t term_index = 0U; term_index < kAggregateTermCount;
       ++term_index) {
    if (term_index > 0U) {
      create_view += " AND ";
    }

    if (term_index % kTermGroupSize == 0U) {
      create_view += '(';
    }

    create_view += "t" + std::to_string(term_index / kColumnCount) + ".c" +
                   std::to_string(term_index % kColumnCount) + " IS NOT NULL";

    if ((term_index + 1U) % kTermGroupSize == 0U ||
        term_index + 1U == kAggregateTermCount) {
      create_view += ')';
    }
  }

  create_view += ';';

  error = nullptr;
  rc = sqlite3_exec(
      database.get(), create_view.c_str(), nullptr, nullptr, &error);
  error_message = error == nullptr ? "" : error;
  sqlite3_free(error);
  ASSERT_EQ(SQLITE_OK, rc) << error_message;

  ASSERT_EQ(SQLITE_OK, sqlite3_close(database.get()));
  database.release();

  raw_database = nullptr;
  rc = sqlite3_open_v2(
      database_path.string().c_str(),
      &raw_database,
      SQLITE_OPEN_READONLY | SQLITE_OPEN_PRIVATECACHE | SQLITE_OPEN_NOMUTEX,
      nullptr);
  database.reset(raw_database);
  ASSERT_EQ(SQLITE_OK, rc) << (database != nullptr
                                   ? sqlite3_errmsg(database.get())
                                   : "sqlite3_open did not return a handle");

  const std::string query =
      "SELECT f.*, last_hit_date, hit_count, icon_mode FROM "
      "(SELECT rowid, * FROM files) f, "
      "(SELECT *, max(last_hit_date) AS last_hit_date FROM thumbnails "
      "GROUP BY file_id) t WHERE t.file_id = rowid;";

  sqlite3_stmt* raw_statement = nullptr;
  rc = sqlite3_prepare_v2(
      database.get(), query.c_str(), -1, &raw_statement, nullptr);
  std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> statement(
      raw_statement, sqlite3_finalize);
  ASSERT_EQ(SQLITE_OK, rc) << sqlite3_errmsg(database.get());
  ASSERT_NE(nullptr, statement.get());
  EXPECT_EQ(SQLITE_DONE, sqlite3_step(statement.get()))
      << sqlite3_errmsg(database.get());
}

TEST_F(SQLiteUtilTests, test_no_results_query) {
  auto dbc = getTestDBC();
  QueryDataTyped results;
  auto status = queryInternal(
      "select * from test_table where username=\"A_NON_EXISTENT_NAME\"",
      results,
      dbc);
  EXPECT_TRUE(status.ok());
}

TEST_F(SQLiteUtilTests, test_whitespace_query) {
  auto dbc = getTestDBC();
  QueryDataTyped results;
  auto status = queryInternal("     ", results, dbc);
  EXPECT_TRUE(status.ok());
}

TEST_F(SQLiteUtilTests, test_whitespace_then_nonwhitespace_query) {
  auto dbc = getTestDBC();
  QueryDataTyped results;
  auto status = queryInternal("     ; select * from time  ", results, dbc);
  EXPECT_TRUE(status.ok());
}

TEST_F(SQLiteUtilTests, test_get_test_db_result_stream) {
  auto dbc = getTestDBC();
  auto results = getTestDBResultStream();
  for (auto r : results) {
    char* err_char = nullptr;
    sqlite3_exec(dbc->db(), (r.first).c_str(), nullptr, nullptr, &err_char);
    EXPECT_TRUE(err_char == nullptr);
    if (err_char != nullptr) {
      sqlite3_free(err_char);
      ASSERT_TRUE(false);
    }

    QueryDataTyped expected;
    auto status = queryInternal(kTestQuery, expected, dbc);
    EXPECT_EQ(expected, r.second);
  }
}

TEST_F(SQLiteUtilTests, test_affected_tables) {
  auto dbc = getTestDBC();
  QueryDataTyped results;
  auto status = queryInternal("SELECT * FROM time", results, dbc);

  // Since the table scanned from "time", it should be recorded as affected.
  ASSERT_EQ(dbc->affected_tables_.size(), 1U);
  EXPECT_EQ(dbc->affected_tables_.begin()->second->name, "time");
  dbc->clearAffectedTables();
  EXPECT_EQ(dbc->affected_tables_.size(), 0U);
}

TEST_F(SQLiteUtilTests, test_table_attributes_event_based) {
  {
    SQLInternal sql_internal("select * from process_events");
    if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
      EXPECT_TRUE(sql_internal.getStatus().ok());
      EXPECT_TRUE(sql_internal.eventBased());
    }
  }

  {
    SQLInternal sql_internal("select * from time");
    EXPECT_TRUE(sql_internal.getStatus().ok());
    EXPECT_FALSE(sql_internal.eventBased());
  }
}

TEST_F(SQLiteUtilTests, test_get_query_columns) {
  auto dbc = getTestDBC();
  TableColumns results;

  std::string query = "SELECT seconds, version FROM time JOIN osquery_info";
  auto status = getQueryColumnsInternal(query, results, dbc);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(2U, results.size());
  EXPECT_EQ(std::make_tuple(
                std::string("seconds"), INTEGER_TYPE, ColumnOptions::DEFAULT),
            results[0]);
  EXPECT_EQ(std::make_tuple(
                std::string("version"), TEXT_TYPE, ColumnOptions::DEFAULT),
            results[1]);

  query = "SELECT * FROM foo";
  status = getQueryColumnsInternal(query, results, dbc);
  ASSERT_FALSE(status.ok());
}

TEST_F(SQLiteUtilTests, test_get_query_tables_failed) {
  auto dbc = getTestDBC();
  QueryDataTyped results;
  EXPECT_FALSE(queryInternal("SELECT * FROM file", results, dbc).ok());
}

TEST_F(SQLiteUtilTests, test_get_query_tables) {
  std::string query =
      "SELECT * FROM time, osquery_info, (SELECT * FROM users) ff GROUP BY pid";
  std::vector<std::string> tables;
  auto status = getQueryTables(query, tables);
  EXPECT_TRUE(status.ok());

  std::vector<std::string> expected = {"time", "osquery_info", "users"};
  EXPECT_EQ(expected, tables);
}

TEST_F(SQLiteUtilTests, test_get_query_tables_required) {
  std::string query =
      "SELECT * FROM time, osquery_info, (SELECT * FROM file where path = "
      "'osquery') ff GROUP BY pid";
  std::vector<std::string> tables;
  auto status = getQueryTables(query, tables);
  EXPECT_TRUE(status.ok());

  std::vector<std::string> expected = {"time", "osquery_info", "file"};
  EXPECT_EQ(expected, tables);
}

std::vector<ColumnType> getTypes(const TableColumns& columns) {
  std::vector<ColumnType> types;
  for (const auto& col : columns) {
    types.push_back(std::get<1>(col));
  }
  return types;
}

TEST_F(SQLiteUtilTests, test_query_planner) {
  using TypeList = std::vector<ColumnType>;

  auto dbc = getTestDBC();
  TableColumns columns;

  std::string query = "select path, path from file";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());

  query = "select path, path from file where path in ('osquery', 'noquery')";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns), TypeList({TEXT_TYPE, TEXT_TYPE}));

  query = "select path, seconds from file, time where path LIKE 'osquery'";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns), TypeList({TEXT_TYPE, INTEGER_TYPE}));

  query = "select path || path from file";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());

  query = "select path || path from file where path = 'osquery'";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns), TypeList({TEXT_TYPE}));

  query = "select seconds, path || path from file, time ";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());

  query =
      "select seconds, path || path from file, time where path in ('osquery')";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns), TypeList({INTEGER_TYPE, TEXT_TYPE}));

  query = "select seconds, seconds from time";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns), TypeList({INTEGER_TYPE, INTEGER_TYPE}));

  query = "select count(*) from time";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns), TypeList({BIGINT_TYPE}));

  query = "select count(*), count(seconds), seconds from time";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns),
            TypeList({BIGINT_TYPE, BIGINT_TYPE, INTEGER_TYPE}));

  query = "select 1, 'path', path from file";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());

  query = "select 1, 'path', path from file where path = 'os'";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns), TypeList({INTEGER_TYPE, TEXT_TYPE, TEXT_TYPE}));

  query = "select weekday, day, count(*), seconds from time";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns),
            TypeList({TEXT_TYPE, INTEGER_TYPE, BIGINT_TYPE, INTEGER_TYPE}));

  query = "select seconds + 1 from time";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns), TypeList({BIGINT_TYPE}));

  query = "select seconds * seconds from time";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns), TypeList({BIGINT_TYPE}));

  query = "select seconds > 1, seconds, count(seconds) from time";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns),
            TypeList({INTEGER_TYPE, INTEGER_TYPE, BIGINT_TYPE}));

  query =
      "select f1.*, seconds, f2.directory from (select path || path from file) "
      "f1, file as f2, time";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());

  query =
      "select f1.*, seconds, f2.directory from (select path || path from file) "
      "f1, file as f2, time where path in ('query', 'query')";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());

  query =
      "select f1.*, seconds, f2.directory from (select path || path from file "
      "where path = 'query') "
      "f1, file as f2, time where path in ('query', 'query')";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns), TypeList({TEXT_TYPE, INTEGER_TYPE, TEXT_TYPE}));

  query = "select CAST(seconds AS INTEGER) FROM time";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns), TypeList({BIGINT_TYPE}));

  query = "select CAST(seconds AS TEXT) FROM time";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns), TypeList({TEXT_TYPE}));

  query = "select CAST(seconds AS REAL) FROM time";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns), TypeList({DOUBLE_TYPE}));

  query = "select CAST(seconds AS BOOLEAN) FROM time";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns), TypeList({UNKNOWN_TYPE}));

  query = "select CAST(seconds AS DATETIME) FROM time";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns), TypeList({UNKNOWN_TYPE}));

  query = "select CAST(seconds AS BLOB) FROM time";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns), TypeList({BLOB_TYPE}));

  query = "select url, round_trip_time, response_code from curl";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());

  query =
      "select url, round_trip_time, response_code from curl where url = "
      "'https://github.com/osquery/osquery'";
  EXPECT_TRUE(getQueryColumnsInternal(query, columns, dbc).ok());
  EXPECT_EQ(getTypes(columns),
            TypeList({TEXT_TYPE, BIGINT_TYPE, INTEGER_TYPE}));
}

using TypeMap = std::map<std::string, ColumnType>;

// Using ColumnType enum just labeling in test_column_type_determination)
class type_picker_visitor : public boost::static_visitor<ColumnType> {
 public:
  ColumnType operator()(const long long& i) const {
    return INTEGER_TYPE;
  }

  ColumnType operator()(const std::string& str) const {
    return TEXT_TYPE;
  }

  ColumnType operator()(const double& d) const {
    return DOUBLE_TYPE;
  }
};

void testTypesExpected(std::string query, TypeMap expectedTypes) {
  auto dbc = getTestDBC();
  QueryDataTyped typedResults;
  queryInternal(query, typedResults, dbc);
  for (const auto& row : typedResults) {
    for (const auto& col : row) {
      if (expectedTypes.count(col.first)) {
        EXPECT_EQ(boost::apply_visitor(type_picker_visitor(), col.second),
                  expectedTypes[col.first])
            << " These are the integer values of actual/expected ColumnType "
               "(resp) of "
            << col.first << " for query: " << query;
      } else {
        FAIL() << "Found no expected type for " << col.first
               << " in test of column types for query " << query;
      }
    }
  }
}

TEST_F(SQLiteUtilTests, test_column_type_determination) {
  // Correct identification of text and ints
  testTypesExpected("select path, inode from file where path like '%'",
                    TypeMap({{"path", TEXT_TYPE}, {"inode", INTEGER_TYPE}}));
  // Correctly treating BLOBs as text
  testTypesExpected("select CAST(seconds AS BLOB) as seconds FROM time",
                    TypeMap({{"seconds", TEXT_TYPE}}));
  // Correctly treating ints cast as double as doubles
  testTypesExpected("select CAST(seconds AS DOUBLE) as seconds FROM time",
                    TypeMap({{"seconds", DOUBLE_TYPE}}));
  // Correctly treating bools as ints
  testTypesExpected("select CAST(seconds AS BOOLEAN) as seconds FROM time",
                    TypeMap({{"seconds", INTEGER_TYPE}}));
  // Correctly recognizing values from columns declared double as double, even
  // if they happen to have integer value.  And also test multi-statement
  // queries.
  testTypesExpected(
      "CREATE TABLE test_types_table (username varchar(30), age "
      "double);INSERT INTO test_types_table VALUES (\"mike\", 23); SELECT age "
      "from test_types_table",
      TypeMap({{"age", DOUBLE_TYPE}}));
}

TEST_F(SQLiteUtilTests, test_enable) {
  // Shadow is not in enable_tables.
  ASSERT_TRUE(SQLiteDBManager::isDisabled("shadow"));
  // Users is explicitly in enable_tables.
  ASSERT_FALSE(SQLiteDBManager::isDisabled("users"));
  // Fake_table is explicitly in enabled_tables and
  // disable_tables, it should be disabled.
  ASSERT_TRUE(SQLiteDBManager::isDisabled("fake_table"));
}

DECLARE_bool(carver_disable_function);

TEST_F(SQLiteUtilTests, test_carve_function_disabled) {
  ASSERT_TRUE(FLAGS_carver_disable_function);

  auto sql = SQL("SELECT carve('/tmp/osquery_carve_test') AS c");
  ASSERT_TRUE(sql.ok());
  ASSERT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0].at("c"), "Carve Failed: function disabled");
}

TEST_F(SQLiteUtilTests, test_carve_function_enabled) {
  initDatabasePluginForTesting();
  FLAGS_carver_disable_function = false;

  auto sql = SQL("SELECT carve('/tmp/osquery_carve_test') AS c");
  FLAGS_carver_disable_function = true;
  ASSERT_TRUE(sql.ok());
  ASSERT_EQ(sql.rows().size(), 1U);

  // The result must carry the full GUID of the queued carve request.
  const std::string prefix = "Carve Started: ";
  const auto& result = sql.rows()[0].at("c");
  ASSERT_GT(result.size(), prefix.size());
  EXPECT_EQ(result.compare(0, prefix.size(), prefix), 0);

  std::string request;
  auto s = getDatabaseValue(
      kCarves, kCarverDBPrefix + result.substr(prefix.size()), request);
  EXPECT_TRUE(s.ok());
}

TEST_F(SQLiteUtilTests, test_sqlite_authorizer) {
  auto rc = sqliteAuthorizer(
      nullptr, SQLITE_ATTACH, nullptr, nullptr, nullptr, nullptr);
  EXPECT_EQ(SQLITE_DENY, rc);

  rc = sqliteAuthorizer(nullptr, 534, nullptr, nullptr, nullptr, nullptr);
  EXPECT_EQ(SQLITE_DENY, rc);

  rc = sqliteAuthorizer(
      nullptr, SQLITE_SELECT, nullptr, nullptr, nullptr, nullptr);
  EXPECT_EQ(SQLITE_OK, rc);
}

} // namespace osquery
