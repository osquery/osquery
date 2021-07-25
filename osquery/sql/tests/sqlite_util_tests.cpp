/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/registry/registry_interface.h>
#include <osquery/sql/sql.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/sql/tests/sql_test_utils.h>
#include <osquery/utils/info/platform_type.h>

#include <gtest/gtest.h>

#include <boost/lexical_cast.hpp>
#include <boost/variant.hpp>

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
  EXPECT_EQ(dbc->affected_tables_.count("time"), 1U);
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
