/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iostream>

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/sql.h>

#include "osquery/sql/sqlite_util.h"
#include "osquery/tests/test_util.h"

namespace osquery {

class SQLiteUtilTests : public testing::Test {};

std::shared_ptr<SQLiteDBInstance> getTestDBC() {
  auto dbc = SQLiteDBManager::getUnique();
  char* err = nullptr;
  std::vector<std::string> queries = {
      "CREATE TABLE test_table (username varchar(30) primary key, age int)",
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

TEST_F(SQLiteUtilTests, test_get_query_tables) {
  std::string query =
      "SELECT * FROM time, osquery_info, (SELECT * FROM file) ff GROUP BY pid";
  std::vector<std::string> tables;
  auto status = getQueryTables(query, tables);
  EXPECT_TRUE(status.ok());

  std::vector<std::string> expected = {"file", "time", "osquery_info"};
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
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns), TypeList({TEXT_TYPE, TEXT_TYPE}));

  query = "select path, seconds from file, time";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns), TypeList({TEXT_TYPE, INTEGER_TYPE}));

  query = "select path || path from file";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns), TypeList({TEXT_TYPE}));

  query = "select seconds, path || path from file, time";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns), TypeList({INTEGER_TYPE, TEXT_TYPE}));

  query = "select seconds, seconds from time";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns), TypeList({INTEGER_TYPE, INTEGER_TYPE}));

  query = "select count(*) from time";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns), TypeList({BIGINT_TYPE}));

  query = "select count(*), count(seconds), seconds from time";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns),
            TypeList({BIGINT_TYPE, BIGINT_TYPE, INTEGER_TYPE}));

  query = "select 1, 'path', path from file";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns), TypeList({INTEGER_TYPE, TEXT_TYPE, TEXT_TYPE}));

  query = "select weekday, day, count(*), seconds from time";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns),
            TypeList({TEXT_TYPE, INTEGER_TYPE, BIGINT_TYPE, INTEGER_TYPE}));

  query = "select seconds + 1 from time";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns), TypeList({BIGINT_TYPE}));

  query = "select seconds * seconds from time";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns), TypeList({BIGINT_TYPE}));

  query = "select seconds > 1, seconds, count(seconds) from time";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns),
            TypeList({INTEGER_TYPE, INTEGER_TYPE, BIGINT_TYPE}));

  query =
      "select f1.*, seconds, f2.directory from (select path || path from file) "
      "f1, file as f2, time";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns), TypeList({TEXT_TYPE, INTEGER_TYPE, TEXT_TYPE}));

  query = "select CAST(seconds AS INTEGER) FROM time";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns), TypeList({BIGINT_TYPE}));

  query = "select CAST(seconds AS TEXT) FROM time";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns), TypeList({TEXT_TYPE}));

  query = "select CAST(seconds AS REAL) FROM time";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns), TypeList({DOUBLE_TYPE}));

  query = "select CAST(seconds AS BOOLEAN) FROM time";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns), TypeList({UNKNOWN_TYPE}));

  query = "select CAST(seconds AS DATETIME) FROM time";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns), TypeList({UNKNOWN_TYPE}));

  query = "select CAST(seconds AS BLOB) FROM time";
  getQueryColumnsInternal(query, columns, dbc);
  EXPECT_EQ(getTypes(columns), TypeList({BLOB_TYPE}));
}

using TypeMap = std::map<std::string, ColumnType>;

// Using ColumnType enum just labeling in test_column_type_determination)
class type_picker_visitor : public boost::static_visitor<ColumnType> {
 public:
  ColumnType operator()(const int64_t& i) const {
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
      "CREATE TABLE test_types_table (username varchar(30) primary key, age "
      "double);INSERT INTO test_types_table VALUES (\"mike\", 23); SELECT age "
      "from test_types_table",
      TypeMap({{"age", DOUBLE_TYPE}}));
}
}
