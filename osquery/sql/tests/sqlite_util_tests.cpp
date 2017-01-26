/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
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
  SQLiteDBManager::resetPrimary();
  auto new_internal_db = SQLiteDBManager::get()->db();

  // Assume the internal (primary) database we reset and recreated.
  EXPECT_NE(nullptr, new_internal_db);
  EXPECT_NE(internal_db, new_internal_db);
}

TEST_F(SQLiteUtilTests, test_direct_query_execution) {
  auto dbc = getTestDBC();
  QueryData results;
  auto status = queryInternal(kTestQuery, results, dbc->db());
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results, getTestDBExpectedResults());
}

TEST_F(SQLiteUtilTests, test_passing_callback_no_data_param) {
  char* err = nullptr;
  auto dbc = getTestDBC();
  sqlite3_exec(dbc->db(), kTestQuery.c_str(), queryDataCallback, nullptr, &err);
  EXPECT_TRUE(err != nullptr);
  if (err != nullptr) {
    sqlite3_free(err);
  }
}

TEST_F(SQLiteUtilTests, test_aggregate_query) {
  auto dbc = getTestDBC();
  QueryData results;
  auto status = queryInternal(kTestQuery, results, dbc->db());
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

    QueryData expected;
    auto status = queryInternal(kTestQuery, expected, dbc->db());
    EXPECT_EQ(expected, r.second);
  }
}

TEST_F(SQLiteUtilTests, test_affected_tables) {
  auto dbc = getTestDBC();
  QueryData results;
  auto status = queryInternal("SELECT * FROM time", results, dbc->db());

  // Since the table scanned from "time", it should be recorded as affected.
  EXPECT_EQ(dbc->affected_tables_.count("time"), 1U);
  dbc->clearAffectedTables();
  EXPECT_EQ(dbc->affected_tables_.size(), 0U);
}

TEST_F(SQLiteUtilTests, test_table_attributes_event_based) {
  {
    SQLInternal sql_internal("select * from process_events");
    if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
      EXPECT_TRUE(sql_internal.ok());
      EXPECT_TRUE(sql_internal.eventBased());
    }
  }

  {
    SQLInternal sql_internal("select * from time");
    EXPECT_TRUE(sql_internal.ok());
    EXPECT_FALSE(sql_internal.eventBased());
  }
}

TEST_F(SQLiteUtilTests, test_get_query_columns) {
  auto dbc = getTestDBC();
  TableColumns results;

  std::string query = "SELECT seconds, version FROM time JOIN osquery_info";
  auto status = getQueryColumnsInternal(query, results, dbc->db());
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(2U, results.size());
  EXPECT_EQ(std::make_tuple(
                std::string("seconds"), INTEGER_TYPE, ColumnOptions::DEFAULT),
            results[0]);
  EXPECT_EQ(std::make_tuple(
                std::string("version"), TEXT_TYPE, ColumnOptions::DEFAULT),
            results[1]);

  query = "SELECT * FROM foo";
  status = getQueryColumnsInternal(query, results, dbc->db());
  ASSERT_FALSE(status.ok());
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
  getQueryColumnsInternal(query, columns, dbc->db());
  EXPECT_EQ(getTypes(columns), TypeList({TEXT_TYPE, TEXT_TYPE}));

  query = "select path, seconds from file, time";
  getQueryColumnsInternal(query, columns, dbc->db());
  EXPECT_EQ(getTypes(columns), TypeList({TEXT_TYPE, INTEGER_TYPE}));

  query = "select path || path from file";
  getQueryColumnsInternal(query, columns, dbc->db());
  EXPECT_EQ(getTypes(columns), TypeList({TEXT_TYPE}));

  query = "select seconds, path || path from file, time";
  getQueryColumnsInternal(query, columns, dbc->db());
  EXPECT_EQ(getTypes(columns), TypeList({INTEGER_TYPE, TEXT_TYPE}));

  query = "select seconds, seconds from time";
  getQueryColumnsInternal(query, columns, dbc->db());
  EXPECT_EQ(getTypes(columns), TypeList({INTEGER_TYPE, INTEGER_TYPE}));

  query = "select count(*) from time";
  getQueryColumnsInternal(query, columns, dbc->db());
  EXPECT_EQ(getTypes(columns), TypeList({BIGINT_TYPE}));

  query = "select count(*), count(seconds), seconds from time";
  getQueryColumnsInternal(query, columns, dbc->db());
  EXPECT_EQ(getTypes(columns),
            TypeList({BIGINT_TYPE, BIGINT_TYPE, INTEGER_TYPE}));

  query = "select 1, 'path', path from file";
  getQueryColumnsInternal(query, columns, dbc->db());
  EXPECT_EQ(getTypes(columns), TypeList({INTEGER_TYPE, TEXT_TYPE, TEXT_TYPE}));

  query = "select weekday, day, count(*), seconds from time";
  getQueryColumnsInternal(query, columns, dbc->db());
  EXPECT_EQ(getTypes(columns),
            TypeList({TEXT_TYPE, INTEGER_TYPE, BIGINT_TYPE, INTEGER_TYPE}));

  query = "select seconds + 1 from time";
  getQueryColumnsInternal(query, columns, dbc->db());
  EXPECT_EQ(getTypes(columns), TypeList({BIGINT_TYPE}));

  query = "select seconds * seconds from time";
  getQueryColumnsInternal(query, columns, dbc->db());
  EXPECT_EQ(getTypes(columns), TypeList({BIGINT_TYPE}));

  query = "select seconds > 1, seconds, count(seconds) from time";
  getQueryColumnsInternal(query, columns, dbc->db());
  EXPECT_EQ(getTypes(columns),
            TypeList({INTEGER_TYPE, INTEGER_TYPE, BIGINT_TYPE}));

  query =
      "select f1.*, seconds, f2.directory from (select path || path from file) "
      "f1, file as f2, time";
  getQueryColumnsInternal(query, columns, dbc->db());
  EXPECT_EQ(getTypes(columns), TypeList({TEXT_TYPE, INTEGER_TYPE, TEXT_TYPE}));
}
}
