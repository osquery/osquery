/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/registry.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

namespace osquery {

class SQLTests : public testing::Test {};

TEST_F(SQLTests, test_simple_query_execution) {
  auto sql = SQL("SELECT * FROM time");
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1);
}

TEST_F(SQLTests, test_get_tables) {
  auto tables = SQL::getTableNames();
  EXPECT_TRUE(tables.size() > 0);
}

TEST_F(SQLTests, test_raw_access) {
  auto results = SQL::selectAllFrom("time");
  EXPECT_EQ(results.size(), 1);
}

class TestTable : public tables::TablePlugin {
 private:
  tables::TableColumns columns() {
    return {{"test_int", "INTEGER"}, {"test_text", "TEXT"}};
  }

  QueryData generate(tables::QueryContext& ctx) {
    QueryData results;
    if (ctx.constraints["test_int"].existsAndMatches("1")) {
      results.push_back({{"test_int", "1"}, {"test_text", "0"}});
    } else {
      results.push_back({{"test_int", "0"}, {"test_text", "1"}});
    }

    auto ints = ctx.constraints["test_int"].getAll<int>(tables::EQUALS);
    for (const auto& int_match : ints) {
      results.push_back({{"test_int", INTEGER(int_match)}});
    }

    return results;
  }
};

TEST_F(SQLTests, test_raw_access_context) {
  REGISTER(TestTable, "table", "test_table");
  auto results = SQL::selectAllFrom("test_table");

  EXPECT_EQ(results.size(), 1);
  EXPECT_EQ(results[0]["test_text"], "1");

  results = SQL::selectAllFrom("test_table", "test_int", tables::EQUALS, "1");
  EXPECT_EQ(results.size(), 2);

  results = SQL::selectAllFrom("test_table", "test_int", tables::EQUALS, "2");
  EXPECT_EQ(results.size(), 2);
  EXPECT_EQ(results[0]["test_int"], "0");
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  osquery::initOsquery(argc, argv);
  return RUN_ALL_TESTS();
}
