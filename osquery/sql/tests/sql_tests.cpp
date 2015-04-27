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

TEST_F(SQLTests, test_raw_access) {
  // Access to the table plugins (no SQL parsing required) works in both
  // extensions and core, though with limitations on available tables.
  auto results = SQL::selectAllFrom("time");
  EXPECT_EQ(results.size(), 1);
}

class TestTablePlugin : public tables::TablePlugin {
 private:
  tables::TableColumns columns() const {
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
  Registry::add<TestTablePlugin>("table", "test");
  auto results = SQL::selectAllFrom("test");

  EXPECT_EQ(results.size(), 1);
  EXPECT_EQ(results[0]["test_text"], "1");

  results = SQL::selectAllFrom("test", "test_int", tables::EQUALS, "1");
  EXPECT_EQ(results.size(), 2);

  results = SQL::selectAllFrom("test", "test_int", tables::EQUALS, "2");
  EXPECT_EQ(results.size(), 2);
  EXPECT_EQ(results[0]["test_int"], "0");
}
}
