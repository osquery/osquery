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
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/sql.h>

#include "osquery/sql/virtual_table.h"

namespace osquery {

class VirtualTableTests : public testing::Test {};

// sample plugin used on tests
class sampleTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const {
    return {
        {"foo", INTEGER_TYPE}, {"bar", TEXT_TYPE},
    };
  }
};

TEST_F(VirtualTableTests, test_tableplugin_columndefinition) {
  auto table = std::make_shared<sampleTablePlugin>();
  EXPECT_EQ("(`foo` INTEGER, `bar` TEXT)", table->columnDefinition());
}

TEST_F(VirtualTableTests, test_sqlite3_attach_vtable) {
  auto table = std::make_shared<sampleTablePlugin>();
  table->setName("sample");

  // Request a managed "connection".
  // This will be a single (potentially locked) instance or a transient
  // SQLite database if there is contention and a lock was not requested.
  auto dbc = SQLiteDBManager::get();

  // Virtual tables require the registry/plugin API to query tables.
  auto status = attachTableInternal("failed_sample", "(foo INTEGER)", dbc.db());
  EXPECT_EQ(status.getCode(), SQLITE_ERROR);

  // The table attach will complete only when the table name is registered.
  Registry::add<sampleTablePlugin>("table", "sample");
  PluginResponse response;
  status = Registry::call("table", "sample", {{"action", "columns"}}, response);
  EXPECT_TRUE(status.ok());

  // Use the table name, plugin-generated schema to attach.
  status = attachTableInternal("sample", columnDefinition(response), dbc.db());
  EXPECT_EQ(status.getCode(), SQLITE_OK);

  std::string q = "SELECT sql FROM sqlite_temp_master WHERE tbl_name='sample';";
  QueryData results;
  status = queryInternal(q, results, dbc.db());
  EXPECT_EQ(
      "CREATE VIRTUAL TABLE sample USING sample(`foo` INTEGER, `bar` TEXT)",
      results[0]["sql"]);
}

TEST_F(VirtualTableTests, test_sqlite3_table_joins) {
  // Get a database connection.
  auto dbc = SQLiteDBManager::get();

  QueryData results;
  // Run a query with a join within.
  std::string statement =
      "SELECT p.pid FROM osquery_info oi, processes p WHERE oi.pid = p.pid";
  auto status = queryInternal(statement, results, dbc.db());
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 1U);
}

class pTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const {
    return {
        {"x", INTEGER_TYPE}, {"y", INTEGER_TYPE},
    };
  }

 public:
  QueryData generate(QueryContext&) {
    return {
        {{"x", "1"}, {"y", "2"}}, {{"x", "2"}, {"y", "1"}},
    };
  }

 private:
  FRIEND_TEST(VirtualTableTests, test_constraints_stacking);
};

class kTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const {
    return {
        {"x", INTEGER_TYPE}, {"z", INTEGER_TYPE},
    };
  }

 public:
  QueryData generate(QueryContext&) {
    return {
        {{"x", "1"}, {"z", "2"}}, {{"x", "2"}, {"z", "1"}},
    };
  }

 private:
  FRIEND_TEST(VirtualTableTests, test_constraints_stacking);
};

static QueryData makeResult(const std::string& col,
                            const std::vector<std::string>& values) {
  QueryData results;
  for (const auto& value : values) {
    Row r;
    r[col] = value;
    results.push_back(r);
  }
  return results;
}

#define MP std::make_pair

TEST_F(VirtualTableTests, test_constraints_stacking) {
  // Add two testing tables to the registry.
  Registry::add<pTablePlugin>("table", "p");
  Registry::add<kTablePlugin>("table", "k");
  auto dbc = SQLiteDBManager::get();

  {
    // To simplify the attach, just access the column definition directly.
    auto p = std::make_shared<pTablePlugin>();
    attachTableInternal("p", p->columnDefinition(), dbc.db());
    auto k = std::make_shared<kTablePlugin>();
    attachTableInternal("k", k->columnDefinition(), dbc.db());
  }

  QueryData results;
  std::string statement;
  std::map<std::string, std::string> expected;

  std::vector<std::pair<std::string, QueryData> > constraint_tests = {
      MP("select k.x from p, k", makeResult("x", {"1", "2", "1", "2"})),
      MP("select k.x from (select * from k) k2, p, k where k.x = p.x",
         makeResult("k.x", {"1", "1", "2", "2"})),
      MP("select k.x from (select * from k where z = 1) k2, p, k where k.x = "
         "p.x",
         makeResult("k.x", {"1", "2"})),
      MP("select k.x from k k1, (select * from p) p1, k where k.x = p1.x",
         makeResult("k.x", {"1", "1", "2", "2"})),
      MP("select k.x from (select * from p) p1, k, (select * from k) k2 where "
         "k.x = p1.x",
         makeResult("k.x", {"1", "1", "2", "2"})),
      MP("select k.x from (select * from p) p1, k, (select * from k where z = "
         "2) k2 where k.x = p1.x",
         makeResult("k.x", {"1", "2"})),
      MP("select k.x from k, (select * from p) p1, k k2, (select * from k "
         "where z = 1) k3 where k.x = p1.x",
         makeResult("k.x", {"1", "1", "2", "2"})),
      MP("select p.x from (select * from k where z = 1) k1, (select * from k "
         "where z != 1) k2, p where p.x = k2.x",
         makeResult("p.x", {"1"})),
      MP("select p.x from (select * from k, (select x as xx from k where x = "
         "1) k2 where z = 1) k1, (select * from k where z != 1) k2, p, k as k3 "
         "where p.x = k2.x",
         makeResult("p.x", {"1", "1"})),
  };

  for (const auto& test : constraint_tests) {
    QueryData results;
    queryInternal(test.first, results, dbc.db());
    EXPECT_EQ(results, test.second);
  }

  std::vector<QueryData> union_results = {
      makeResult("k.x", {"1", "2"}),
      makeResult("k.x", {"1", "2"}),
      makeResult("k.x", {"1", "2"}),
      makeResult("k.x", {"1", "2"}),
      makeResult("k.x", {"1", "2"}),
      makeResult("k.x", {"1", "2"}),
      makeResult("k.x", {"1", "2"}),
      makeResult("p.x", {"1"}),
      makeResult("p.x", {"1"}),
  };

  size_t index = 0;
  for (const auto& test : constraint_tests) {
    QueryData results;
    queryInternal(test.first + " union " + test.first, results, dbc.db());
    EXPECT_EQ(results, union_results[index++]);
  }
}
}
