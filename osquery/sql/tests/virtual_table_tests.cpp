/*
 *  Copyright (c) 2014-present, Facebook, Inc.
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
  TableColumns columns() const override {
    return {
        std::make_tuple("foo", INTEGER_TYPE, DEFAULT),
        std::make_tuple("bar", TEXT_TYPE, DEFAULT),
    };
  }
};

TEST_F(VirtualTableTests, test_tableplugin_columndefinition) {
  auto table = std::make_shared<sampleTablePlugin>();
  EXPECT_EQ("(`foo` INTEGER, `bar` TEXT)", table->columnDefinition());
}

class optionsTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("id", INTEGER_TYPE, INDEX | REQUIRED),
        std::make_tuple("username", TEXT_TYPE, OPTIMIZED),
        std::make_tuple("name", TEXT_TYPE, DEFAULT),
    };
  }

 private:
  FRIEND_TEST(VirtualTableTests, test_tableplugin_options);
};

TEST_F(VirtualTableTests, test_tableplugin_options) {
  auto table = std::make_shared<optionsTablePlugin>();
  EXPECT_EQ(INDEX | REQUIRED, std::get<2>(table->columns()[0]));

  PluginResponse response;
  PluginRequest request = {{"action", "columns"}};
  EXPECT_TRUE(table->call(request, response).ok());
  EXPECT_EQ(INTEGER(INDEX | REQUIRED), response[0]["op"]);

  response = table->routeInfo();
  EXPECT_EQ(INTEGER(INDEX | REQUIRED), response[0]["op"]);

  std::string expected_statement =
      "(`id` INTEGER PRIMARY KEY, `username` TEXT, `name` TEXT) WITHOUT ROWID";
  EXPECT_EQ(expected_statement, columnDefinition(response, true));
}

class aliasesTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("username", TEXT_TYPE, DEFAULT),
        std::make_tuple("name", TEXT_TYPE, DEFAULT),
    };
  }

  std::vector<std::string> aliases() const override {
    return {"aliases1", "aliases2"};
  }

  ColumnAliasSet columnAliases() const override {
    return {
        {"username", {"user_name"}}, {"name", {"name1", "name2"}},
    };
  }

 private:
  FRIEND_TEST(VirtualTableTests, test_tableplugin_aliases);
};

TEST_F(VirtualTableTests, test_tableplugin_aliases) {
  auto table = std::make_shared<aliasesTablePlugin>();
  std::vector<std::string> expected_aliases = {"aliases1", "aliases2"};
  EXPECT_EQ(expected_aliases, table->aliases());

  PluginResponse response;
  PluginRequest request = {{"action", "columns"}};
  EXPECT_TRUE(table->call(request, response).ok());

  PluginResponse expected_response = {
      {{"id", "column"},
       {"name", "username"},
       {"type", "TEXT"},
       {"op", INTEGER(DEFAULT)}},
      {{"id", "column"},
       {"name", "name"},
       {"type", "TEXT"},
       {"op", INTEGER(DEFAULT)}},
      {{"alias", "aliases1"}, {"id", "alias"}},
      {{"alias", "aliases2"}, {"id", "alias"}},
      {{"id", "columnAlias"}, {"name", "name1"}, {"target", "name"}},
      {{"id", "columnAlias"}, {"name", "name2"}, {"target", "name"}},
      {{"id", "columnAlias"}, {"name", "user_name"}, {"target", "username"}},
  };
  EXPECT_EQ(response, expected_response);

  // Compare the expected table definitions.
  std::string expected_statement =
      "(`username` TEXT, `name` TEXT, `name1` TEXT HIDDEN, `name2` TEXT HIDDEN,"
      " `user_name` TEXT HIDDEN)";
  EXPECT_EQ(expected_statement, columnDefinition(response, true));
  expected_statement = "(`username` TEXT, `name` TEXT)";
  EXPECT_EQ(expected_statement, columnDefinition(response, false));
}

TEST_F(VirtualTableTests, test_sqlite3_attach_vtable) {
  auto table = std::make_shared<sampleTablePlugin>();
  table->setName("sample");

  // Request a managed "connection".
  // This will be a single (potentially locked) instance or a transient
  // SQLite database if there is contention and a lock was not requested.
  auto dbc = SQLiteDBManager::get();

  // Virtual tables require the registry/plugin API to query tables.
  auto status = attachTableInternal("failed_sample", "(foo INTEGER)", dbc);
  EXPECT_EQ(status.getCode(), SQLITE_ERROR);

  // The table attach will complete only when the table name is registered.
  Registry::add<sampleTablePlugin>("table", "sample");
  PluginResponse response;
  status = Registry::call("table", "sample", {{"action", "columns"}}, response);
  EXPECT_TRUE(status.ok());

  // Use the table name, plugin-generated schema to attach.
  status = attachTableInternal("sample", columnDefinition(response), dbc);
  EXPECT_EQ(status.getCode(), SQLITE_OK);

  std::string q = "SELECT sql FROM sqlite_temp_master WHERE tbl_name='sample';";
  QueryData results;
  status = queryInternal(q, results, dbc->db());
  EXPECT_EQ(
      "CREATE VIRTUAL TABLE sample USING sample(`foo` INTEGER, `bar` TEXT)",
      results[0]["sql"]);
}

TEST_F(VirtualTableTests, test_sqlite3_table_joins) {
  // Get a database connection.
  auto dbc = SQLiteDBManager::getUnique();

  QueryData results;
  // Run a query with a join within.
  std::string statement =
      "SELECT p.pid FROM osquery_info oi, processes p WHERE oi.pid = p.pid";
  auto status = queryInternal(statement, results, dbc->db());
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 1U);
}

class pTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("x", INTEGER_TYPE, DEFAULT),
        std::make_tuple("y", INTEGER_TYPE, DEFAULT),
    };
  }

 public:
  QueryData generate(QueryContext&) override {
    return {
        {{"x", "1"}, {"y", "2"}}, {{"x", "2"}, {"y", "1"}},
    };
  }

 private:
  FRIEND_TEST(VirtualTableTests, test_constraints_stacking);
};

class kTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("x", INTEGER_TYPE, DEFAULT),
        std::make_tuple("z", INTEGER_TYPE, DEFAULT),
    };
  }

 public:
  QueryData generate(QueryContext&) override {
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
  auto dbc = SQLiteDBManager::getUnique();

  {
    // To simplify the attach, just access the column definition directly.
    auto p = std::make_shared<pTablePlugin>();
    attachTableInternal("p", p->columnDefinition(), dbc);
    auto k = std::make_shared<kTablePlugin>();
    attachTableInternal("k", k->columnDefinition(), dbc);
  }

  QueryData results;
  std::string statement;
  std::map<std::string, std::string> expected;

  std::vector<std::pair<std::string, QueryData>> constraint_tests = {
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
    queryInternal(test.first, results, dbc->db());
    EXPECT_EQ(results, test.second);
  }

  std::vector<QueryData> union_results = {
      makeResult("x", {"1", "2"}),   makeResult("k.x", {"1", "2"}),
      makeResult("k.x", {"1", "2"}), makeResult("k.x", {"1", "2"}),
      makeResult("k.x", {"1", "2"}), makeResult("k.x", {"1", "2"}),
      makeResult("k.x", {"1", "2"}), makeResult("p.x", {"1"}),
      makeResult("p.x", {"1"}),
  };

  size_t index = 0;
  for (const auto& test : constraint_tests) {
    QueryData results;
    queryInternal(test.first + " union " + test.first, results, dbc->db());
    EXPECT_EQ(results, union_results[index++]);
  }
}

class jsonTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("data", TEXT_TYPE, DEFAULT),
    };
  }

 public:
  QueryData generate(QueryContext&) override {
    return {
        {{"data", "{\"test\": 1}"}},
    };
  }

 private:
  FRIEND_TEST(VirtualTableTests, test_json_extract);
};

TEST_F(VirtualTableTests, test_json_extract) {
  // Get a database connection.
  Registry::add<jsonTablePlugin>("table", "json");
  auto dbc = SQLiteDBManager::getUnique();

  {
    auto json = std::make_shared<jsonTablePlugin>();
    attachTableInternal("json", json->columnDefinition(), dbc);
  }

  QueryData results;
  // Run a query with a join within.
  std::string statement =
      "SELECT JSON_EXTRACT(data, '$.test') AS test FROM json;";
  auto status = queryInternal(statement, results, dbc->db());
  EXPECT_TRUE(status.ok());
  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0]["test"], "1");
}

TEST_F(VirtualTableTests, test_null_values) {
  auto dbc = SQLiteDBManager::getUnique();

  std::string statement = "SELECT NULL as null_value;";
  {
    QueryData results;
    auto status = queryInternal(statement, results, dbc->db());
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(results[0]["null_value"], "");
  }

  // Try INTEGER.
  {
    QueryData results;
    statement = "SELECT CAST(NULL as INTEGER) as null_value;";
    queryInternal(statement, results, dbc->db());
    EXPECT_EQ(results[0]["null_value"], "");
  }

  // BIGINT.
  {
    QueryData results;
    statement = "SELECT CAST(NULL as BIGINT) as null_value;";
    queryInternal(statement, results, dbc->db());
    EXPECT_EQ(results[0]["null_value"], "");
  }

  // Try DOUBLE.
  {
    QueryData results;
    statement = "SELECT CAST(NULL as DOUBLE) as null_value;";
    queryInternal(statement, results, dbc->db());
    EXPECT_EQ(results[0]["null_value"], "");
  }
}

class cacheTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("data", TEXT_TYPE, DEFAULT),
    };
  }

 public:
  QueryData generate(QueryContext& context) override {
    if (context.isCached("awesome_data")) {
      // There is cache entry for awesome data.
      return {{{"data", "more_awesome_data"}}};
    } else {
      Row r = {{"data", "awesome_data"}};
      context.setCache("awesome_data", r);
      return {r};
    }
  }

 private:
  FRIEND_TEST(VirtualTableTests, test_table_cache);
};

TEST_F(VirtualTableTests, test_table_cache) {
  // Get a database connection.
  Registry::add<cacheTablePlugin>("table", "cache");
  auto dbc = SQLiteDBManager::getUnique();

  {
    auto cache = std::make_shared<cacheTablePlugin>();
    attachTableInternal("cache", cache->columnDefinition(), dbc);
  }

  QueryData results;
  // Run a query with a join within.
  std::string statement = "SELECT c2.data as data FROM cache c1, cache c2;";
  auto status = queryInternal(statement, results, dbc->db());
  dbc->clearAffectedTables();
  EXPECT_TRUE(status.ok());
  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0]["data"], "more_awesome_data");

  // Run the query again, the virtual table cache should have been expired.
  results.clear();
  statement = "SELECT data from cache c1";
  queryInternal(statement, results, dbc->db());
  ASSERT_EQ(results.size(), 1U);
  ASSERT_EQ(results[0]["data"], "awesome_data");
}
}
