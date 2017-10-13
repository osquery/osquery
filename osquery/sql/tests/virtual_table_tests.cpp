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
        std::make_tuple("foo", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("bar", TEXT_TYPE, ColumnOptions::DEFAULT),
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
        std::make_tuple(
            "id", INTEGER_TYPE, ColumnOptions::INDEX | ColumnOptions::REQUIRED),
        std::make_tuple("username", TEXT_TYPE, ColumnOptions::OPTIMIZED),
        std::make_tuple("name", TEXT_TYPE, ColumnOptions::DEFAULT),
    };
  }

 private:
  FRIEND_TEST(VirtualTableTests, test_tableplugin_options);
};

TEST_F(VirtualTableTests, test_tableplugin_options) {
  auto table = std::make_shared<optionsTablePlugin>();
  EXPECT_EQ(ColumnOptions::INDEX | ColumnOptions::REQUIRED,
            std::get<2>(table->columns()[0]));

  PluginResponse response;
  PluginRequest request = {{"action", "columns"}};
  EXPECT_TRUE(table->call(request, response).ok());
  auto index_required =
      static_cast<size_t>(ColumnOptions::INDEX | ColumnOptions::REQUIRED);
  EXPECT_EQ(INTEGER(index_required), response[0]["op"]);

  response = table->routeInfo();
  EXPECT_EQ(INTEGER(index_required), response[0]["op"]);

  std::string expected_statement =
      "(`id` INTEGER, `username` TEXT, `name` TEXT, PRIMARY KEY (`id`)) "
      "WITHOUT ROWID";
  EXPECT_EQ(expected_statement, columnDefinition(response, true));
}

class moreOptionsTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("id", INTEGER_TYPE, ColumnOptions::INDEX),
        std::make_tuple("username", TEXT_TYPE, ColumnOptions::ADDITIONAL),
        std::make_tuple("name", TEXT_TYPE, ColumnOptions::DEFAULT),
    };
  }

 private:
  FRIEND_TEST(VirtualTableTests, test_tableplugin_moreoptions);
};

TEST_F(VirtualTableTests, test_tableplugin_moreoptions) {
  auto table = std::make_shared<moreOptionsTablePlugin>();

  PluginResponse response;
  PluginRequest request = {{"action", "columns"}};
  EXPECT_TRUE(table->call(request, response).ok());

  std::string expected_statement =
      "(`id` INTEGER, `username` TEXT, `name` TEXT, PRIMARY KEY (`id`, "
      "`username`)) WITHOUT ROWID";
  EXPECT_EQ(expected_statement, columnDefinition(response, true));
}

class aliasesTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("username", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("name", TEXT_TYPE, ColumnOptions::DEFAULT),
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

  auto default_option = static_cast<size_t>(ColumnOptions::DEFAULT);
  PluginResponse expected_response = {
      {{"id", "column"},
       {"name", "username"},
       {"type", "TEXT"},
       {"op", INTEGER(default_option)}},
      {{"id", "column"},
       {"name", "name"},
       {"type", "TEXT"},
       {"op", INTEGER(default_option)}},
      {{"alias", "aliases1"}, {"id", "alias"}},
      {{"alias", "aliases2"}, {"id", "alias"}},
      {{"id", "columnAlias"}, {"name", "name1"}, {"target", "name"}},
      {{"id", "columnAlias"}, {"name", "name2"}, {"target", "name"}},
      {{"id", "columnAlias"}, {"name", "user_name"}, {"target", "username"}},
      {{"attributes", "0"}, {"id", "attributes"}},
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
  auto tables = RegistryFactory::get().registry("table");
  tables->add("sample", std::make_shared<sampleTablePlugin>());
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
        std::make_tuple("x", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("y", INTEGER_TYPE, ColumnOptions::DEFAULT),
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
        std::make_tuple("x", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("z", INTEGER_TYPE, ColumnOptions::DEFAULT),
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
  auto tables = RegistryFactory::get().registry("table");
  tables->add("p", std::make_shared<pTablePlugin>());
  tables->add("k", std::make_shared<kTablePlugin>());
  auto dbc = SQLiteDBManager::getUnique();

  {
    // To simplify the attach, just access the column definition directly.
    auto p = std::make_shared<pTablePlugin>();
    attachTableInternal("p", p->columnDefinition(), dbc);
    auto k = std::make_shared<kTablePlugin>();
    attachTableInternal("k", k->columnDefinition(), dbc);
  }

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
      makeResult("x", {"1", "2"}),
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
    queryInternal(test.first + " union " + test.first, results, dbc->db());
    EXPECT_EQ(results, union_results[index++]);
  }
}

class jsonTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("data", TEXT_TYPE, ColumnOptions::DEFAULT),
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
  auto tables = RegistryFactory::get().registry("table");
  auto json = std::make_shared<jsonTablePlugin>();
  tables->add("json", json);

  auto dbc = SQLiteDBManager::getUnique();
  attachTableInternal("json", json->columnDefinition(), dbc);

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
        std::make_tuple("data", TEXT_TYPE, ColumnOptions::DEFAULT),
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
  auto tables = RegistryFactory::get().registry("table");
  auto cache = std::make_shared<cacheTablePlugin>();
  tables->add("cache", cache);
  auto dbc = SQLiteDBManager::getUnique();
  attachTableInternal("cache", cache->columnDefinition(), dbc);

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

class tableCacheTablePlugin : public TablePlugin {
 public:
  TableColumns columns() const override {
    return {
        std::make_tuple("i", TEXT_TYPE, ColumnOptions::INDEX),
        std::make_tuple("d", TEXT_TYPE, ColumnOptions::DEFAULT),
    };
  }

  TableAttributes attributes() const override {
    return TableAttributes::CACHEABLE;
  }

  QueryData generate(QueryContext& ctx) override {
    if (isCached(60, ctx)) {
      return getCache();
    }

    generates_++;
    Row r;
    r["i"] = "1";
    setCache(60, 1, ctx, {r});
    return {r};
  }

  size_t generates_{0};
};

TEST_F(VirtualTableTests, test_table_results_cache) {
  // Get a database connection.
  auto tables = RegistryFactory::get().registry("table");
  auto cache = std::make_shared<tableCacheTablePlugin>();
  tables->add("table_cache", cache);
  auto dbc = SQLiteDBManager::getUnique();
  attachTableInternal("table_cache", cache->columnDefinition(), dbc);

  QueryData results;
  std::string statement = "SELECT * from table_cache;";
  auto status = queryInternal(statement, results, dbc->db());
  dbc->clearAffectedTables();

  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 1U);
  EXPECT_EQ(cache->generates_, 1U);

  // Run the query again, the virtual table cache was not requested.
  results.clear();
  statement = "SELECT * from table_cache;";
  queryInternal(statement, results, dbc->db());
  EXPECT_EQ(results.size(), 1U);

  // The table should have used the cache.
  EXPECT_EQ(cache->generates_, 2U);

  // Now request that caching be used.
  dbc->useCache(true);

  // Run the query again, the virtual table cache will be populated.
  results.clear();
  statement = "SELECT * from table_cache;";
  queryInternal(statement, results, dbc->db());
  EXPECT_EQ(results.size(), 1U);
  EXPECT_EQ(cache->generates_, 3U);

  // Run the query again, the virtual table cache will be returned.
  results.clear();
  statement = "SELECT * from table_cache;";
  queryInternal(statement, results, dbc->db());
  EXPECT_EQ(results.size(), 1U);
  EXPECT_EQ(cache->generates_, 3U);

  // Once last time with constraints that invalidate the cache results.
  results.clear();
  statement = "SELECT * from table_cache where i = '1';";
  queryInternal(statement, results, dbc->db());
  EXPECT_EQ(results.size(), 1U);

  // The table should NOT have used the cache.
  EXPECT_EQ(cache->generates_, 4U);
}

class yieldTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("index", INTEGER_TYPE, ColumnOptions::DEFAULT),
    };
  }

 public:
  bool usesGenerator() const override {
    return true;
  }

  void generator(RowYield& yield, QueryContext& qc) override {
    for (size_t i = 0; i < 10; i++) {
      Row r;
      r["index"] = std::to_string(index_++);
      yield(r);
    }
  }

 private:
  size_t index_{0};
};

TEST_F(VirtualTableTests, test_yield_generator) {
  auto table = std::make_shared<yieldTablePlugin>();
  auto table_registry = RegistryFactory::get().registry("table");
  table_registry->add("yield", table);

  auto dbc = SQLiteDBManager::getUnique();
  attachTableInternal("yield", table->columnDefinition(), dbc);

  QueryData results;
  queryInternal("SELECT * from yield", results, dbc->db());
  dbc->clearAffectedTables();
  EXPECT_EQ(results.size(), 10U);
  EXPECT_EQ(results[0]["index"], "0");

  results.clear();
  queryInternal("SELECT * from yield", results, dbc->db());
  dbc->clearAffectedTables();
  EXPECT_EQ(results[0]["index"], "10");
}

class likeTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("i", TEXT_TYPE, ColumnOptions::INDEX),
        std::make_tuple("op", TEXT_TYPE, ColumnOptions::DEFAULT),
    };
  }

 public:
  QueryData generate(QueryContext& context) override {
    QueryData results;

    // To test, we'll move all predicate constraints into the result set.
    // First we'll move constrains for the column `i` using operands =, LIKE.
    auto i = context.constraints["i"].getAll(EQUALS);
    for (const auto& constraint : i) {
      Row r;
      r["i"] = constraint;
      r["op"] = "EQUALS";
      results.push_back(r);
    }

    i = context.constraints["i"].getAll(LIKE);
    for (const auto& constraint : i) {
      Row r;
      r["i"] = constraint;
      r["op"] = "LIKE";
      results.push_back(r);
    }

    return results;
  }

 private:
  FRIEND_TEST(VirtualTableTests, test_like_constraints);
};

TEST_F(VirtualTableTests, test_like_constraints) {
  auto table = std::make_shared<likeTablePlugin>();
  auto table_registry = RegistryFactory::get().registry("table");
  table_registry->add("like_table", table);

  auto dbc = SQLiteDBManager::getUnique();
  attachTableInternal("like_table", table->columnDefinition(), dbc);

  // Base case, without constrains this table has no results.
  QueryData results;
  queryInternal("SELECT * FROM like_table", results, dbc->db());
  dbc->clearAffectedTables();
  ASSERT_EQ(results.size(), 0U);

  // A single EQUAL constraint's value is emitted.
  queryInternal("SELECT * FROM like_table WHERE i = '1'", results, dbc->db());
  dbc->clearAffectedTables();
  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0]["i"], "1");
  EXPECT_EQ(results[0]["op"], "EQUALS");

  // When using OR, both values should be added.
  results.clear();
  queryInternal(
      "SELECT * FROM like_table WHERE i = '1' OR i = '2'", results, dbc->db());
  dbc->clearAffectedTables();
  ASSERT_EQ(results.size(), 2U);
  EXPECT_EQ(results[0]["i"], "1");
  EXPECT_EQ(results[0]["op"], "EQUALS");
  EXPECT_EQ(results[1]["i"], "2");
  EXPECT_EQ(results[1]["op"], "EQUALS");

  // When using a LIKE, the value (with substitution character) is emitted.
  results.clear();
  queryInternal(
      "SELECT * FROM like_table WHERE i LIKE '/test/1/%'", results, dbc->db());
  dbc->clearAffectedTables();
  ASSERT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0]["i"], "/test/1/%");
  EXPECT_EQ(results[0]["op"], "LIKE");

  // As with EQUAL, multiple LIKEs mean multiple values.
  results.clear();
  queryInternal(
      "SELECT * FROM like_table WHERE i LIKE '/test/1/%' OR i LIKE '/test/2/%'",
      results,
      dbc->db());
  dbc->clearAffectedTables();
  ASSERT_EQ(results.size(), 2U);
  EXPECT_EQ(results[0]["i"], "/test/1/%");
  EXPECT_EQ(results[0]["op"], "LIKE");
  EXPECT_EQ(results[1]["i"], "/test/2/%");
  EXPECT_EQ(results[1]["op"], "LIKE");

  // As with EQUAL, multiple LIKEs mean multiple values.
  results.clear();
  queryInternal(
      "SELECT * FROM like_table WHERE i LIKE '/home/%/downloads' OR i LIKE "
      "'/home/%/documents'",
      results,
      dbc->db());
  dbc->clearAffectedTables();
  ASSERT_EQ(results.size(), 2U);
  EXPECT_EQ(results[0]["i"], "/home/%/downloads");
  EXPECT_EQ(results[0]["op"], "LIKE");
  EXPECT_EQ(results[1]["i"], "/home/%/documents");
  EXPECT_EQ(results[1]["op"], "LIKE");
}

class indexIOptimizedTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("i", INTEGER_TYPE, ColumnOptions::INDEX),
        std::make_tuple("j", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("text", INTEGER_TYPE, ColumnOptions::DEFAULT),
    };
  }

 public:
  QueryData generate(QueryContext& context) override {
    scans++;

    QueryData results;
    auto indexes = context.constraints["i"].getAll<int>(EQUALS);
    for (const auto& i : indexes) {
      results.push_back(
          {{"i", INTEGER(i)}, {"j", INTEGER(i * 10)}, {"text", "none"}});
    }
    if (indexes.empty()) {
      for (size_t i = 0; i < 100; i++) {
        results.push_back(
            {{"i", INTEGER(i)}, {"j", INTEGER(i * 10)}, {"text", "some"}});
      }
    }
    return results;
  }

  // Here the goal is to expect/assume the number of scans.
  size_t scans{0};
};

class indexJOptimizedTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("j", INTEGER_TYPE, ColumnOptions::INDEX),
        std::make_tuple("text", INTEGER_TYPE, ColumnOptions::DEFAULT),
    };
  }

 public:
  QueryData generate(QueryContext& context) override {
    scans++;

    QueryData results;
    auto indexes = context.constraints["j"].getAll<int>(EQUALS);
    for (const auto& j : indexes) {
      results.push_back({{"j", INTEGER(j)}, {"text", "none"}});
    }
    if (indexes.empty()) {
      for (size_t j = 0; j < 100; j++) {
        results.push_back({{"j", INTEGER(j)}, {"text", "some"}});
      }
    }
    return results;
  }

  // Here the goal is to expect/assume the number of scans.
  size_t scans{0};
};

class defaultScanTablePlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("i", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("text", INTEGER_TYPE, ColumnOptions::DEFAULT),
    };
  }

 public:
  QueryData generate(QueryContext& context) override {
    scans++;

    QueryData results;
    for (size_t i = 0; i < 10; i++) {
      results.push_back({{"i", INTEGER(i)}, {"text", "some"}});
    }
    return results;
  }

  // Here the goal is to expect/assume the number of scans.
  size_t scans{0};
};

TEST_F(VirtualTableTests, test_indexing_costs) {
  // Get a database connection.
  auto dbc = SQLiteDBManager::getUnique();
  auto table_registry = RegistryFactory::get().registry("table");

  auto i = std::make_shared<indexIOptimizedTablePlugin>();
  table_registry->add("index_i", i);
  attachTableInternal("index_i", i->columnDefinition(), dbc);

  auto j = std::make_shared<indexJOptimizedTablePlugin>();
  table_registry->add("index_j", j);
  attachTableInternal("index_j", j->columnDefinition(), dbc);

  auto default_scan = std::make_shared<defaultScanTablePlugin>();
  table_registry->add("default_scan", default_scan);
  attachTableInternal("default_scan", default_scan->columnDefinition(), dbc);

  QueryData results;
  queryInternal(
      "SELECT * from default_scan JOIN index_i using (i);", results, dbc->db());
  dbc->clearAffectedTables();

  // We expect index_i to optimize, meaning the constraint evaluation
  // understood the marked columns and returned a low cost.
  ASSERT_EQ(1U, default_scan->scans);
  EXPECT_EQ(10U, i->scans);

  // Reset.
  default_scan->scans = 0;
  i->scans = 0;

  // The inverse should also hold, all cost evaluations will be high.
  queryInternal(
      "SELECT * from index_i JOIN default_scan using (i);", results, dbc->db());
  dbc->clearAffectedTables();
  EXPECT_EQ(10U, i->scans);
  EXPECT_EQ(1U, default_scan->scans);

  // Reset.
  default_scan->scans = 0;
  i->scans = 0;

  queryInternal(
      "SELECT * from default_scan join index_i using (i) join index_j using "
      "(j);",
      results,
      dbc->db());
  dbc->clearAffectedTables();
  ASSERT_EQ(1U, default_scan->scans);
  EXPECT_EQ(10U, i->scans);
  EXPECT_EQ(10U, j->scans);
}
}
