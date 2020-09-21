/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <gflags/gflags.h>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry.h>

namespace osquery {

class TablesTests : public testing::Test {
protected:
 void SetUp() {
   platformSetup();
   registryAndPluginInit();
   initDatabasePluginForTesting();
 }
};

TEST_F(TablesTests, test_constraint) {
  auto constraint = Constraint(EQUALS);
  constraint.expr = "none";

  EXPECT_EQ(constraint.op, EQUALS);
  EXPECT_EQ(constraint.expr, "none");
}

TEST_F(TablesTests, test_constraint_list) {
  struct ConstraintList cl;

  auto constraint = Constraint(EQUALS);
  constraint.expr = "some";

  // The constraint list is a simple struct.
  cl.add(constraint);
  EXPECT_EQ(cl.constraints_.size(), 1U);

  constraint = Constraint(EQUALS);
  constraint.expr = "some_other";
  cl.add(constraint);

  constraint = Constraint(GREATER_THAN);
  constraint.expr = "more_than";
  cl.add(constraint);
  EXPECT_EQ(cl.constraints_.size(), 3U);

  auto all_equals = cl.getAll(EQUALS);
  EXPECT_EQ(all_equals.size(), 2U);
}

TEST_F(TablesTests, test_constraint_matching) {
  struct ConstraintList cl;
  // An empty constraint list has expectations.
  EXPECT_FALSE(cl.exists());
  EXPECT_FALSE(cl.exists(GREATER_THAN));
  EXPECT_TRUE(cl.notExistsOrMatches("some"));

  auto constraint = Constraint(EQUALS);
  constraint.expr = "some";
  cl.add(constraint);

  // Test existence checks based on flags.
  EXPECT_TRUE(cl.exists());
  EXPECT_TRUE(cl.exists(EQUALS));
  EXPECT_TRUE(cl.exists(EQUALS | LESS_THAN));
  EXPECT_FALSE(cl.exists(LESS_THAN));

  EXPECT_TRUE(cl.notExistsOrMatches("some"));
  EXPECT_TRUE(cl.matches("some"));
  EXPECT_FALSE(cl.notExistsOrMatches("not_some"));

  struct ConstraintList cl2;
  cl2.affinity = INTEGER_TYPE;
  constraint = Constraint(LESS_THAN);
  constraint.expr = "1000";
  cl2.add(constraint);
  constraint = Constraint(GREATER_THAN);
  constraint.expr = "1";
  cl2.add(constraint);

  // Test both SQL-provided string types.
  EXPECT_TRUE(cl2.matches("10"));
  // ...and the type literal.
  EXPECT_TRUE(cl2.matches(10));

  // Test operator lower bounds.
  EXPECT_FALSE(cl2.matches(0));
  EXPECT_FALSE(cl2.matches(1));

  // Test operator upper bounds.
  EXPECT_FALSE(cl2.matches(1000));
  EXPECT_FALSE(cl2.matches(1001));

  // Now test inclusive bounds.
  struct ConstraintList cl3;
  constraint = Constraint(LESS_THAN_OR_EQUALS);
  constraint.expr = "1000";
  cl3.add(constraint);
  constraint = Constraint(GREATER_THAN_OR_EQUALS);
  constraint.expr = "1";
  cl3.add(constraint);

  EXPECT_FALSE(cl3.matches(1001));
  EXPECT_TRUE(cl3.matches(1000));

  EXPECT_FALSE(cl3.matches(0));
  EXPECT_TRUE(cl3.matches(1));
}

TEST_F(TablesTests, test_constraint_map) {
  ConstraintMap cm;

  cm["path"].add(Constraint(EQUALS, "some"));

  // If a constraint list exists for a map key, normal constraints apply.
  EXPECT_TRUE(cm["path"].matches("some"));
  EXPECT_FALSE(cm["path"].matches("not_some"));

  // If a constraint list does not exist, then all checks will match.
  // If there is no predicate clause then all results will match.
  EXPECT_TRUE(cm["not_path"].matches("some"));
  EXPECT_TRUE(cm["not_path"].notExistsOrMatches("some"));
  EXPECT_FALSE(cm["not_path"].exists());
  EXPECT_FALSE(cm["not_path"].existsAndMatches("some"));

  // And of the column has constraints:
  EXPECT_TRUE(cm["path"].notExistsOrMatches("some"));
  EXPECT_FALSE(cm["path"].notExistsOrMatches("not_some"));
  EXPECT_TRUE(cm["path"].exists());
  EXPECT_TRUE(cm["path"].existsAndMatches("some"));
}

TEST_F(TablesTests, test_constraint_map_cast) {
  ConstraintMap cm;

  cm["num"].affinity = INTEGER_TYPE;
  cm["num"].add(Constraint(EQUALS, "hello"));

  EXPECT_FALSE(cm["num"].existsAndMatches("hello"));
}

class TestTablePlugin : public TablePlugin {
 public:
  void testSetCache(uint64_t step, uint64_t interval) {
    TableRows r;
    QueryContext ctx;
    ctx.useCache(true);
    setCache(step, interval, ctx, r);
  }

  bool testIsCached(size_t interval) {
    QueryContext ctx;
    ctx.useCache(true);
    return isCached(interval, ctx);
  }
};

TEST_F(TablesTests, test_caching) {
  TestTablePlugin test;
  // By default the interval and step is 0, so a step of 5 will not be cached.
  EXPECT_FALSE(test.testIsCached(5));

  TablePlugin::kCacheInterval = 5;
  TablePlugin::kCacheStep = 1;
  EXPECT_FALSE(test.testIsCached(5));
  // Set the current time to 1, and the interval at 5.
  test.testSetCache(TablePlugin::kCacheStep, TablePlugin::kCacheInterval);
  // Time at 1 is cached for an interval of 5, so at time 5 the cache is fresh.
  EXPECT_TRUE(test.testIsCached(5));
  // 6 is the end of the cache, it is not fresh.
  EXPECT_FALSE(test.testIsCached(6));
  // 7 is past the cache, it is not fresh.
  EXPECT_FALSE(test.testIsCached(7));

  // Set the time at now to 2.
  TablePlugin::kCacheStep = 2;
  test.testSetCache(TablePlugin::kCacheStep, TablePlugin::kCacheInterval);
  EXPECT_TRUE(test.testIsCached(5));
  // Now 6 is within the freshness of 2 + 5.
  EXPECT_TRUE(test.testIsCached(6));
  EXPECT_FALSE(test.testIsCached(7));
}
}
