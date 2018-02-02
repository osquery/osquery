/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <osquery/tables.h>

namespace osquery {

class TablesTests : public testing::Test {};

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

const TableDefinition tbl_test1_def = {
    "test1",
    {/* table aliases */},
    {
        std::make_tuple("time", BIGINT_TYPE, ColumnOptions::DEFAULT),
    },
    {/* column aliases */},
    TableAttributes::CACHEABLE};

class TestTablePlugin : public TablePluginBase {
 public:
  TestTablePlugin() : TablePluginBase(tbl_test1_def) {}
};

extern size_t kTableCacheStep;
extern size_t kTableCacheInterval;

#include <gflags/gflags.h>
DECLARE_bool(disable_caching);

// emulate how sceduler uses step and interval.
// kTableCacheStep increments every second.
// kTableCacheInterval is the interval of the query in seconds.
// While it's a shared value, it's updated each time a query is run.
// Since cache instances snapshot interval on set(), conflicts do not occur.
// When cacheing data, the cache will snapshot the current values:
//   snapshotStep=kTableCacheStep, snapshotInterval=kTableCacheInterval
// The cached data remains valid while kTableCacheStep < (snapshotStep +
// snapshotInterval) For example, if interval is 60 seconds, and data is cached
// at kTableCacheInterval = 1000, the data is valid until kTableCacheStep >=
// 1060

TEST_F(TablesTests, test_caching) {
  TestTablePlugin test;

  FLAGS_disable_caching = false;

  size_t testQueryIntervalSeconds = 60; // seconds

  kTableCacheInterval = testQueryIntervalSeconds;
  kTableCacheStep = 1;

  // By default the interval and step is 0, so a step of 5 will not be cached.

  EXPECT_FALSE(test.cache().isCached());

  test.cache().set(QueryData());
  EXPECT_TRUE(test.cache().isCached());

  // 6 is the end of the cache, it is not fresh.
  kTableCacheStep = testQueryIntervalSeconds;
  EXPECT_TRUE(test.cache().isCached());
  kTableCacheStep += 1;
  EXPECT_FALSE(test.cache().isCached());
  kTableCacheStep += 1;
  EXPECT_FALSE(test.cache().isCached());

  test.cache().set(QueryData());
  EXPECT_TRUE(test.cache().isCached());
  kTableCacheStep += testQueryIntervalSeconds - 1;
  EXPECT_TRUE(test.cache().isCached());
  kTableCacheStep += 1;
  EXPECT_FALSE(test.cache().isCached());
}
} // namespace osquery
