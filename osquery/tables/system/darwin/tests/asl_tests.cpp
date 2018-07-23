/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <string>
#include <thread>

#include <gtest/gtest.h>

#include <osquery/filesystem.h>
#include <osquery/sql.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/darwin/asl_utils.h"
#include "osquery/tests/test_util.h"

namespace osquery {
namespace tables {

class AslTests : public testing::Test {};

// macOS ASL is deprecated in 10.12
_Pragma("clang diagnostic push");
_Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"");

#ifndef OLD_ASL_API
TEST_F(AslTests, test_add_query_op) {
  aslmsg query = asl_new(ASL_TYPE_QUERY);
  ASSERT_EQ((uint32_t)ASL_TYPE_QUERY, asl_get_type(query));
  ASSERT_EQ((size_t)0, asl_count(query));

  const char *key, *val;
  uint32_t op;

  addQueryOp(query, "sender", "bar", EQUALS, TEXT_TYPE);
  ASSERT_EQ((size_t)1, asl_count(query));

  ASSERT_EQ(0, asl_fetch_key_val_op(query, 0, &key, &val, &op));
  ASSERT_STREQ("Sender", key);
  ASSERT_STREQ("bar", val);
  ASSERT_EQ((uint32_t)ASL_QUERY_OP_EQUAL, op);

  addQueryOp(query, "level", "1", GREATER_THAN, INTEGER_TYPE);
  ASSERT_EQ((size_t)2, asl_count(query));
  ASSERT_EQ(0, asl_fetch_key_val_op(query, 1, &key, &val, &op));
  ASSERT_STREQ("Level", key);
  ASSERT_STREQ("1", val);
  ASSERT_EQ((uint32_t)(ASL_QUERY_OP_GREATER | ASL_QUERY_OP_NUMERIC), op);

  addQueryOp(query, "gid", "999", LESS_THAN, BIGINT_TYPE);
  ASSERT_EQ((size_t)3, asl_count(query));
  ASSERT_EQ(0, asl_fetch_key_val_op(query, 2, &key, &val, &op));
  ASSERT_STREQ("GID", key);
  ASSERT_STREQ("999", val);
  ASSERT_EQ((uint32_t)(ASL_QUERY_OP_LESS | ASL_QUERY_OP_NUMERIC), op);

  addQueryOp(query, "facility", "hoo", GREATER_THAN_OR_EQUALS, TEXT_TYPE);
  ASSERT_EQ((size_t)4, asl_count(query));
  ASSERT_EQ(0, asl_fetch_key_val_op(query, 3, &key, &val, &op));
  ASSERT_STREQ("Facility", key);
  ASSERT_STREQ("hoo", val);
  ASSERT_EQ((uint32_t)ASL_QUERY_OP_GREATER_EQUAL, op);

  addQueryOp(query, "pid", "30", LESS_THAN_OR_EQUALS, INTEGER_TYPE);
  ASSERT_EQ((size_t)5, asl_count(query));
  ASSERT_EQ(0, asl_fetch_key_val_op(query, 4, &key, &val, &op));
  ASSERT_STREQ("PID", key);
  ASSERT_STREQ("30", val);
  ASSERT_EQ((uint32_t)(ASL_QUERY_OP_LESS_EQUAL | ASL_QUERY_OP_NUMERIC), op);

  addQueryOp(query, "ref_proc", "%tom%", LIKE, TEXT_TYPE);
  ASSERT_EQ((size_t)6, asl_count(query));
  ASSERT_EQ(0, asl_fetch_key_val_op(query, 5, &key, &val, &op));
  ASSERT_STREQ("RefProc", key);
  ASSERT_STREQ(".*tom.*", val);
  ASSERT_EQ((uint32_t)(ASL_QUERY_OP_EQUAL | ASL_QUERY_OP_REGEX |
                       ASL_QUERY_OP_CASEFOLD),
            op);

  // Queries against the extra column should not be sent to ASL
  addQueryOp(query, "extra", "tom", EQUALS, TEXT_TYPE);
  ASSERT_EQ((size_t)6, asl_count(query));

  // Queries with unsupported operators should not be sent to ASL
  addQueryOp(query, "host", "tom", GLOB, TEXT_TYPE);
  ASSERT_EQ((size_t)6, asl_count(query));

  asl_release(query);
}

TEST_F(AslTests, test_create_asl_query) {
  QueryContext ctx;
  ctx.constraints["sender"].add(Constraint(EQUALS, "bar"));
  ctx.constraints["sender"].add(Constraint(LIKE, "%a%"));
  ctx.constraints["message"].affinity = INTEGER_TYPE;
  ctx.constraints["message"].add(Constraint(LESS_THAN, "10"));

  aslmsg query = createAslQuery(ctx);

  ASSERT_EQ((uint32_t)ASL_TYPE_QUERY, asl_get_type(query));
  ASSERT_EQ((size_t)3, asl_count(query));

  const char *key, *val;
  uint32_t op;

  // Ordering doesn't really matter here, only that we only ended up with
  // (message, baz, LESS) and (sender, bar, EQUAL)
  ASSERT_EQ(0, asl_fetch_key_val_op(query, 0, &key, &val, &op));
  ASSERT_STREQ("Message", key);
  ASSERT_STREQ("10", val);
  ASSERT_EQ((uint32_t)(ASL_QUERY_OP_LESS | ASL_QUERY_OP_NUMERIC), op);

  ASSERT_EQ(0, asl_fetch_key_val_op(query, 1, &key, &val, &op));
  ASSERT_STREQ("Sender", key);
  ASSERT_STREQ("bar", val);
  ASSERT_EQ((uint32_t)ASL_QUERY_OP_EQUAL, op);

  ASSERT_EQ(0, asl_fetch_key_val_op(query, 2, &key, &val, &op));
  ASSERT_STREQ("Sender", key);
  ASSERT_STREQ(".*a.*", val);
  ASSERT_EQ((uint32_t)(ASL_QUERY_OP_EQUAL | ASL_QUERY_OP_REGEX |
                       ASL_QUERY_OP_CASEFOLD),
            op);

  asl_release(query);
}
#endif

TEST_F(AslTests, test_read_asl_row) {
  aslmsg row = asl_new(ASL_TYPE_MSG);
  ASSERT_EQ(0, asl_set(row, "Sender", "foo"));
  ASSERT_EQ(0, asl_set(row, "Level", "1"));
  ASSERT_EQ(0, asl_set(row, "Message", "bar"));
  ASSERT_EQ(0, asl_set(row, "Bang", "bang_val"));

  Row r;
  readAslRow(row, r);

  ASSERT_EQ((size_t)4, r.size());

  ASSERT_EQ("foo", r["sender"]);
  ASSERT_EQ("1", r["level"]);
  ASSERT_EQ("bar", r["message"]);
  ASSERT_EQ((size_t)0, r.count("bang"));
  ASSERT_EQ("{\"Bang\":\"bang_val\"}\n", r["extra"]);

  asl_release(row);
}

TEST_F(AslTests, test_convert_like_regex) {
  EXPECT_EQ(".*", convertLikeRegex("%"));
  EXPECT_EQ("foo.*", convertLikeRegex("foo%"));
  EXPECT_EQ(".*foo.*", convertLikeRegex("%foo%"));
  EXPECT_EQ(".*.*", convertLikeRegex("%%"));
  EXPECT_EQ(".*.*", convertLikeRegex("%%"));
  EXPECT_EQ(".", convertLikeRegex("_"));
  EXPECT_EQ("foo.", convertLikeRegex("foo_"));
  EXPECT_EQ(".foo", convertLikeRegex("_foo"));
  EXPECT_EQ(".foo.", convertLikeRegex("_foo_"));
  EXPECT_EQ("..*", convertLikeRegex("_%"));
  EXPECT_EQ(".*foo..*", convertLikeRegex("%foo_%"));
}

TEST_F(AslTests, test_actual_query) {
  auto version = SQL::selectAllFrom("os_version");
  unsigned long minor_version;
  auto s = safeStrtoul(version[0]["minor"], 10, minor_version);
  if (minor_version >= 12) {
    // macOS Sierra and above do not support ASL.
    return;
  }

  // An integration test, this test writes to ASL, and then verifies that we
  // can query for the written log
  std::string time_str = std::to_string(std::time(nullptr));
  std::string command =
      "logger -p user.notice -t osquery_test 'osquery_test: "
      "test_actual_query " +
      time_str + "'";
  std::system(command.c_str());
  std::this_thread::sleep_for(std::chrono::seconds(1));

  // Check for our written log
  auto results =
      SQL("select * from asl where facility = 'user' and level = 5 and sender "
          "= 'osquery_test' and message like '%" +
          time_str + "' and time >= " + time_str);
  ASSERT_GT(results.rows().size(), (size_t)0);
  ASSERT_EQ("osquery_test", results.rows()[0].at("sender"));
  ASSERT_EQ("user", results.rows()[0].at("facility"));
}

_Pragma("clang diagnostic pop");
}
}
