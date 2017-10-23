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
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tests/test_util.h"

namespace osquery {
namespace tables {

class SystemsTablesTests : public testing::Test {};

TEST_F(SystemsTablesTests, test_os_version) {
  SQL results("select * from os_version");

  EXPECT_EQ(results.rows().size(), 1U);

  // Make sure major and minor have data (a missing value of -1 is an error).
  EXPECT_FALSE(results.rows()[0].at("major").empty());
  // The OS name should be filled in too.
  EXPECT_FALSE(results.rows()[0].at("name").empty());
}

TEST_F(SystemsTablesTests, test_hostname) {
  SQL results("select hostname from system_info");
  EXPECT_EQ(results.rows().size(), 1U);
  EXPECT_FALSE(results.rows()[0].at("hostname").empty());
}

TEST_F(SystemsTablesTests, test_process_info) {
  SQL results("select * from osquery_info join processes using (pid)");
  ASSERT_EQ(results.rows().size(), 1U);

  // Make sure there is a valid UID and parent.
  EXPECT_EQ(results.rows()[0].count("uid"), 1U);
  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    EXPECT_NE(results.rows()[0].at("uid"), "-1");
  }

  EXPECT_NE(results.rows()[0].at("parent"), "-1");
}

TEST_F(SystemsTablesTests, test_processes) {
  {
    SQL results("select pid, name from processes limit 1");
    ASSERT_EQ(results.rows().size(), 1U);

    EXPECT_FALSE(results.rows()[0].at("pid").empty());
    EXPECT_FALSE(results.rows()[0].at("name").empty());
  }

  {
    // Make sure an invalid pid within the query constraint returns no rows.
    SQL results("select pid, name from processes where pid = -1");
    EXPECT_EQ(results.rows().size(), 0U);
  }
}

TEST_F(SystemsTablesTests, test_users) {
  {
    SQL results("select uid, uuid, username from users limit 1");
    ASSERT_EQ(results.rows().size(), 1U);

    EXPECT_FALSE(results.rows()[0].at("uid").empty());
    if (!isPlatform(PlatformType::TYPE_LINUX)) {
      EXPECT_FALSE(results.rows()[0].at("uuid").empty());
    }
    EXPECT_FALSE(results.rows()[0].at("username").empty());
  }

  {
    // Make sure that we can query all users without crash or hang: Issue #3079
    SQL results("select uid, uuid, username from users");
    EXPECT_GT(results.rows().size(), 1U);
  }

  {
    // Make sure an invalid pid within the query constraint returns no rows.
    SQL results("select uuid, username from users where uuid = -1");
    EXPECT_EQ(results.rows().size(), 0U);
  }
}

TEST_F(SystemsTablesTests, test_processes_memory_cpu) {
  SQL results("select * from osquery_info join processes using (pid)");
  long long bytes;
  safeStrtoll(results.rows()[0].at("resident_size"), 0, bytes);

  // Now we expect the running test to use over 1M of RSS.
  bytes = bytes / (1024 * 1024);
  EXPECT_GT(bytes, 1U);

  safeStrtoll(results.rows()[0].at("total_size"), 0, bytes);
  bytes = bytes / (1024 * 1024);
  EXPECT_GT(bytes, 1U);

  // Make sure user/system time are in seconds, pray we haven't actually used
  // more than 100 seconds of CPU.
  SQL results2("select * from osquery_info join processes using (pid)");

  long long cpu_start, value;
  safeStrtoll(results.rows()[0].at("user_time"), 0, cpu_start);
  safeStrtoll(results2.rows()[0].at("user_time"), 0, value);
  EXPECT_LT(value - cpu_start, 100U);
  EXPECT_GE(value - cpu_start, 0U);

  safeStrtoll(results.rows()[0].at("user_time"), 0, cpu_start);
  safeStrtoll(results2.rows()[0].at("user_time"), 0, value);
  EXPECT_LT(value - cpu_start, 100U);
  EXPECT_GE(value - cpu_start, 0U);
}

TEST_F(SystemsTablesTests, test_abstract_joins) {
  // Codify several assumptions about how tables should be joined into tests.
  // The first is an implicit inner join from processes to file information.
  std::string join_preamble =
      "select * from (select path from osquery_info join processes using "
      "(pid)) p";
  {
    SQL results(join_preamble + " join file using (path);");
    ASSERT_EQ(results.rows().size(), 1U);
  }

  {
    // The same holds for an explicit left join.
    SQL results(join_preamble + "left join file using (path);");
    ASSERT_EQ(results.rows().size(), 1U);
  }

  {
    // A secondary inner join against hash.
    SQL results(join_preamble +
                " join file using (path) join hash using (path);");
    ASSERT_EQ(results.rows().size(), 1U);
  }

  {
    SQL results(join_preamble +
                " left join file using (path) left join hash using (path);");
    ASSERT_EQ(results.rows().size(), 1U);
  }

  {
    // Check LIKE and = operands.
    SQL results(
        "select path from file where path = '/etc/' or path LIKE '/dev/%' or "
        "path LIKE '\\Windows\\%';");
    ASSERT_GT(results.rows().size(), 1U);
  }
}
}
}
