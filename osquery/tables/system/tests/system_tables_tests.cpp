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

#include "osquery/tests/test_util.h"

namespace osquery {
namespace tables {

#ifndef WIN32
QueryData genOSVersion(QueryContext& context);
#endif

class SystemsTablesTests : public testing::Test {};

#ifndef WIN32
TEST_F(SystemsTablesTests, test_os_version) {
  QueryContext context;
  auto result = genOSVersion(context);
  EXPECT_EQ(result.size(), 1U);

  // Make sure major and minor contain data (a missing value of -1 is an error).
  EXPECT_FALSE(result[0]["major"].empty());

// Debian does not define a minor.
#if !defined(DEBIAN)
  EXPECT_FALSE(result[0]["minor"].empty());
#endif

  // The OS name should be filled in too.
  EXPECT_FALSE(result[0]["name"].empty());
}
#endif

TEST_F(SystemsTablesTests, test_process_info) {
  auto results = SQL("select * from osquery_info join processes using (pid)");
  ASSERT_EQ(results.rows().size(), 1U);

  // Make sure there is a valid UID and parent.
  EXPECT_EQ(results.rows()[0].count("uid"), 1U);
  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    EXPECT_NE(results.rows()[0].at("uid"), "-1");
  }

  EXPECT_NE(results.rows()[0].at("parent"), "-1");
}

TEST_F(SystemsTablesTests, test_processes) {
  auto results = SQL("select pid, name from processes limit 1");
  ASSERT_EQ(results.rows().size(), 1U);

  EXPECT_FALSE(results.rows()[0].at("pid").empty());
  EXPECT_FALSE(results.rows()[0].at("name").empty());

  // Make sure an invalid pid within the query constraint returns no rows.
  results = SQL("select pid, name from processes where pid = -1");
  EXPECT_EQ(results.rows().size(), 0U);
}

TEST_F(SystemsTablesTests, test_abstract_joins) {
  // Codify several assumptions about how tables should be joined into tests.
  // The first is an implicit inner join from processes to file information.
  std::string join_preamble =
      "select * from (select path from osquery_info join processes using "
      "(pid)) p";
  auto results = SQL(join_preamble + " join file using (path);");
  ASSERT_EQ(results.rows().size(), 1U);

  // The same holds for an explicit left join.
  results = SQL(join_preamble + "left join file using (path);");
  ASSERT_EQ(results.rows().size(), 1U);

  // A secondary inner join against hash.
  results =
      SQL(join_preamble + " join file using (path) join hash using (path);");
  ASSERT_EQ(results.rows().size(), 1U);

  results = SQL(join_preamble +
                " left join file using (path) left join hash using (path);");
  ASSERT_EQ(results.rows().size(), 1U);

  // Check LIKE and = operands.
  results =
      SQL("select path from file where path = '/etc/' or path LIKE '/dev/%' or "
          "path LIKE '\\Windows\\%';");
  ASSERT_GT(results.rows().size(), 1U);
}
}
}
