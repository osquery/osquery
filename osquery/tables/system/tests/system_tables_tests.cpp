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

#include <fstream>
#include <iostream>
#include <stdio.h>

#include <boost/filesystem.hpp>
#include <gflags/gflags.h>

#include <osquery/core.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tests/test_util.h"

namespace osquery {

DECLARE_bool(enable_hash_cache);

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
        R"(select path from file where path = '/etc/' or path LIKE '/dev/%' or path LIKE '\Windows\%';)");
    ASSERT_GT(results.rows().size(), 1U);
  }
}

TEST_F(SystemsTablesTests, test_hash_table) {
  // this test requires cwd be writeable, which is meh,
  // but I cannot figure out a better way to do it

  const std::vector<std::string> content{"31337 hax0r", "random n00b"};
  const std::string contentMd5 = "2adfc0fd337a144cb2f8abd7cb0bf98e";
  const std::string contentSha1 = "21bd89f4580ef635e87f655fab5807a01e0ff2e9";
  const std::string contentSha256 =
      "6f1c16ac918f64721d14ff4bb3c51fe25ffde92f795ce6dbeb45722ce9d6e05c";
  const std::string badContentMd5 = "e1cd6c58b0d4d9d7bcbfc0ec2b55ce94";

  char f1path[] = "hash_table_test.tmpXXXXXX";
  char* f1path_p = mktemp(f1path);
  ASSERT_NE(f1path_p, nullptr);
  std::ofstream f1;
  f1.open(f1path);
  f1 << content[0];
  f1.flush();

  char qry[0x200] = {0};
  snprintf(qry,
           sizeof(qry),
           "select md5, sha1, sha256 from hash where path='%s'",
           f1path);

  // confirm we calculate correct hashes
  {
    SQL results(qry);
    auto rows = results.rows();
    EXPECT_EQ(rows.size(), 1U);
    if (rows.size() == 1) {
      EXPECT_EQ(rows[0].at("md5"), contentMd5);
      EXPECT_EQ(rows[0].at("sha1"), contentSha1);
      EXPECT_EQ(rows[0].at("sha256"), contentSha256);
    }
  }

  // test caching
  FLAGS_enable_hash_cache = true;
  {
    // test if result is cached
    // cache is re-calculated if file's mtime and size do not match
    // recorded value; both strings are the same size, and mtime
    // has a resolution in seconds
    // XXX: this relies on sub-second performance of write and query,
    // which should be the case, but still something to consider
    for (int i = 0; i < 2; ++i) {
      f1.seekp(0, std::ios_base::beg);
      f1 << content[i];
      f1.flush();
      SQL results(qry);
      auto rows = results.rows();
      EXPECT_EQ(rows[0].at("md5"), contentMd5);
    }
    // test if the cache is re-calculated properly
    boost::filesystem::path p(f1path);
    // now() - 1 hour, just in case
    boost::filesystem::last_write_time(p, time(nullptr) - 60 * 60);
    SQL results(qry);
    auto rows = results.rows();
    EXPECT_NE(rows[0].at("md5"), contentMd5);
    EXPECT_EQ(rows[0].at("md5"), badContentMd5);
  }

  f1.close();
  unlink(f1path);
}
} // namespace tables
} // namespace osquery
