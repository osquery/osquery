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

#include <boost/filesystem.hpp>
#include <gflags/gflags.h>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
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

TEST_F(SystemsTablesTests, test_processes_disk_io) {
  // TODO: Remove once implemented on these platforms.
  if (!isPlatform(PlatformType::TYPE_LINUX) &&
      !isPlatform(PlatformType::TYPE_OSX)) {
    return;
  }

  SQL before("select * from osquery_info join processes using (pid)");
  boost::filesystem::path tmpFile =
      boost::filesystem::temp_directory_path() /
      boost::filesystem::unique_path("osquery_processes_disk_io_%%%%%%%");
  {
    std::string content(1024 * 1024, 'x');
    std::ofstream stream;

    stream.open(tmpFile.string());
    stream << content;
    stream.flush();
  }

  SQL after("select * from osquery_info join processes using (pid)");

  long long bytes_written_before, bytes_written_after;
  safeStrtoll(
      before.rows()[0].at("disk_bytes_written"), 0, bytes_written_before);
  safeStrtoll(after.rows()[0].at("disk_bytes_written"), 0, bytes_written_after);

  EXPECT_GE(bytes_written_after - bytes_written_before, 1024 * 1024);
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

TEST_F(SystemsTablesTests, test_win_drivers_query_time) {
  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    return;
  }
  SQL results("select * from osquery_info join processes using (pid)");
  long long utime1, systime1;
  safeStrtoll(results.rows()[0].at("user_time"), 0, utime1);
  safeStrtoll(results.rows()[0].at("system_time"), 0, systime1);

  // Query the drivers table and ensure that we don't take too long to exec
  SQL drivers("select * from drivers");

  // Ensure we at least got some drivers back
  ASSERT_GT(drivers.rows().size(), 10U);

  // Get a rough idea of the time utilized by the query
  long long utime2, systime2;
  SQL results2("select * from osquery_info join processes using (pid)");
  safeStrtoll(results2.rows()[0].at("user_time"), 0, utime2);
  safeStrtoll(results2.rows()[0].at("system_time"), 0, systime2);

  EXPECT_LT(utime2 - utime1, 10U);
  EXPECT_LT(systime2 - systime1, 10U);
}

TEST_F(SystemsTablesTests, test_win_crashes_parsing) {
  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    return;
  }
  SQL results("select * from windows_crashes limit 1");

  // If no local crash dumps are found return
  if (results.rows().empty()) {
    return;
  }

  // Ensure calls to the Windows API to reconstruct the stack trace don't crash
  EXPECT_FALSE(results.rows()[0].at("stack_trace").empty());
}

class HashTableTest : public testing::Test {
 public:
  const std::vector<std::string> content{"31337 hax0r", "random n00b"};
  const std::string contentMd5 = "2adfc0fd337a144cb2f8abd7cb0bf98e";
  const std::string contentSha1 = "21bd89f4580ef635e87f655fab5807a01e0ff2e9";
  const std::string contentSha256 =
      "6f1c16ac918f64721d14ff4bb3c51fe25ffde92f795ce6dbeb45722ce9d6e05c";
  const std::string badContentMd5 = "e1cd6c58b0d4d9d7bcbfc0ec2b55ce94";

  void SetContent(int n) {
    if (pathExists(tmpPath)) {
      boost::filesystem::resize_file(tmpPath, 0);
    }
    writeTextFile(tmpPath, content[n]);
  }

 protected:
  virtual void SetUp() {
    tmpPath = boost::filesystem::temp_directory_path();
    tmpPath /= boost::filesystem::unique_path(
        "osquery_hash_t_test-%%%%-%%%%-%%%%-%%%%");
    qry = std::string("select md5, sha1, sha256 from hash where path='") +
          tmpPath.string() + "'";
  }

  virtual void TearDown() {
    removePath(tmpPath);
  }

  boost::filesystem::path tmpPath;
  std::string qry;
};

TEST_F(HashTableTest, hashes_are_correct) {
  SetContent(0);
  SQL results(qry);
  auto rows = results.rows();
  ASSERT_EQ(rows.size(), 1U);
  EXPECT_EQ(rows[0].at("md5"), contentMd5);
  EXPECT_EQ(rows[0].at("sha1"), contentSha1);
  EXPECT_EQ(rows[0].at("sha256"), contentSha256);
}

TEST_F(HashTableTest, test_cache_works) {
  time_t last_mtime = 0;
  for (int i = 0; i < 2; ++i) {
    SetContent(i);
    if (last_mtime == 0) {
      last_mtime = boost::filesystem::last_write_time(tmpPath);
    } else {
      // make sure mtime doesn't change
      boost::filesystem::last_write_time(tmpPath, last_mtime);
    }
    SQL results(qry);
    auto rows = results.rows();
    ASSERT_EQ(rows.size(), 1U);
    EXPECT_EQ(rows[0].at("md5"), contentMd5);
  }
}

TEST_F(HashTableTest, test_cache_updates) {
  SetContent(0);
  // cache the current state
  SQL r1(qry);
  ASSERT_EQ(r1.rows().size(), 1U);

  SetContent(1);
  // now() - 1 hour, just in case
  boost::filesystem::last_write_time(tmpPath, time(nullptr) - 60 * 60);
  SQL r2(qry);
  auto rows = r2.rows();
  ASSERT_EQ(rows.size(), 1U);
  EXPECT_NE(rows[0].at("md5"), contentMd5);
  EXPECT_EQ(rows[0].at("md5"), badContentMd5);
}
} // namespace tables
} // namespace osquery
