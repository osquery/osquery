/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <future>
#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <boost/format.hpp>

#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>
#include <osquery/tests/test_util.h>
#include <osquery/utils/info/platform_type.h>
#ifdef OSQUERY_WINDOWS
#include <osquery/utils/conversions/windows/strings.h>
#endif

namespace osquery {
namespace tables {

class SystemsTablesTests : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }

#ifdef OSQUERY_WINDOWS
  static void SetUpTestSuite() {
    initUsersAndGroupsServices(true, true);
  }

  static void TearDownTestSuite() {
    Dispatcher::stopServices();
    Dispatcher::joinServices();
    deinitUsersAndGroupsServices(true, true);
    Dispatcher::instance().resetStopping();
  }
#endif
};

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
    SQL results("select * from users limit 1");
    ASSERT_EQ(results.rows().size(), 1U);

    EXPECT_FALSE(results.rows()[0].at("uid").empty());
    EXPECT_FALSE(results.rows()[0].at("username").empty());
    if (!isPlatform(PlatformType::TYPE_LINUX)) {
      EXPECT_FALSE(results.rows()[0].at("uuid").empty());
    }
  }

  {
    // Make sure that we can query all users without crash or hang: Issue #3079
    SQL results("select * from users");
    EXPECT_GT(results.rows().size(), 1U);
  }

  {
    // Make sure an invalid pid within the query constraint returns no rows.
    SQL results("select uuid, username from users where uuid = -1");
    EXPECT_EQ(results.rows().size(), 0U);
  }

  {
    // Make sure an invalid pid within the query constraint returns no rows.
    SQL results("select * from users where uid = -1");
    EXPECT_EQ(results.rows().size(), 0U);
  }
}

TEST_F(SystemsTablesTests, test_groups) {
  {
    SQL results("select * from groups limit 1");
    ASSERT_EQ(results.rows().size(), 1U);

    EXPECT_FALSE(results.rows()[0].at("gid").empty());
  }

  {
    // Make sure that we can query all users without crash or hang
    SQL results("select * from groups");
    EXPECT_GT(results.rows().size(), 1U);
  }

  {
    // Make sure an invalid pid within the query constraint returns no rows.
    SQL results("select * from groups where gid = -1");
    EXPECT_EQ(results.rows().size(), 0U);
  }
}

TEST_F(SystemsTablesTests, test_processes_memory_cpu) {
  SQL results("select * from osquery_info join processes using (pid)");
  long long bytes = std::stoll(results.rows()[0].at("resident_size"), 0, 0);

  // Now we expect the running test to use over 1M of RSS.
  bytes = bytes / (1024 * 1024);
  EXPECT_GE(bytes, 1U);

  bytes = std::stoll(results.rows()[0].at("total_size"), 0, 0);
  bytes = bytes / (1024 * 1024);
  EXPECT_GE(bytes, 1U);

  // Make sure user/system time are in seconds, pray we haven't actually used
  // more than 100 seconds of CPU.
  SQL results2("select * from osquery_info join processes using (pid)");

  auto cpu_start = std::stoll(results.rows()[0].at("user_time"), 0, 0);
  auto value = std::stoll(results2.rows()[0].at("user_time"), 0, 0);
  EXPECT_LT(value - cpu_start, 100U);
  EXPECT_GE(value - cpu_start, 0U);

  cpu_start = std::stoll(results.rows()[0].at("user_time"), 0, 0);
  value = std::stoll(results2.rows()[0].at("user_time"), 0, 0);
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

  auto bytes_written_before =
      std::stoll(before.rows()[0].at("disk_bytes_written"), 0, 0);
  auto bytes_written_after =
      std::stoll(after.rows()[0].at("disk_bytes_written"), 0, 0);

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
}

TEST_F(SystemsTablesTests, test_table_constraints) {
  {
    // Check LIKE and = operands.
#ifdef OSQUERY_WINDOWS
    WCHAR windows_path[64];
    auto windows_path_length =
        GetSystemWindowsDirectoryW(windows_path, ARRAYSIZE(windows_path));
    ASSERT_FALSE(windows_path_length == 0);

    std::stringstream qry_stream;
    qry_stream << boost::format("select path from file where path LIKE '%s") %
                      wstringToString(windows_path)
               << R"(\%';)";
    std::string like_query = qry_stream.str();
    qry_stream = std::stringstream();

    qry_stream << boost::format("select path from file where path = '%s") %
                      wstringToString(windows_path)
               << R"(';)";
    std::string equal_query = qry_stream.str();

#else
    std::string like_query =
        R"(select path from file where path LIKE '/dev/%';)";
    std::string equal_query = "select path from file where path = '/etc/'";
#endif
    SQL like_results(like_query);
    SQL equal_results(equal_query);
    EXPECT_GT(like_results.rows().size(), 1U);
    EXPECT_GT(equal_results.rows().size(), 0U);
  }
}

TEST_F(SystemsTablesTests, test_win_drivers_query_time) {
  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    return;
  }
  SQL results("select * from osquery_info join processes using (pid)");
  auto utime1 = std::stoll(results.rows()[0].at("user_time"), 0, 0);
  auto systime1 = std::stoll(results.rows()[0].at("system_time"), 0, 0);

  // Query the drivers table and ensure that we don't take too long to exec
  SQL drivers("select * from drivers");

  // Ensure we at least got some drivers back
  ASSERT_GT(drivers.rows().size(), 10U);

  // Get a rough idea of the time utilized by the query
  SQL results2("select * from osquery_info join processes using (pid)");
  auto utime2 = std::stoll(results2.rows()[0].at("user_time"), 0, 0);
  auto systime2 = std::stoll(results2.rows()[0].at("system_time"), 0, 0);

  EXPECT_LT(utime2 - utime1, 10000U);
  EXPECT_LT(systime2 - systime1, 10000U);
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
    std::stringstream qry_stream;
    qry_stream << boost::format(
                      "select md5, sha1, sha256 from hash where path='%s'") %
                      tmpPath.string();
    qry = qry_stream.str();
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
