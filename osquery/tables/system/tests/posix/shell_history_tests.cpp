/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fstream>

#include <boost/filesystem.hpp>

#include <gtest/gtest.h>

#include <osquery/sql/sql.h>
#include <osquery/tables/system/posix/shell_history.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

class ShellHistoryTests : public testing::Test {};

TEST_F(ShellHistoryTests, empty_timestamp) {
  std::vector<DynamicTableRowHolder> results;
  auto predicate = [&results](DynamicTableRowHolder& r) {
    results.push_back(std::move(r));
  };

  auto directory =
      fs::temp_directory_path() /
      fs::unique_path("osquery.shell_history_tests.empty_timestamp.%%%%-%%%%");
  ASSERT_TRUE(fs::create_directory(directory));
  auto filepath = directory / fs::path(".sh_history");
  auto const first_line = R"raw([\]^_`!a"b#c$d %e&f'g(h)i*j+k,l-m.n/o0p1q2)raw";
  auto const second_line = R"raw(r 3 s4t5u6v7w8 x9y:9:z; {<|=}>~?)raw";
  {
    auto fout =
        std::ofstream(filepath.native(), std::ios::out | std::ios::binary);
    fout << first_line << '\n';
    fout << second_line << '\n';
  }

  auto const uid = std::to_string(geteuid());
  genShellHistoryForUser(
      uid, std::to_string(getegid()), directory.native(), predicate);
  ASSERT_EQ(results.size(), 2u);

  const auto& first_row = results[0];
  EXPECT_EQ(first_row["uid"], uid);
  EXPECT_EQ(first_row["time"], "0");
  EXPECT_EQ(first_row["command"], first_line);
  EXPECT_EQ(first_row["history_file"], filepath.native());

  const auto& second_row = results[1];
  EXPECT_EQ(second_row["uid"], uid);
  EXPECT_EQ(second_row["time"], "0");
  EXPECT_EQ(second_row["command"], second_line);
  EXPECT_EQ(second_row["history_file"], filepath.native());
  fs::remove_all(directory);
}

TEST_F(ShellHistoryTests, bash_sessions_no_exist) {
  std::vector<DynamicTableRowHolder> results;
  auto predicate = [&results](DynamicTableRowHolder& r) {
    results.push_back(std::move(r));
  };

  auto directory =
      fs::temp_directory_path() /
      fs::unique_path(
          "osquery.shell_history_tests.bash_sessions_no_exist.%%%%-%%%%");
  ASSERT_TRUE(fs::create_directory(directory));
  auto const uid = std::to_string(geteuid());

  // test non-existent .bash_sessions directory
  genShellHistoryFromBashSessions(uid, directory.native(), predicate);
  ASSERT_EQ(results.size(), 0u);
  fs::remove_all(directory);
}

TEST_F(ShellHistoryTests, bash_sessions_no_history) {
  std::vector<DynamicTableRowHolder> results;
  auto predicate = [&results](DynamicTableRowHolder& r) {
    results.push_back(std::move(r));
  };

  auto directory =
      fs::temp_directory_path() /
      fs::unique_path(
          "osquery.shell_history_tests.bash_sessions_no_exist.%%%%-%%%%");
  ASSERT_TRUE(fs::create_directory(directory));

  auto bash_sessions_directory = directory / ".bash_sessions";
  ASSERT_TRUE(fs::create_directory(bash_sessions_directory));
  // create a junk session file that will not be read
  auto filepath = bash_sessions_directory / fs::path("some_guid_here.session");
  auto const restore_string =
      R"raw(echo Restored session: "$(date -r 1479082319)")raw";
  {
    auto fout =
        std::ofstream(filepath.native(), std::ios::out | std::ios::binary);
    fout << restore_string << '\n';
  }
  auto const uid = std::to_string(geteuid());
  // test non-existent some_guid_here.history file
  genShellHistoryFromBashSessions(uid, directory.native(), predicate);
  ASSERT_EQ(results.size(), 0u);
  fs::remove_all(directory);
}

TEST_F(ShellHistoryTests, bash_sessions_empty_ts) {
  std::vector<DynamicTableRowHolder> results;
  auto predicate = [&results](DynamicTableRowHolder& r) {
    results.push_back(std::move(r));
  };

  auto directory =
      fs::temp_directory_path() /
      fs::unique_path(
          "osquery.shell_history_tests.bash_sessions_empty_ts.%%%%-%%%%");
  ASSERT_TRUE(fs::create_directory(directory));

  auto bash_sessions_directory = directory / ".bash_sessions";
  ASSERT_TRUE(fs::create_directory(bash_sessions_directory));
  // create a junk session file that will not be read
  auto filepath = bash_sessions_directory / fs::path("some_guid_here.history");
  auto const first_line = R"raw([\]^_`!a"b#c$d %e&f'g(h)i*j+k,l-m.n/o0p1q2)raw";
  auto const second_line = R"raw(r 3 s4t5u6v7w8 x9y:9:z; {<|=}>~?)raw";
  {
    auto fout =
        std::ofstream(filepath.native(), std::ios::out | std::ios::binary);
    fout << first_line << '\n';
    fout << second_line << '\n';
  }
  auto const uid = std::to_string(geteuid());
  genShellHistoryFromBashSessions(uid, directory.native(), predicate);
  ASSERT_EQ(results.size(), 2u);

  const auto& first_row = results[0];
  EXPECT_EQ(first_row["uid"], uid);
  EXPECT_EQ(first_row["time"], "0");
  EXPECT_EQ(first_row["command"], first_line);
  EXPECT_EQ(first_row["history_file"], fs::canonical(filepath).native());

  const auto& second_row = results[1];
  EXPECT_EQ(second_row["uid"], uid);
  EXPECT_EQ(second_row["time"], "0");
  EXPECT_EQ(second_row["command"], second_line);
  EXPECT_EQ(second_row["history_file"], fs::canonical(filepath).native());
  fs::remove_all(directory);
}

} // namespace tables
} // namespace osquery
