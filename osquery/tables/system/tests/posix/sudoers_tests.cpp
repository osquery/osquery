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
#include <osquery/tables/system/posix/sudoers.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/scope_guard.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

static fs::path real_temp_path() {
  auto temp_dir = fs::temp_directory_path();

  // NOTE(ww): The sudoers table expands paths to their canonical
  // form when listing directories, so we need to make sure that
  // the temp directory is canonicalized as well.
  return fs::canonical(temp_dir);
}

class SudoersTests : public testing::Test {};

TEST_F(SudoersTests, basic_sudoers) {
  auto directory =
      real_temp_path() / fs::unique_path("osquery.sudoers_tests.%%%%-%%%%");

  ASSERT_TRUE(fs::create_directories(directory));

  auto const path_guard =
      scope_guard::create([directory]() { fs::remove_all(directory); });

  auto sudoers_file = directory / fs::path("sudoers");

  {
    auto fout = std::ofstream(sudoers_file.native());
    fout << "Defaults env_reset\n"
         << "# This is a comment\n"
         << " # with a leading space\n"
         << "#includedir\n" // bad include syntax
         << "#includedir \n" // bad include syntax
         << "#include\n"; // bad include syntax
  }

  auto results = QueryData{};
  genSudoersFile(sudoers_file.string(), 1, results);

  ASSERT_EQ(results.size(), 1);

  EXPECT_EQ(results[0].at("source"), sudoers_file.string());
  EXPECT_EQ(results[0].at("header"), "Defaults");
  EXPECT_EQ(results[0].at("rule_details"), "env_reset");
}

TEST_F(SudoersTests, include_file) {
  auto directory =
      real_temp_path() / fs::unique_path("osquery.sudoers_tests.%%%%-%%%%");

  ASSERT_TRUE(fs::create_directories(directory));

  auto const path_guard =
      scope_guard::create([directory]() { fs::remove_all(directory); });

  auto sudoers_top = directory / fs::path("sudoers");
  auto sudoers_inc_at = directory / fs::path("sudoers_inc_at");
  auto sudoers_inc_hash = directory / fs::path("sudoers_inc_hash");

  {
    auto fout_top = std::ofstream(sudoers_top.native());
    // Test both relative and absolute path
    fout_top << "#include sudoers_inc_hash\n";
    fout_top << "@include " << sudoers_inc_at.string() << '\n';

    auto fout_inc_at = std::ofstream(sudoers_inc_at.native());
    fout_inc_at << "Defaults env_keep += \"AT\"" << '\n';

    auto fout_inc_hash = std::ofstream(sudoers_inc_hash.native());
    fout_inc_hash << "Defaults env_keep += \"HASH\"" << '\n';
  }

  auto results = QueryData{};
  genSudoersFile(sudoers_top.string(), 1, results);

  ASSERT_EQ(results.size(), 4);

  EXPECT_EQ(results[0].at("source"), sudoers_top.string());
  EXPECT_EQ(results[0].at("header"), "#include");
  EXPECT_EQ(results[0].at("rule_details"), "sudoers_inc_hash");

  EXPECT_EQ(results[1].at("source"), sudoers_inc_hash.string());
  EXPECT_EQ(results[1].at("header"), "Defaults");
  EXPECT_EQ(results[1].at("rule_details"), "env_keep += \"HASH\"");

  EXPECT_EQ(results[2].at("source"), sudoers_top.string());
  EXPECT_EQ(results[2].at("header"), "@include");
  EXPECT_EQ(results[2].at("rule_details"), sudoers_inc_at.string());

  EXPECT_EQ(results[3].at("source"), sudoers_inc_at.string());
  EXPECT_EQ(results[3].at("header"), "Defaults");
  EXPECT_EQ(results[3].at("rule_details"), "env_keep += \"AT\"");
}

TEST_F(SudoersTests, include_dir) {
  auto directory =
      real_temp_path() / fs::unique_path("osquery.sudoers_tests.%%%%-%%%%");

  ASSERT_TRUE(fs::create_directories(directory));

  auto const path_guard =
      scope_guard::create([directory]() { fs::remove_all(directory); });

  auto sudoers_top = directory / fs::path("sudoers");
  auto sudoers_dir_at = directory / fs::path("sudoers.d.at");
  auto sudoers_dir_hash = directory / fs::path("sudoers.d.hash");

  auto sudoers_inc_at = sudoers_dir_at / fs::path("sudoers_inc");
  auto sudoers_inc_hash = sudoers_dir_hash / fs::path("sudoers_inc");

  ASSERT_TRUE(fs::create_directories(sudoers_dir_at));
  ASSERT_TRUE(fs::create_directories(sudoers_dir_hash));

  {
    auto fout_top = std::ofstream(sudoers_top.native());
    // test both relative and absolute
    fout_top << "#includedir sudoers.d.hash\n";
    fout_top << "@includedir " << sudoers_dir_at.string() << '\n';

    auto fout_inc_at = std::ofstream(sudoers_inc_at.native());
    fout_inc_at << "Defaults env_keep += \"AT\"" << '\n';

    auto fout_inc_hash = std::ofstream(sudoers_inc_hash.native());
    fout_inc_hash << "Defaults env_keep += \"HASH\"" << '\n';
  }

  auto results = QueryData{};
  genSudoersFile(sudoers_top.string(), 1, results);

  ASSERT_EQ(results.size(), 4);

  EXPECT_EQ(results[0].at("source"), sudoers_top.string());
  EXPECT_EQ(results[0].at("header"), "#includedir");
  EXPECT_EQ(results[0].at("rule_details"), "sudoers.d.hash");

  EXPECT_EQ(results[1].at("source"), sudoers_inc_hash.string());
  EXPECT_EQ(results[1].at("header"), "Defaults");
  EXPECT_EQ(results[1].at("rule_details"), "env_keep += \"HASH\"");

  EXPECT_EQ(results[2].at("source"), sudoers_top.string());
  EXPECT_EQ(results[2].at("header"), "@includedir");
  EXPECT_EQ(results[2].at("rule_details"), sudoers_dir_at.string());

  EXPECT_EQ(results[3].at("source"), sudoers_inc_at.string());
  EXPECT_EQ(results[3].at("header"), "Defaults");
  EXPECT_EQ(results[3].at("rule_details"), "env_keep += \"AT\"");
}

TEST_F(SudoersTests, long_line) {
  auto directory =
      real_temp_path() / fs::unique_path("osquery.sudoers_tests.%%%%-%%%%");

  ASSERT_TRUE(fs::create_directories(directory));

  auto const path_guard =
      scope_guard::create([directory]() { fs::remove_all(directory); });

  auto sudoers_file = directory / fs::path("sudoers");

  {
    auto fout = std::ofstream(sudoers_file.native());
    fout << "# This is a comment\\\n" // comment ends with backslash
         << " # with a leading space\\\n" // comment ends with backslash
         << "User_Alias OTHER_USERS=foo,\\\n" // long line
         << "bar,\\\n" // long line
         << "baz\n"
         << "User_Alias NUM_USERS=#501,#502\n"
         << "User_Alias ALL_USERS = NUM_USERS,\\\n" // long line
         << "OTHER_USERS\n"
         << "Cmnd_Alias CMDS_1=/usr/bin/cmd1 \"a\\,b\",\\\n" // long line
         << "/usr/bin/cmd2\n"
         << "ALL_USERS ALL=(ALL)CMDS_1\n";
  }

  auto results = QueryData{};
  genSudoersFile(sudoers_file.string(), 1, results);

  ASSERT_EQ(results.size(), 5);

  EXPECT_EQ(results[0].at("source"), sudoers_file.string());
  EXPECT_EQ(results[0].at("header"), "User_Alias");
  EXPECT_EQ(results[0].at("rule_details"), "OTHER_USERS=foo,bar,baz");

  EXPECT_EQ(results[1].at("source"), sudoers_file.string());
  EXPECT_EQ(results[1].at("header"), "User_Alias");
  EXPECT_EQ(results[1].at("rule_details"), "NUM_USERS=#501,#502");

  EXPECT_EQ(results[2].at("source"), sudoers_file.string());
  EXPECT_EQ(results[2].at("header"), "User_Alias");
  EXPECT_EQ(results[2].at("rule_details"), "ALL_USERS = NUM_USERS,OTHER_USERS");

  EXPECT_EQ(results[3].at("source"), sudoers_file.string());
  EXPECT_EQ(results[3].at("header"), "Cmnd_Alias");
  EXPECT_EQ(results[3].at("rule_details"),
            "CMDS_1=/usr/bin/cmd1 \"a\\,b\",/usr/bin/cmd2");

  EXPECT_EQ(results[4].at("source"), sudoers_file.string());
  EXPECT_EQ(results[4].at("header"), "ALL_USERS");
  EXPECT_EQ(results[4].at("rule_details"), "ALL=(ALL)CMDS_1");
}

} // namespace tables
} // namespace osquery
