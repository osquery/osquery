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
    fout << "Defaults env_reset" << '\n';
  }

  auto results = QueryData{};
  genSudoersFile(sudoers_file.string(), 1, results);

  ASSERT_EQ(results.size(), 1);

  const auto& row = results[0];
  ASSERT_EQ(row.at("source"), sudoers_file.string());
  ASSERT_EQ(row.at("header"), "Defaults");
  ASSERT_EQ(row.at("rule_details"), "env_reset");
}

TEST_F(SudoersTests, include_file) {
  auto directory =
      real_temp_path() / fs::unique_path("osquery.sudoers_tests.%%%%-%%%%");

  ASSERT_TRUE(fs::create_directories(directory));

  auto const path_guard =
      scope_guard::create([directory]() { fs::remove_all(directory); });

  auto sudoers_top = directory / fs::path("sudoers");
  auto sudoers_inc = directory / fs::path("sudoers_inc");

  {
    auto fout_top = std::ofstream(sudoers_top.native());
    fout_top << "#include sudoers_inc" << '\n';

    auto fout_inc = std::ofstream(sudoers_inc.native());
    fout_inc << "Defaults env_reset" << '\n';
  }

  auto results = QueryData{};
  genSudoersFile(sudoers_top.string(), 1, results);

  ASSERT_EQ(results.size(), 2);

  const auto& first_row = results[0];
  ASSERT_EQ(first_row.at("source"), sudoers_top.string());
  ASSERT_EQ(first_row.at("header"), "#include");
  ASSERT_EQ(first_row.at("rule_details"), sudoers_inc.string());

  const auto& second_row = results[1];
  ASSERT_EQ(second_row.at("source"), sudoers_inc.string());
  ASSERT_EQ(second_row.at("header"), "Defaults");
  ASSERT_EQ(second_row.at("rule_details"), "env_reset");
}

TEST_F(SudoersTests, include_dir) {
  auto directory =
      real_temp_path() / fs::unique_path("osquery.sudoers_tests.%%%%-%%%%");

  ASSERT_TRUE(fs::create_directories(directory));

  auto const path_guard =
      scope_guard::create([directory]() { fs::remove_all(directory); });

  auto sudoers_top = directory / fs::path("sudoers");
  auto sudoers_dir = directory / fs::path("sudoers.d");
  auto sudoers_inc = sudoers_dir / fs::path("sudoers_inc");

  ASSERT_TRUE(fs::create_directories(sudoers_dir));

  {
    auto fout_top = std::ofstream(sudoers_top.native());
    fout_top << "#includedir " << sudoers_dir.string() << '\n';

    auto fout_inc = std::ofstream(sudoers_inc.native());
    fout_inc << "Defaults env_reset" << '\n';
  }

  auto results = QueryData{};
  genSudoersFile(sudoers_top.string(), 1, results);

  ASSERT_EQ(results.size(), 2);

  const auto& first_row = results[0];
  ASSERT_EQ(first_row.at("source"), sudoers_top.string());
  ASSERT_EQ(first_row.at("header"), "#includedir");
  ASSERT_EQ(first_row.at("rule_details"), sudoers_dir.string());

  const auto& second_row = results[1];
  ASSERT_EQ(second_row.at("source"), sudoers_inc.string());
  ASSERT_EQ(second_row.at("header"), "Defaults");
  ASSERT_EQ(second_row.at("rule_details"), "env_reset");
}

} // namespace tables
} // namespace osquery
