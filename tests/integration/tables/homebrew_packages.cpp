/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Spec file: specs/posix/homebrew_packages.table

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

namespace fs = boost::filesystem;

class homebrewPackages : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
    prefix_ = fs::temp_directory_path() /
              fs::unique_path("osquery-homebrew-%%%%-%%%%-%%%%");
    fs::create_directories(prefix_ / "Cellar");
    fs::create_directories(prefix_ / "Caskroom");
  }

  void TearDown() override {
    fs::remove_all(prefix_);
  }

  std::string prefixConstraint(const fs::path& prefix) {
    return "prefix = '" + boost::replace_all_copy(prefix.string(), "'", "''") +
           "'";
  }

  fs::path prefix_;
};

TEST_F(homebrewPackages, test_sanity) {
  execute_query("select * from homebrew_packages");
}

TEST_F(homebrewPackages, custom_prefix) {
  fs::create_directories(prefix_ / "Cellar" / "example" / "1.0");
  fs::create_directories(prefix_ / "Cellar" / "example" / "2.0");
  fs::create_directories(prefix_ / "Cellar" / "example" / ".metadata");
  fs::create_directories(prefix_ / "Cellar" / "other" / "3.0");

  const auto data = execute_query(
      "select name, version, path, type, prefix from homebrew_packages where " +
      prefixConstraint(prefix_) + " order by name, version");

  ASSERT_EQ(data.size(), 3U);
  EXPECT_EQ(data[0].at("name"), "example");
  EXPECT_EQ(data[0].at("version"), "1.0");
  EXPECT_EQ(data[1].at("name"), "example");
  EXPECT_EQ(data[1].at("version"), "2.0");
  EXPECT_EQ(data[2].at("name"), "other");
  EXPECT_EQ(data[2].at("version"), "3.0");
  for (const auto& row : data) {
    EXPECT_EQ(row.at("type"), "formula");
    EXPECT_EQ(row.at("prefix"), prefix_.string());
    EXPECT_EQ(row.at("path"),
              (fs::canonical(prefix_) / "Cellar" / row.at("name")).string());
  }
}

TEST_F(homebrewPackages, empty_prefix) {
  const auto data = execute_query("select * from homebrew_packages where " +
                                  prefixConstraint(prefix_));
  EXPECT_TRUE(data.empty());
}

TEST_F(homebrewPackages, missing_prefix) {
  const auto data = execute_query("select * from homebrew_packages where " +
                                  prefixConstraint(prefix_ / "missing"));
  EXPECT_TRUE(data.empty());
}

} // namespace table_tests
} // namespace osquery
