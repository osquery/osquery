/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <filesystem>

#include <boost/filesystem.hpp>

#include <osquery/tables/system/windows/startup_items.h>

namespace osquery {
namespace tables {

struct StartupItemsTests : testing::Test {
  Row r;
  std::error_code ec;
  std::filesystem::path tmp;

  void SetUp() {
    tmp =
        std::filesystem::temp_directory_path(ec) /
        boost::filesystem::unique_path("osquery-startup-items-%%%%%").string();
    ASSERT_FALSE(ec);
    std::filesystem::create_directories(tmp, ec);
    ASSERT_FALSE(ec);
  }

  void TearDown() {
    // reset Row each test
    r = {};
    ec = {};
    std::filesystem::remove_all(tmp, ec);
  }
};

TEST_F(StartupItemsTests, test_no_path) {
  auto path = std::string{};
  ASSERT_FALSE(parseStartupPath(path, r));
  EXPECT_TRUE(r.empty());
}

TEST_F(StartupItemsTests, test_path_no_spaces) {
  auto path = std::string{"C:\\Windows\\System32\\cmd.exe"};
  ASSERT_TRUE(parseStartupPath(path, r));
  EXPECT_EQ(r["path"], "C:\\Windows\\System32\\cmd.exe");
}

TEST_F(StartupItemsTests, test_path_no_spaces_with_argument) {
  auto path = std::string{"C:\\Windows\\System32\\cmd.exe /r /c"};
  ASSERT_TRUE(parseStartupPath(path, r));
  EXPECT_EQ(r["path"], "C:\\Windows\\System32\\cmd.exe");
  EXPECT_EQ(r["args"], "/r /c");
}

TEST_F(StartupItemsTests, test_path_with_spaces) {
  auto file = tmp / "path with spaces";
  file.make_preferred();
  std::filesystem::create_directories(file);

  file /= "startup_item.exe";
  file.make_preferred();
  {
    std::ofstream out(file);
    ASSERT_TRUE(out.is_open());
    out << "";
  }
  ASSERT_TRUE(parseStartupPath(file.string(), r));
  EXPECT_EQ(r["path"], file.string());
  EXPECT_EQ(r["args"], "");
}

TEST_F(StartupItemsTests, test_path_with_spaces_and_args) {
  auto file = tmp / "spaces in path";
  file.make_preferred();
  std::filesystem::create_directories(file);

  file /= "startup_item.exe";
  file.make_preferred();
  {
    std::ofstream out(file);
    ASSERT_TRUE(out.is_open());
    out << "";
  }
  ASSERT_TRUE(parseStartupPath(file.string() + " /a /b", r));
  EXPECT_EQ(r["path"], file.string());
  EXPECT_EQ(r["args"], "/a /b");
}

TEST_F(StartupItemsTests, test_quoted_path_with_spaces_and_args) {
  auto file = tmp / "spaces in path";
  file.make_preferred();
  std::filesystem::create_directories(file);

  file /= "startup_item.exe";
  file.make_preferred();
  {
    std::ofstream out(file);
    ASSERT_TRUE(out.is_open());
    out << "";
  }
  ASSERT_TRUE(parseStartupPath("\"" + file.string() + "\" /g /h", r));
  EXPECT_EQ(r["path"], file.string());
  EXPECT_EQ(r["args"], "/g /h");
}

TEST_F(StartupItemsTests, test_non_existing_path) {
  auto file = tmp / "spaces in path" / "startup_item.exe";
  file.make_preferred();

  ASSERT_FALSE(parseStartupPath(file.string() + " /g /h", r));
  EXPECT_TRUE(r.empty());
}

TEST_F(StartupItemsTests, test_quoted_non_existing_path) {
  auto file = tmp / "spaces in path" / "startup_item.exe";
  file.make_preferred();

  ASSERT_FALSE(parseStartupPath("\"" + file.string() + "\" /g /h", r));
  EXPECT_TRUE(r.empty());
}
} // namespace tables
} // namespace osquery
