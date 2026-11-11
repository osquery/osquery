/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <map>
#include <string>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem/filesystem.h>
#include <osquery/tables/applications/vscode_extensions.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

class VSCodeExtensionsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ =
        fs::temp_directory_path() / fs::unique_path("osquery-vscode-%%%%%%");
    fs::create_directories(root_);
  }

  void TearDown() override {
    fs::remove_all(root_);
  }

  void writeProfile(const std::string& id, const std::string& json) {
    fs::create_directories(root_ / id);
    ASSERT_TRUE(writeTextFile(root_ / id / "extensions.json", json).ok());
  }

  fs::path root_;
};

TEST_F(VSCodeExtensionsTest, reads_every_profile_manifest) {
  // Same shape VS Code writes for the default profile.
  writeProfile("1a2b3c4d", R"([{
    "identifier": {"id": "ms-python.python", "uuid": "u-1"},
    "version": "2024.1.0",
    "location": {"$mid": 1, "path": "/home/u/.vscode/extensions/ms-python.python-2024.1.0"},
    "relativeLocation": "ms-python.python-2024.1.0",
    "metadata": {"id": "u-1", "publisherId": "p-1",
                 "publisherDisplayName": "Microsoft",
                 "installedTimestamp": 1700000000000,
                 "isPreReleaseVersion": false}
  }])");
  writeProfile("5e6f7a8b", R"([{
    "identifier": {"id": "rust-lang.rust-analyzer"},
    "version": "0.3.1",
    "location": {"$mid": 1, "path": "/home/u/.vscode/extensions/rust-analyzer-0.3.1"},
    "metadata": {"id": "u-2", "publisherId": "p-2",
                 "publisherDisplayName": "rust-lang",
                 "installedTimestamp": 1700000000001,
                 "isPreReleaseVersion": true}
  }])");
  // A profile dir without a manifest and a corrupt manifest are skipped.
  fs::create_directories(root_ / "empty");
  writeProfile("broken", "not json");

  QueryData results;
  genVSCodeProfileExtensionRows("1000", root_, "vscode", results);

  ASSERT_EQ(results.size(), 2U);
  std::map<std::string, Row> by_name;
  for (const auto& r : results) {
    by_name[r.at("name")] = r;
  }
  ASSERT_EQ(by_name.count("ms-python.python"), 1U);
  ASSERT_EQ(by_name.count("rust-lang.rust-analyzer"), 1U);
  EXPECT_EQ(by_name["ms-python.python"].at("version"), "2024.1.0");
  EXPECT_EQ(by_name["ms-python.python"].at("uid"), "1000");
  EXPECT_EQ(by_name["ms-python.python"].at("vscode_edition"), "vscode");
  EXPECT_EQ(by_name["rust-lang.rust-analyzer"].at("prerelease"), "1");
}

TEST_F(VSCodeExtensionsTest, missing_profiles_dir_yields_no_rows) {
  QueryData results;
  genVSCodeProfileExtensionRows("1000", root_ / "nope", "vscode", results);
  EXPECT_TRUE(results.empty());
}

} // namespace tables
} // namespace osquery
