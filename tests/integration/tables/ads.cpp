/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for ads
// Spec file: specs/windows/ads.table

#include <osquery/filesystem/filesystem.h>
#include <osquery/tests/integration/tables/helper.h>
#include <string>

namespace osquery {
namespace table_tests {

const std::string fileName = "test.txt";
const std::string streamName = "teststream";
const std::string streamContents = "This is some data in an alternate stream";

class ads : public testing::Test {
 public:
  boost::filesystem::path directory;

  void SetUp() override {
    setUpEnvironment();

    directory =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("test-integration-file-table.%%%%-%%%%");

    ASSERT_TRUE(boost::filesystem::create_directory(directory));

    auto filepath = directory / boost::filesystem::path(fileName);

    // Create a file
    std::ofstream file(filepath.native());
    file << "This is the main file data";
    file.close();

    // Add data to alternate stream
    std::string fullStreamPath = filepath.string() + ":" + streamName;
    std::ofstream streamFile(fullStreamPath);
    streamFile << streamContents;
    streamFile.close();
  }

  virtual void TearDown() {
    boost::filesystem::remove_all(directory);
  }
};

TEST_F(ads, test_sanity) {
  // std::string path_constraint =
  //     (directory / boost::filesystem::path("%.txt")).string();

  auto expected_path = directory.string();
  expected_path += "\\";
  expected_path += fileName;
  QueryData data =
      execute_query("select * from ads where path = \'" + expected_path + "\'");

  auto& row = data.at(0);
  ASSERT_EQ(row.at("key"), streamName);
  ASSERT_EQ(row.at("value"), streamContents);
  ASSERT_EQ(row.at("base64"), true);
  ASSERT_EQ(row.at("path"), expected_path);
  ASSERT_EQ(row.at("directory"), directory.string());

  ValidationMap row_map = {
      {"path", FileOnDisk},
      {"directory", DirectoryOnDisk},
      {"key", NormalType},
      {"value", NormalType},
      {"base64", IntType},
  };

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
