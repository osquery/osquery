/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for process_open_files
// Spec file: specs/posix/process_open_files.table

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/utils/info/platform_type.h>

#include <boost/filesystem.hpp>

#include <unistd.h>

namespace osquery {
namespace table_tests {

class ProcessOpenFilesTest : public testing::Test {
 public:
  boost::filesystem::path filepath;

 private:
  std::ofstream opened_file_;

  void SetUp() override {
    setUpEnvironment();
    filepath =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("test-process-open-files.%%%%-%%%%.txt");
    opened_file_.open(filepath.native(), std::ios::out);
    opened_file_ << "test";
  }

  void TearDown() override {
    opened_file_.close();
    boost::filesystem::remove(filepath);
  }
};

namespace {

bool checkProcessOpenFilePath(std::string const& value){
    // Some processes could have opened file with unlinked pathname
    if (value.find("(deleted)") != std::string::npos) {
      return true;
    }
    auto const path = boost::filesystem::path(value);
    return !path.empty() && path.is_absolute();
}

}

TEST_F(ProcessOpenFilesTest, test_sanity) {
  QueryData data = execute_query("select * from process_open_files");
  ASSERT_GT(data.size(), 0ul);
  ValidationMap row_map = {
      {"pid", NonNegativeInt},
      {"fd", NonNegativeInt},
      {"path", checkProcessOpenFilePath},
  };
  validate_rows(data, row_map);

  std::string self_pid = std::to_string(getpid());
  auto const test_filepath = boost::filesystem::canonical(filepath).string();
  bool found_self_file_open = false;
  for (const auto& row : data) {
    if (row.at("pid") == self_pid && row.at("path") == test_filepath) {
      found_self_file_open = true;
      break;
    }
  }
  ASSERT_TRUE(found_self_file_open)
      << "process_open_files tables could not find opened file by test";
}

} // namespace table_tests
} // namespace osquery
