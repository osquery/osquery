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

#include <fstream>
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

TEST_F(ProcessOpenFilesTest, test_path_containing_descriptor_type) {
  // Only the "socket:[", "pipe:[" and "anon_inode:" prefixes mark a
  // descriptor that is not a file; a file path containing them is a file.
  auto const marker_path =
      boost::filesystem::temp_directory_path() /
      boost::filesystem::unique_path(
          "test-socket:[1]-pipe:[2]-anon_inode:x.%%%%-%%%%.txt");
  std::ofstream marker_file(marker_path.native(), std::ios::out);
  ASSERT_TRUE(marker_file.is_open());

  auto const self_pid = std::to_string(getpid());
  auto const expected_path = boost::filesystem::canonical(marker_path).string();
  QueryData data =
      execute_query("select * from process_open_files where pid = " + self_pid);

  bool found_marker_file_open = false;
  for (const auto& row : data) {
    if (row.at("path") == expected_path) {
      found_marker_file_open = true;
      break;
    }
  }

  marker_file.close();
  boost::filesystem::remove(marker_path);

  ASSERT_TRUE(found_marker_file_open)
      << "process_open_files did not report " << expected_path;
}

} // namespace table_tests
} // namespace osquery
