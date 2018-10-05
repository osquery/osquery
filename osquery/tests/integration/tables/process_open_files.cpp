/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for process_open_files
// Spec file: specs/posix/process_open_files.table

#include <unistd.h>

#include <boost/filesystem.hpp>

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class ProcessOpenFilesTest : public IntegrationTableTest {
 public:
  boost::filesystem::path filepath;

  virtual void SetUp() {
    auto directory =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path("test-process-open-files.%%%%-%%%%");
    ASSERT_TRUE(boost::filesystem::create_directory(directory));
    filepath = directory / boost::filesystem::path("file-table-test.txt");
    {
      auto fout = std::ofstream(filepath.native(), std::ios::out);
      fout.open(filepath.string(), std::ios::out);
      fout << "test";
    }
  }

  virtual void TearDown() {
    boost::filesystem::remove_all(filepath.parent_path());
  }
};

TEST_F(ProcessOpenFilesTest, test_sanity) {
  QueryData data = execute_query("select * from process_open_files");
  ASSERT_GT(data.size(), 0ul);
  ValidatatioMap row_map = {
      {"pid", NonNegativeInt}, {"fd", NonNegativeInt}, {"path", FileOnDisk}};
  validate_rows(data, row_map);

  std::string self_pid = std::to_string(getpid());
  bool found_self_file_open = false;
  for (const auto& row : data) {
    if (row.at("pid") == self_pid && row.at("path") == filepath.string()) {
      found_self_file_open = true;
      break;
    }
  }
  ASSERT_TRUE(found_self_file_open)
      << "process_open_files tables could not find opened file by test";
}

} // namespace osquery
