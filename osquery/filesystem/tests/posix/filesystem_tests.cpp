/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem.hpp>

#include <gtest/gtest.h>

#include <osquery/filesystem/filesystem.h>

namespace fs = boost::filesystem;

namespace osquery {

class PosixFilesystemTests : public testing::Test {
 protected:
  fs::path test_working_dir_;

  void SetUp() override {
    test_working_dir_ = fs::temp_directory_path() /
                        fs::unique_path("osquery.test_working_dir.%%%%.%%%%");
    fs::create_directories(test_working_dir_);
  }

  void TearDown() override {
    fs::remove_all(test_working_dir_);
  }
};

TEST_F(PosixFilesystemTests, test_read_unopened_fifo) {
  // This test verifies that open and read operations do not hang when using
  // non-blocking mode for pipes.
  auto test_file = test_working_dir_ / "fifo";
  ASSERT_EQ(::mkfifo(test_file.c_str(), S_IRUSR | S_IWUSR), 0);

  std::string content;
  ASSERT_TRUE(readFile(test_file, content));
  ASSERT_TRUE(content.empty());
  ::unlink(test_file.c_str());
}
} // namespace osquery
