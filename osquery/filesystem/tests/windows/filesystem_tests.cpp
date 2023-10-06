/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include <gtest/gtest.h>

#include <osquery/filesystem/filesystem.h>

namespace fs = boost::filesystem;

namespace osquery {
class WindowsFilesystemTests : public testing::Test {
 protected:
  fs::path test_working_dir_;

  void SetUp() override {
    test_working_dir_ = fs::temp_directory_path() /
                        fs::unique_path("osquery.test_working_dir.%%%%.%%%%");
    fs::create_directories(test_working_dir_);
  }

  void TearDown() override {}
};

TEST_F(WindowsFilesystemTests, test_read_empty_named_pipe) {
  // This test verifies that open and read operations do not hang when using
  // non-blocking mode for pipes.
  std::wstring pipe_name = LR"(\\.\pipe\osquery_test_pipe)";
  HANDLE pipe_handle = CreateNamedPipe(pipe_name.c_str(),
                                       PIPE_ACCESS_DUPLEX,
                                       PIPE_WAIT,
                                       PIPE_UNLIMITED_INSTANCES,
                                       0,
                                       0,
                                       1000,
                                       0);
  std::string content;
  ASSERT_NE(pipe_handle, INVALID_HANDLE_VALUE) << GetLastError();
  ASSERT_FALSE(readFile(pipe_name, content));
  ASSERT_TRUE(content.empty());
  CloseHandle(pipe_handle);
}

} // namespace osquery
