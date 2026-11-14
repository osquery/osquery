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

#include <osquery/filesystem/fileops.h>
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

TEST_F(WindowsFilesystemTests, test_regular_only_opens_regular_file) {
  auto path = test_working_dir_ / "file";
  ASSERT_TRUE(writeTextFile(path, "content").ok());

  PlatformFile file(path, PF_OPEN_EXISTING | PF_READ | PF_REGULAR_ONLY);
  ASSERT_TRUE(file.isValid());

  char buffer[7];
  EXPECT_EQ(file.read(buffer, sizeof(buffer)), 7);
  EXPECT_EQ(std::string(buffer, sizeof(buffer)), "content");
}

TEST_F(WindowsFilesystemTests, test_regular_only_refuses_character_device) {
  PlatformFile file(fs::path(R"(\\.\NUL)"),
                    PF_OPEN_EXISTING | PF_READ | PF_REGULAR_ONLY);
  EXPECT_FALSE(file.isValid());
}

TEST_F(WindowsFilesystemTests, test_regular_only_refuses_raw_disk) {
  // A raw disk is of FILE_TYPE_DISK, as a file is.
  const fs::path disk(R"(\\.\PhysicalDrive0)");
  PlatformFile raw(disk, PF_OPEN_EXISTING | PF_READ);
  if (!raw.isValid()) {
    GTEST_SKIP() << "Opening a raw disk needs administrator rights";
  }
  ASSERT_EQ(::GetFileType(raw.nativeHandle()), FILE_TYPE_DISK);

  PlatformFile file(disk, PF_OPEN_EXISTING | PF_READ | PF_REGULAR_ONLY);
  EXPECT_FALSE(file.isValid());
}

} // namespace osquery
